//! Format registry: maps identifiers to backends, runs probes, resolves conversions.

use crate::capability::{CapabilitySet, ConversionEdge, FormatDescriptor, Support};
use crate::error::{Error, ErrorCode, Result};
use crate::format::{FormatId, NestedProbe, ProbeEvidence, ProbeLimits, ProbeResult};
use crate::model::NodeKind;
use crate::plan::PlannedOperation;
use crate::reader::{Backend, ConvertRequest, OpenContext, PackageReader};
use crate::source::{DataSource, SharedSource};

/// A set of registered backends.
#[derive(Default)]
pub struct Registry {
    backends: Vec<Box<dyn Backend>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn register(&mut self, b: Box<dyn Backend>) -> &mut Self {
        self.backends.push(b);
        self
    }
    pub fn with(mut self, b: impl Backend + 'static) -> Self {
        self.backends.push(Box::new(b));
        self
    }
    pub fn backends(&self) -> impl Iterator<Item = &dyn Backend> {
        self.backends.iter().map(|b| b.as_ref())
    }

    /// All formats from compiled backends.
    pub fn supported_formats(&self) -> Vec<FormatDescriptor> {
        let mut v: Vec<_> = self.backends.iter().flat_map(|b| b.formats()).collect();
        v.sort_by_key(|d| d.id);
        v
    }

    pub fn descriptor(&self, id: FormatId) -> Option<FormatDescriptor> {
        self.backends.iter().flat_map(|b| b.formats()).find(|d| d.id == id)
    }

    pub fn find_format(&self, id: &str) -> Option<FormatId> {
        self.supported_formats().into_iter().map(|d| d.id).find(|f| f.as_str() == id)
    }

    fn backend_for(&self, id: FormatId) -> Result<&dyn Backend> {
        self.backends
            .iter()
            .find(|b| b.formats().iter().any(|d| d.id == id))
            .map(|b| b.as_ref())
            .ok_or_else(|| Error::new(ErrorCode::UnknownFormat, format!("no compiled backend handles {id}")))
    }

    /// All declared conversion edges.
    pub fn conversions(&self) -> Vec<ConversionEdge> {
        self.backends.iter().flat_map(|b| b.conversions()).collect()
    }

    pub fn find_conversion(&self, from: FormatId, to: FormatId) -> Option<ConversionEdge> {
        self.conversions().into_iter().find(|e| e.from == from && e.to == to)
    }

    /// Probe a source against every backend.
    pub fn probe(&self, source: &dyn DataSource, limits: &ProbeLimits) -> Result<ProbeResult> {
        let size = source.len()?;
        let mut candidates: Vec<ProbeEvidence> = Vec::new();
        let mut warnings = Vec::new();
        for b in &self.backends {
            match b.probe(source, limits) {
                Ok(mut ev) => candidates.append(&mut ev),
                Err(e) if e.code() == ErrorCode::Io => return Err(e),
                Err(e) => warnings.push(format!("{} probe error: {}", b.name(), e)),
            }
        }
        candidates.sort_by(|a, b| b.confidence.cmp(&a.confidence).then(b.specificity.cmp(&a.specificity)));
        // Drop candidates refined by a stronger, more specific candidate.
        let refined: Vec<FormatId> = candidates.iter().flat_map(|c| c.refines.iter().copied().filter(move |r| *r != c.format)).collect();
        let (primary, refined_out): (Vec<_>, Vec<_>) = candidates.into_iter().partition(|c| !refined.contains(&c.format));
        let mut ambiguity = Vec::new();
        let format = match primary.as_slice() {
            [] => None,
            [one] => Some(one.format),
            [a, b, ..] => {
                if a.confidence == b.confidence && a.specificity == b.specificity {
                    let tied: Vec<_> = primary
                        .iter()
                        .filter(|c| c.confidence == a.confidence && c.specificity == a.specificity)
                        .map(|c| c.format.to_string())
                        .collect();
                    ambiguity.push(format!("equally strong matches: {}", tied.join(", ")));
                    None
                } else {
                    Some(a.format)
                }
            }
        };
        let mut all = primary;
        all.extend(refined_out);
        Ok(ProbeResult { size, format, candidates: all, ambiguity, warnings, children: Vec::new() })
    }

    /// Probe and recursively detect child formats up to `limits.max_depth`.
    pub fn probe_nested(&self, source: SharedSource, limits: &ProbeLimits, ctx: &OpenContext) -> Result<ProbeResult> {
        let mut r = self.probe(source.as_ref(), limits)?;
        if let Some(f) = r.format {
            if limits.max_depth > 0 {
                r.children = self.children(f, source, limits, ctx, limits.max_depth)?;
            }
        }
        Ok(r)
    }

    fn children(
        &self,
        format: FormatId,
        source: SharedSource,
        limits: &ProbeLimits,
        ctx: &OpenContext,
        depth: u32,
    ) -> Result<Vec<NestedProbe>> {
        let mut out = Vec::new();
        if depth == 0 {
            return Ok(out);
        }
        let reader = match self.open_as(format, source, ctx) {
            Ok(r) => r,
            Err(_) => return Ok(out),
        };
        let mut examined = 0usize;
        for node in reader.entries()? {
            let node = match node {
                Ok(n) => n,
                Err(_) => break,
            };
            if matches!(node.kind, NodeKind::Directory | NodeKind::Partition) || !node.readable || node.length < 16 {
                continue;
            }
            examined += 1;
            if examined > limits.max_children {
                break;
            }
            let child = match reader.open_entry(node.id) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let pr = match self.probe(child.as_ref(), limits) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if let Some(cf) = pr.format {
                let conf = pr.best().map(|b| b.confidence).unwrap_or(crate::format::Confidence::Low);
                let grand = self.children(cf, child, limits, ctx, depth - 1).unwrap_or_default();
                out.push(NestedProbe { path: node.path.clone(), format: cf, confidence: conf, children: grand });
            }
        }
        Ok(out)
    }

    /// Open with an explicit format.
    pub fn open_as(&self, format: FormatId, source: SharedSource, ctx: &OpenContext) -> Result<Box<dyn PackageReader>> {
        self.backend_for(format)?.open(format, source, ctx).map_err(|e| e.with_format(format))
    }

    /// Probe and open the best match. Ambiguity and unknown formats are errors.
    pub fn open(&self, source: SharedSource, ctx: &OpenContext) -> Result<Box<dyn PackageReader>> {
        let pr = self.probe(source.as_ref(), &ProbeLimits::default())?;
        match pr.format {
            Some(f) => self.open_as(f, source, ctx),
            None if !pr.ambiguity.is_empty() => Err(Error::new(ErrorCode::AmbiguousFormat, pr.ambiguity.join("; "))
                .with_suggestion("specify the format explicitly with --as <format-id>")),
            None => Err(Error::new(ErrorCode::UnknownFormat, "no compiled backend recognised this file")
                .with_suggestion("run `romux formats` to see compiled formats")),
        }
    }

    /// Capability set of a concrete source.
    pub fn capabilities(&self, source: SharedSource, ctx: &OpenContext) -> Result<CapabilitySet> {
        self.open(source, ctx)?.capabilities()
    }

    /// Plan a conversion along a declared edge.
    pub fn plan_convert(&self, req: ConvertRequest) -> Result<Box<dyn PlannedOperation>> {
        let edge = self.find_conversion(req.from, req.to).ok_or_else(|| {
            Error::new(ErrorCode::InvalidOutputFormat, format!("no declared conversion from {} to {}", req.from, req.to))
                .with_suggestion("run `romux formats --conversions` to list valid edges")
        })?;
        if edge.support == Support::Unsupported {
            return Err(Error::unsupported(format!("conversion {} -> {}: {}", edge.from, edge.to, edge.note)));
        }
        // Dispatch to the backend that declares the edge (it may differ from the backend
        // owning the source format, e.g. ISO9660 -> CSO is declared by the PSP backend).
        let owner = self
            .backends
            .iter()
            .find(|b| b.conversions().iter().any(|e| e.from == req.from && e.to == req.to))
            .map(|b| b.as_ref())
            .ok_or_else(|| Error::internal("declared edge has no owning backend"))?;
        owner.plan_convert(req)
    }
}

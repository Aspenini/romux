//! Typed, machine-readable errors shared by every Romux crate.

use serde::Serialize;
use std::fmt;

/// Stable machine-readable error codes. New codes may be added (non-exhaustive).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Io,
    UnknownFormat,
    AmbiguousFormat,
    MalformedHeader,
    BoundsViolation,
    IntegrityMismatch,
    UnsupportedFeature,
    NeedsKeyMaterial,
    IncompatibleTitles,
    IncompatibleVersions,
    InvalidOutputFormat,
    InsufficientSpace,
    Cancelled,
    UnsafePath,
    ConflictingOutput,
    CodecFailure,
    SignatureUnavailable,
    InternalInvariant,
    InvalidArgument,
    LimitExceeded,
    VerificationFailed,
}

/// Documented process exit codes used by the CLI.
pub mod exit {
    pub const SUCCESS: i32 = 0;
    pub const GENERAL: i32 = 1;
    pub const INVALID_ARGUMENT: i32 = 2;
    pub const UNSUPPORTED: i32 = 3;
    pub const PROTECTED_CONTENT: i32 = 4;
    pub const CORRUPT_INPUT: i32 = 5;
    pub const IO: i32 = 6;
    pub const CANCELLED: i32 = 7;
    pub const VERIFICATION_FAILED: i32 = 8;
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Io => "io",
            ErrorCode::UnknownFormat => "unknown_format",
            ErrorCode::AmbiguousFormat => "ambiguous_format",
            ErrorCode::MalformedHeader => "malformed_header",
            ErrorCode::BoundsViolation => "bounds_violation",
            ErrorCode::IntegrityMismatch => "integrity_mismatch",
            ErrorCode::UnsupportedFeature => "unsupported_feature",
            ErrorCode::NeedsKeyMaterial => "needs_key_material",
            ErrorCode::IncompatibleTitles => "incompatible_titles",
            ErrorCode::IncompatibleVersions => "incompatible_versions",
            ErrorCode::InvalidOutputFormat => "invalid_output_format",
            ErrorCode::InsufficientSpace => "insufficient_space",
            ErrorCode::Cancelled => "cancelled",
            ErrorCode::UnsafePath => "unsafe_path",
            ErrorCode::ConflictingOutput => "conflicting_output",
            ErrorCode::CodecFailure => "codec_failure",
            ErrorCode::SignatureUnavailable => "signature_unavailable",
            ErrorCode::InternalInvariant => "internal_invariant",
            ErrorCode::InvalidArgument => "invalid_argument",
            ErrorCode::LimitExceeded => "limit_exceeded",
            ErrorCode::VerificationFailed => "verification_failed",
        }
    }

    /// Process exit code associated with this error class.
    pub fn exit_code(self) -> i32 {
        use ErrorCode::*;
        match self {
            InvalidArgument | IncompatibleTitles | IncompatibleVersions | InvalidOutputFormat | ConflictingOutput => exit::INVALID_ARGUMENT,
            UnknownFormat | AmbiguousFormat | UnsupportedFeature => exit::UNSUPPORTED,
            NeedsKeyMaterial | SignatureUnavailable => exit::PROTECTED_CONTENT,
            MalformedHeader | BoundsViolation | IntegrityMismatch | CodecFailure | UnsafePath | LimitExceeded => exit::CORRUPT_INPUT,
            Io | InsufficientSpace => exit::IO,
            Cancelled => exit::CANCELLED,
            VerificationFailed => exit::VERIFICATION_FAILED,
            InternalInvariant => exit::GENERAL,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where an error happened.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ErrorContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_id: Option<String>,
}

/// The Romux error type (boxed so `Result<T>` stays pointer-sized on the error path).
pub struct Error(Box<ErrorInner>);

#[doc(hidden)]
pub struct ErrorInner {
    code: ErrorCode,
    message: String,
    context: ErrorContext,
    suggestion: Option<String>,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Error(Box::new(ErrorInner { code, message: message.into(), context: ErrorContext::default(), suggestion: None, source: None }))
    }
    pub fn code(&self) -> ErrorCode {
        self.code
    }
    pub fn message(&self) -> &str {
        &self.message
    }
    pub fn context(&self) -> &ErrorContext {
        &self.context
    }
    pub fn suggestion(&self) -> Option<&str> {
        self.suggestion.as_deref()
    }

    pub fn with_operation(mut self, op: impl Into<String>) -> Self {
        if self.context.operation.is_none() {
            self.context.operation = Some(op.into());
        }
        self
    }
    pub fn with_format(mut self, format: impl fmt::Display) -> Self {
        if self.context.format.is_none() {
            self.context.format = Some(format.to_string());
        }
        self
    }
    pub fn with_file(mut self, file: impl Into<String>) -> Self {
        if self.context.file.is_none() {
            self.context.file = Some(file.into());
        }
        self
    }
    pub fn with_offset(mut self, offset: u64) -> Self {
        if self.context.offset.is_none() {
            self.context.offset = Some(offset);
        }
        self
    }
    pub fn with_content_id(mut self, id: impl Into<String>) -> Self {
        self.context.content_id = Some(id.into());
        self
    }
    pub fn with_suggestion(mut self, s: impl Into<String>) -> Self {
        self.suggestion = Some(s.into());
        self
    }
    pub fn with_source(mut self, e: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(e));
        self
    }

    // Convenience constructors -------------------------------------------------
    pub fn malformed(msg: impl Into<String>) -> Self {
        Error::new(ErrorCode::MalformedHeader, msg)
    }
    pub fn bounds(msg: impl Into<String>) -> Self {
        Error::new(ErrorCode::BoundsViolation, msg)
    }
    pub fn unsupported(msg: impl Into<String>) -> Self {
        Error::new(ErrorCode::UnsupportedFeature, msg)
    }
    pub fn needs_keys(msg: impl Into<String>) -> Self {
        Error::new(ErrorCode::NeedsKeyMaterial, msg).with_suggestion("supply legitimately obtained key material with --key-file")
    }
    pub fn invalid_arg(msg: impl Into<String>) -> Self {
        Error::new(ErrorCode::InvalidArgument, msg)
    }
    pub fn integrity(msg: impl Into<String>) -> Self {
        Error::new(ErrorCode::IntegrityMismatch, msg)
    }
    pub fn limit(msg: impl Into<String>) -> Self {
        Error::new(ErrorCode::LimitExceeded, msg)
    }
    pub fn codec(msg: impl Into<String>) -> Self {
        Error::new(ErrorCode::CodecFailure, msg)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Error::new(ErrorCode::InternalInvariant, msg)
    }
    pub fn unsafe_path(msg: impl Into<String>) -> Self {
        Error::new(ErrorCode::UnsafePath, msg)
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        Error::new(ErrorCode::ConflictingOutput, msg)
    }
    pub fn cancelled() -> Self {
        Error::new(ErrorCode::Cancelled, "operation cancelled")
    }

    /// Structured diagnostic suitable for JSON output.
    pub fn to_diagnostic(&self) -> Diagnostic {
        let mut causes = Vec::new();
        let mut src: Option<&(dyn std::error::Error + 'static)> = self.source.as_deref().map(|e| e as _);
        while let Some(e) = src {
            causes.push(e.to_string());
            src = e.source();
        }
        Diagnostic {
            severity: Severity::Error,
            code: self.code.as_str().to_string(),
            message: self.message.clone(),
            context: self.context.clone(),
            suggestion: self.suggestion.clone(),
            causes,
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Error")
            .field("code", &self.code)
            .field("message", &self.message)
            .field("context", &self.context)
            .field("suggestion", &self.suggestion)
            .field("source", &self.source.as_ref().map(|s| s.to_string()))
            .finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)?;
        let c = &self.context;
        let mut parts = Vec::new();
        if let Some(op) = &c.operation {
            parts.push(format!("operation={op}"));
        }
        if let Some(fm) = &c.format {
            parts.push(format!("format={fm}"));
        }
        if let Some(file) = &c.file {
            parts.push(format!("file={file}"));
        }
        if let Some(o) = c.offset {
            parts.push(format!("offset=0x{o:x}"));
        }
        if let Some(id) = &c.content_id {
            parts.push(format!("content={id}"));
        }
        if !parts.is_empty() {
            write!(f, " ({})", parts.join(", "))?;
        }
        if let Some(s) = &self.source {
            write!(f, ": {s}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|e| e as _)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        let code = match e.kind() {
            std::io::ErrorKind::UnexpectedEof => ErrorCode::BoundsViolation,
            std::io::ErrorKind::Interrupted => ErrorCode::Cancelled,
            _ if is_out_of_space(&e) => ErrorCode::InsufficientSpace,
            _ => ErrorCode::Io,
        };
        let msg = e.to_string();
        Error::new(code, msg).with_source(e)
    }
}

fn is_out_of_space(e: &std::io::Error) -> bool {
    // ENOSPC (28) on unix, ERROR_DISK_FULL (112) / ERROR_HANDLE_DISK_FULL (39) on Windows.
    matches!(e.raw_os_error(), Some(28) | Some(112) | Some(39))
}

/// Severity level of a diagnostic.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

/// Machine-readable diagnostic (errors and warnings).
#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: String,
    pub message: String,
    pub context: ErrorContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub causes: Vec<String>,
}

impl Diagnostic {
    pub fn warning(code: &str, message: impl Into<String>) -> Self {
        Diagnostic {
            severity: Severity::Warning,
            code: code.to_string(),
            message: message.into(),
            context: ErrorContext::default(),
            suggestion: None,
            causes: Vec::new(),
        }
    }
}

/// Extension trait to attach context to results.
pub trait ResultExt<T> {
    fn op(self, op: &str) -> Result<T>;
    fn fmt_ctx(self, fmt: impl fmt::Display) -> Result<T>;
    fn file_ctx(self, file: impl Into<String>) -> Result<T>;
}

impl<T, E: Into<Error>> ResultExt<T> for std::result::Result<T, E> {
    fn op(self, op: &str) -> Result<T> {
        self.map_err(|e| e.into().with_operation(op))
    }
    fn fmt_ctx(self, fmt: impl fmt::Display) -> Result<T> {
        self.map_err(|e| e.into().with_format(fmt))
    }
    fn file_ctx(self, file: impl Into<String>) -> Result<T> {
        self.map_err(|e| e.into().with_file(file))
    }
}

/// Return early with an error built from a code and format string.
#[macro_export]
macro_rules! bail {
    ($code:ident, $($arg:tt)*) => {
        return Err($crate::Error::new($crate::ErrorCode::$code, format!($($arg)*)))
    };
}

/// Ensure a condition holds, otherwise return the given error code.
#[macro_export]
macro_rules! ensure {
    ($cond:expr_2021, $code:ident, $($arg:tt)*) => {
        if !($cond) {
            return Err($crate::Error::new($crate::ErrorCode::$code, format!($($arg)*)));
        }
    };
}

impl std::ops::Deref for Error {
    type Target = ErrorInner;
    fn deref(&self) -> &ErrorInner {
        &self.0
    }
}

impl std::ops::DerefMut for Error {
    fn deref_mut(&mut self) -> &mut ErrorInner {
        &mut self.0
    }
}

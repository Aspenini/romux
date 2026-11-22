//! Logical-path sanitisation for extraction targets.

use crate::error::{Error, Result};

const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4",
    "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Split an archive-internal path into safe components.
///
/// Rejects absolute paths, drive prefixes, `..`, NUL and control characters, reserved
/// Windows device names, and over-long components. Both `/` and `\` separate components.
/// Empty and `.` components are dropped.
pub fn sanitize_components(logical: &str, max_component_len: usize) -> Result<Vec<String>> {
    if logical.starts_with('/') || logical.starts_with('\\') {
        return Err(Error::unsafe_path(format!("absolute path rejected: {logical:?}")));
    }
    let bytes = logical.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        return Err(Error::unsafe_path(format!("drive-prefixed path rejected: {logical:?}")));
    }
    let mut out = Vec::new();
    for comp in logical.split(['/', '\\']) {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp == ".." {
            return Err(Error::unsafe_path(format!("path traversal rejected: {logical:?}")));
        }
        if comp.len() > max_component_len {
            return Err(Error::unsafe_path(format!("path component longer than {max_component_len} bytes")));
        }
        if comp.chars().any(|c| c.is_control() || matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|')) {
            return Err(Error::unsafe_path(format!("path component contains forbidden characters: {comp:?}")));
        }
        let stem = comp.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase();
        if WINDOWS_RESERVED.contains(&stem.as_str()) {
            return Err(Error::unsafe_path(format!("reserved device name rejected: {comp:?}")));
        }
        if comp.ends_with(' ') || comp.ends_with('.') {
            return Err(Error::unsafe_path(format!("trailing dot/space rejected: {comp:?}")));
        }
        out.push(comp.to_string());
    }
    if out.is_empty() {
        return Err(Error::unsafe_path(format!("empty path: {logical:?}")));
    }
    Ok(out)
}

/// Case-folded key used to detect collisions on case-insensitive filesystems.
pub fn collision_key(components: &[String]) -> String {
    components.iter().map(|c| c.to_lowercase()).collect::<Vec<_>>().join("/")
}

/// Normalise a logical path to `/` separators without leading slash (no safety checks).
pub fn normalize_logical(p: &str) -> String {
    p.split(['/', '\\']).filter(|c| !c.is_empty() && *c != ".").collect::<Vec<_>>().join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_paths() {
        for bad in ["../x", "a/../../b", "/etc/passwd", "C:\\win", "a\\..\\b", "CON", "x/aux.txt", "a\0b", "x. "] {
            assert!(sanitize_components(bad, 255).is_err(), "{bad}");
        }
        assert_eq!(sanitize_components("a/./b\\c", 255).unwrap(), vec!["a", "b", "c"]);
    }
}

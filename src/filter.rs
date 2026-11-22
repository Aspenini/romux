//! Minimal glob matching for entry filters (`*`, `?`, `**`).

/// Match `path` against a glob. Patterns without `/` match either the whole path or its basename.
/// `*` and `?` never cross `/`; `**` does, and `**/` also matches zero directories.
pub fn glob_match(pattern: &str, path: &str) -> bool {
    if pattern.len() > 512 {
        return false;
    }
    if !pattern.contains('/') {
        let base = path.rsplit('/').next().unwrap_or(path);
        if m(pattern.as_bytes(), base.as_bytes()) {
            return true;
        }
    }
    m(pattern.as_bytes(), path.as_bytes())
}

fn m(p: &[u8], s: &[u8]) -> bool {
    match p.first() {
        None => s.is_empty(),
        Some(b'*') if p.get(1) == Some(&b'*') => {
            let rest = &p[2..];
            if rest.first() == Some(&b'/') && m(&rest[1..], s) {
                return true;
            }
            (0..=s.len()).any(|i| m(rest, &s[i..]))
        }
        Some(b'*') => {
            let rest = &p[1..];
            for i in 0..=s.len() {
                if m(rest, &s[i..]) {
                    return true;
                }
                if i < s.len() && s[i] == b'/' {
                    break;
                }
            }
            false
        }
        Some(b'?') => !s.is_empty() && s[0] != b'/' && m(&p[1..], &s[1..]),
        Some(&c) => !s.is_empty() && s[0] == c && m(&p[1..], &s[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::glob_match;
    #[test]
    fn globs() {
        assert!(glob_match("*.nca", "secure/abc.nca"));
        assert!(glob_match("secure/*.nca", "secure/abc.nca"));
        assert!(!glob_match("secure/*.nca", "secure/x/abc.nca"));
        assert!(glob_match("**/*.bin", "a/b/c.bin"));
        assert!(glob_match("**/c.bin", "c.bin"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("*.nca", "abc.ncz"));
    }
}

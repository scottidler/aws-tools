//! utils.rs
//! ---------------------------------------------------------------------------
//! Helper utilities that don’t fit anywhere else.

use std::{env, fs, path::PathBuf};
use terminal_size::{terminal_size, Width};

/// Return (and create if needed) a platform-appropriate directory for log files.
pub fn get_or_create_log_dir() -> PathBuf {
    let dir = if cfg!(target_os = "macos") {
        env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("Library")
            .join("Logs")
            .join("slam")
    } else if let Ok(x) = env::var("XDG_STATE_HOME") {
        PathBuf::from(x).join("slam")
    } else if let Ok(h) = env::var("HOME") {
        PathBuf::from(h).join(".local").join("state").join("slam")
    } else {
        PathBuf::from("slam_logs")
    };
    fs::create_dir_all(&dir).ok();
    dir
}

/// Best-effort detection of the current terminal width (columns).
pub fn terminal_width() -> usize {
    terminal_size()
        .map(|(Width(w), _)| w as usize)
        .unwrap_or(80)
}

/// Wrap a long AWS identifier (ARN, ENI-id …) so that every rendered line
/// (after the two-space indent on continuations) is **≤ `max_width`**.
///
/// * Prefer `'/'` as the break delimiter; fall back to `':'`.
/// * We break only **between segments**, never in the middle of one.
/// * The delimiter itself is always the last character on the line we break on.
/// * Each continuation line starts with two spaces.
///
/// Example (`max_width = 55`)
///
/// ```text
/// arn:aws:elasticloadbalancing:us-west-2:878256633362:loadbalancer/net/
///   a3dc296703c0844b38a4ed71522e6826/20515466b45776d4
/// ```
pub fn wrap_identifier(ident: &str, max_width: usize) -> String {
    if max_width < 10 || ident.len() <= max_width {
        return ident.to_owned();
    }

    let delim = if ident.contains('/') { '/' } else { ':' };
    let segments: Vec<&str> = ident.split(delim).collect();

    let mut lines:   Vec<String> = Vec::new();
    let mut current: String      = String::new();

    for seg in segments.iter() {
        // Length we’d add if we append this segment (+1 for delim when needed).
        let extra = if current.is_empty() { seg.len() } else { 1 + seg.len() };

        if !current.is_empty() && current.len() + extra > max_width {
            // Finish the current line with the delimiter and push it.
            current.push(delim);
            lines.push(current.clone());

            // Start a new indented line for the segment we couldn’t fit.
            current.clear();
            current.push_str("  ");         // two-space indent
            current.push_str(seg);
        } else {
            if !current.is_empty() {
                current.push(delim);
            }
            current.push_str(seg);
        }
    }

    // Push whatever is left in `current`.
    if !current.is_empty() {
        lines.push(current);
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_identifier_short_string_unchanged() {
        let ident = "vpc-12345678";
        assert_eq!(wrap_identifier(ident, 50), ident);
    }

    #[test]
    fn wrap_identifier_exact_length_unchanged() {
        let ident = "arn:aws:ec2:us-west-2:123456789012:vpc/vpc-12345";
        assert_eq!(wrap_identifier(ident, ident.len()), ident);
    }

    #[test]
    fn wrap_identifier_small_max_width_returns_unchanged() {
        let ident = "arn:aws:ec2:us-west-2:123456789012:vpc/vpc-12345";
        // max_width < 10 returns unchanged
        assert_eq!(wrap_identifier(ident, 5), ident);
    }

    #[test]
    fn wrap_identifier_breaks_on_slash() {
        let ident = "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/net/my-lb/abc123";
        let result = wrap_identifier(ident, 55);
        // Should contain continuation with two-space indent
        assert!(result.contains("\n  "));
        // Should break on slash
        assert!(result.contains("/\n"));
    }

    #[test]
    fn wrap_identifier_breaks_on_colon_when_no_slash() {
        let ident = "arn:aws:ec2:us-west-2:123456789012:vpc:vpc-12345678901234567";
        let result = wrap_identifier(ident, 30);
        // Should contain continuation
        assert!(result.contains("\n  "));
    }

    #[test]
    fn wrap_identifier_preserves_all_content() {
        let ident = "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/net/my-lb/abc123";
        let result = wrap_identifier(ident, 40);
        // Remove newlines and indentation to verify all content is preserved
        let cleaned: String = result.lines().map(|l| l.trim()).collect();
        let original_cleaned: String = ident.chars().collect();
        assert_eq!(cleaned, original_cleaned);
    }

    #[test]
    fn wrap_identifier_continuation_lines_indented() {
        let ident = "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/net/my-lb/abc123";
        let result = wrap_identifier(ident, 40);
        let lines: Vec<&str> = result.lines().collect();
        // All continuation lines should start with two spaces
        for line in lines.iter().skip(1) {
            assert!(line.starts_with("  "), "Continuation line should start with two spaces: {}", line);
        }
    }

    #[test]
    fn terminal_width_returns_positive() {
        let width = terminal_width();
        assert!(width > 0);
    }

    #[test]
    fn get_or_create_log_dir_returns_valid_path() {
        let dir = get_or_create_log_dir();
        // Should end with "slam"
        assert!(dir.ends_with("slam"));
    }
}

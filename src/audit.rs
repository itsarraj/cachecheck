//! Pure header-auditing logic: given the response headers a real HTTP
//! request returned, find real caching misconfigurations. No network
//! access here — `main.rs` is the only part that makes a real request.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule: &'static str,
    pub message: String,
}

/// Case-insensitive header lookup, matching real HTTP semantics (header
/// names are never case-sensitive).
fn get<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

pub fn audit_headers(headers: &[(String, String)], now_unix: i64) -> Vec<Finding> {
    let mut findings = Vec::new();
    let cache_control = get(headers, "cache-control");
    let expires = get(headers, "expires");
    let etag = get(headers, "etag");
    let last_modified = get(headers, "last-modified");

    if cache_control.is_none() && expires.is_none() {
        findings.push(Finding {
            rule: "no_cache_headers",
            message: "no Cache-Control or Expires header at all — caching behavior is left entirely to the client's own defaults".to_string(),
        });
    }

    if let Some(cc) = cache_control {
        let no_store = cc
            .split(',')
            .any(|d| d.trim().eq_ignore_ascii_case("no-store"));
        if no_store && (etag.is_some() || last_modified.is_some()) {
            findings.push(Finding {
                rule: "no_store_with_validators",
                message: "Cache-Control: no-store is set, but ETag/Last-Modified validators are also present — they can never be used".to_string(),
            });
        }
    }

    if etag.is_some() && cache_control.is_none() {
        findings.push(Finding {
            rule: "etag_without_cache_control",
            message: "ETag is present but Cache-Control is missing — a validator with no caching policy attached".to_string(),
        });
    }

    if let Some(expires_val) = expires {
        let is_intentionally_uncached = cache_control
            .map(|cc| {
                cc.split(',').any(|d| {
                    let d = d.trim();
                    d.eq_ignore_ascii_case("no-cache") || d.eq_ignore_ascii_case("no-store")
                })
            })
            .unwrap_or(false);
        if !is_intentionally_uncached {
            if let Ok(expires_time) = httpdate::parse_http_date(expires_val) {
                let expires_unix = expires_time
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                if expires_unix < now_unix {
                    findings.push(Finding {
                        rule: "expires_in_the_past",
                        message: format!("Expires ({expires_val}) is already in the past, and Cache-Control doesn't mark this as intentionally uncacheable"),
                    });
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    const NOW: i64 = 1_700_000_000;

    #[test]
    fn flags_completely_missing_cache_headers() {
        let findings = audit_headers(&h(&[("content-type", "text/html")]), NOW);
        assert!(findings.iter().any(|f| f.rule == "no_cache_headers"));
    }

    #[test]
    fn clean_response_with_max_age_has_no_findings() {
        let findings = audit_headers(&h(&[("cache-control", "public, max-age=3600")]), NOW);
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_no_store_combined_with_etag() {
        let findings = audit_headers(
            &h(&[("cache-control", "no-store"), ("etag", "\"abc\"")]),
            NOW,
        );
        assert!(findings
            .iter()
            .any(|f| f.rule == "no_store_with_validators"));
    }

    #[test]
    fn no_store_alone_with_no_validators_is_clean() {
        let findings = audit_headers(&h(&[("cache-control", "no-store")]), NOW);
        assert!(findings
            .iter()
            .all(|f| f.rule != "no_store_with_validators"));
    }

    #[test]
    fn flags_etag_with_no_cache_control() {
        let findings = audit_headers(&h(&[("etag", "\"abc\"")]), NOW);
        assert!(findings
            .iter()
            .any(|f| f.rule == "etag_without_cache_control"));
    }

    #[test]
    fn etag_with_cache_control_present_is_not_flagged_for_that_rule() {
        let findings = audit_headers(
            &h(&[("etag", "\"abc\""), ("cache-control", "max-age=60")]),
            NOW,
        );
        assert!(findings
            .iter()
            .all(|f| f.rule != "etag_without_cache_control"));
    }

    #[test]
    fn flags_a_stale_hardcoded_past_expires_header() {
        // Thu, 01 Jan 1970 00:00:00 GMT — a real HTTP-date, genuinely in the past.
        let findings = audit_headers(&h(&[("expires", "Thu, 01 Jan 1970 00:00:00 GMT")]), NOW);
        assert!(findings.iter().any(|f| f.rule == "expires_in_the_past"));
    }

    #[test]
    fn past_expires_is_not_flagged_when_no_cache_makes_it_intentional() {
        let findings = audit_headers(
            &h(&[
                ("expires", "Thu, 01 Jan 1970 00:00:00 GMT"),
                ("cache-control", "no-cache"),
            ]),
            NOW,
        );
        assert!(findings.iter().all(|f| f.rule != "expires_in_the_past"));
    }

    #[test]
    fn future_expires_is_not_flagged() {
        // Fri, 01 Jan 2038 00:00:00 GMT — safely in the future relative to NOW.
        let findings = audit_headers(&h(&[("expires", "Fri, 01 Jan 2038 00:00:00 GMT")]), NOW);
        assert!(findings.iter().all(|f| f.rule != "expires_in_the_past"));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let findings = audit_headers(&h(&[("Cache-Control", "max-age=60")]), NOW);
        assert!(findings.is_empty());
    }

    #[test]
    fn malformed_expires_value_is_ignored_rather_than_erroring() {
        let findings = audit_headers(
            &h(&[("expires", "not a date"), ("cache-control", "max-age=1")]),
            NOW,
        );
        assert!(findings.iter().all(|f| f.rule != "expires_in_the_past"));
    }
}

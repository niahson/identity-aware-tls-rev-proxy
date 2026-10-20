use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
    str::FromStr,
};

use anyhow::{Context, Result, bail};
use http::Method;
use serde::Deserialize;
use thiserror::Error;

const MAX_PATH_BYTES: usize = 4_096;

#[derive(Clone, Debug)]
pub struct PolicyEngine {
    rules: HashMap<String, Vec<Rule>>,
}

#[derive(Clone, Debug)]
struct Rule {
    method: Method,
    path: PathMatcher,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
enum PathMatcher {
    Exact(String),
    Prefix(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    policies: Vec<IdentityPolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityPolicy {
    identity: String,
    allow: Vec<AllowRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowRule {
    method: String,
    path: String,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PathError {
    #[error("path is too long")]
    TooLong,
    #[error("path must start with a slash")]
    MissingLeadingSlash,
    #[error("path contains malformed percent encoding")]
    BadEncoding,
    #[error("path contains a forbidden percent-encoded byte or control byte")]
    ForbiddenEncoding,
    #[error("path is not valid UTF-8")]
    InvalidUtf8,
    #[error("path contains an ambiguous segment")]
    AmbiguousSegment,
}

impl PolicyEngine {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read policy file {}", path.display()))?;
        Self::from_json(&bytes)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let source: PolicyFile =
            serde_json::from_slice(bytes).context("policy must be valid JSON")?;
        if source.policies.is_empty() {
            bail!("policy must contain at least one identity");
        }

        let mut rules: HashMap<String, Vec<Rule>> = HashMap::new();
        let mut seen = HashSet::new();
        for identity_policy in source.policies {
            let identity = canonical_spiffe_id(&identity_policy.identity)
                .with_context(|| format!("invalid policy identity {}", identity_policy.identity))?;
            if identity_policy.allow.is_empty() {
                bail!("identity {identity} has no allow rules");
            }
            for allow in identity_policy.allow {
                let method = Method::from_str(&allow.method)
                    .with_context(|| format!("invalid HTTP method {}", allow.method))?;
                if allow.method != method.as_str() {
                    bail!("policy methods must use their canonical uppercase spelling");
                }
                let path = PathMatcher::parse(&allow.path)?;
                let key = (identity.clone(), method.clone(), path.clone());
                if !seen.insert(key) {
                    bail!("duplicate authorization rule for {identity}");
                }
                rules
                    .entry(identity.clone())
                    .or_default()
                    .push(Rule { method, path });
            }
        }
        Ok(Self { rules })
    }

    pub fn is_allowed(&self, identity: &str, method: &Method, canonical_path: &str) -> bool {
        self.rules.get(identity).is_some_and(|rules| {
            rules.iter().any(|rule| {
                rule.method == *method
                    && match &rule.path {
                        PathMatcher::Exact(path) => canonical_path == path,
                        PathMatcher::Prefix(prefix) => canonical_path.starts_with(prefix),
                    }
            })
        })
    }
}

impl PathMatcher {
    fn parse(raw: &str) -> Result<Self> {
        if let Some(prefix) = raw.strip_suffix('*') {
            if !prefix.ends_with('/') || prefix[..prefix.len() - 1].contains('*') {
                bail!("wildcards are allowed only as a terminal /* segment");
            }
            let canonical = canonicalize_path(prefix)?;
            return Ok(Self::Prefix(canonical));
        }
        if raw.contains('*') {
            bail!("wildcards are allowed only as a terminal /* segment");
        }
        Ok(Self::Exact(canonicalize_path(raw)?))
    }
}

pub fn canonicalize_path(raw: &str) -> Result<String, PathError> {
    if raw.len() > MAX_PATH_BYTES {
        return Err(PathError::TooLong);
    }
    if !raw.starts_with('/') {
        return Err(PathError::MissingLeadingSlash);
    }

    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err(PathError::BadEncoding);
                }
                let high = hex(bytes[index + 1]).ok_or(PathError::BadEncoding)?;
                let low = hex(bytes[index + 2]).ok_or(PathError::BadEncoding)?;
                let value = high * 16 + low;
                // Only unreserved RFC 3986 characters may be percent encoded.
                // In particular, encoded '%' is rejected so a downstream that
                // incorrectly decodes twice cannot manufacture a separator.
                if !(value.is_ascii_alphanumeric() || matches!(value, b'-' | b'.' | b'_' | b'~')) {
                    return Err(PathError::ForbiddenEncoding);
                }
                decoded.push(value);
                index += 3;
            }
            b'\\' | 0..=0x1f | 0x7f => return Err(PathError::ForbiddenEncoding),
            value => {
                decoded.push(value);
                index += 1;
            }
        }
    }

    let path = String::from_utf8(decoded).map_err(|_| PathError::InvalidUtf8)?;
    if path.contains("//") || path.split('/').any(|segment| matches!(segment, "." | "..")) {
        return Err(PathError::AmbiguousSegment);
    }
    Ok(path)
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

pub fn canonical_spiffe_id(raw: &str) -> Result<String> {
    if raw.len() > 2_048 {
        bail!("SPIFFE identity exceeds 2048 bytes");
    }
    let remainder = raw
        .strip_prefix("spiffe://")
        .context("identity must use the lowercase spiffe:// scheme")?;
    let (trust_domain, path) = remainder
        .split_once('/')
        .context("SPIFFE identity must contain an absolute workload path")?;
    if trust_domain.is_empty()
        || trust_domain.len() > 255
        || trust_domain.starts_with('.')
        || trust_domain.starts_with('-')
        || trust_domain.ends_with('.')
        || trust_domain.ends_with('-')
        || !trust_domain.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
    {
        bail!("SPIFFE trust domain is invalid or non-canonical");
    }
    if path.is_empty()
        || path.contains("//")
        || path
            .split('/')
            .any(|segment| matches!(segment, "" | "." | ".."))
        || !path.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'/' | b':' | b'@')
        })
    {
        bail!("SPIFFE workload path is invalid or non-canonical");
    }
    Ok(raw.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> PolicyEngine {
        PolicyEngine::from_json(
            br#"{
                "policies": [{
                    "identity": "spiffe://acme/prod/reporting-agent",
                    "allow": [
                        {"method": "GET", "path": "/reports/*"},
                        {"method": "POST", "path": "/payments"}
                    ]
                }]
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn prefix_matching_is_segment_anchored() {
        let engine = engine();
        let identity = "spiffe://acme/prod/reporting-agent";
        assert!(engine.is_allowed(identity, &Method::GET, "/reports/2026"));
        assert!(!engine.is_allowed(identity, &Method::GET, "/reports-evil/2026"));
        assert!(!engine.is_allowed(identity, &Method::GET, "/reports"));
    }

    #[test]
    fn method_and_identity_must_match_exactly() {
        let engine = engine();
        assert!(!engine.is_allowed("spiffe://acme/prod/other", &Method::POST, "/payments"));
        assert!(!engine.is_allowed(
            "spiffe://acme/prod/reporting-agent",
            &Method::GET,
            "/payments"
        ));
    }

    #[test]
    fn rejects_path_confusion_inputs() {
        for path in [
            "/reports//secret",
            "/reports/../secret",
            "/reports/%2fsecret",
            "/reports/%5Csecret",
            "/reports/%2e%2e/secret",
            "/reports/%252fsecret",
            "/reports/%3fadmin=true",
            "/reports/%00",
        ] {
            assert!(canonicalize_path(path).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn canonicalizes_safe_percent_encoding() {
        assert_eq!(
            canonicalize_path("/reports/%32%30%32%36").unwrap(),
            "/reports/2026"
        );
    }

    #[test]
    fn rejects_ambiguous_or_duplicate_rules() {
        assert!(PolicyEngine::from_json(br#"{"policies": []}"#).is_err());
        assert!(
            PolicyEngine::from_json(
                br#"{
            "policies": [{"identity":"spiffe://acme/prod/a","allow":[
                {"method":"GET","path":"/x"},
                {"method":"GET","path":"/x"}
            ]}]
        }"#
            )
            .is_err()
        );
        assert!(
            PolicyEngine::from_json(
                br#"{
            "policies": [{"identity":"spiffe://acme/prod/a","allow":[
                {"method":"GET","path":"/x/*/y"}
            ]}]
        }"#
            )
            .is_err()
        );
    }

    #[test]
    fn validates_strict_spiffe_subset() {
        assert!(canonical_spiffe_id("spiffe://acme/prod/agent").is_ok());
        assert!(canonical_spiffe_id("SPIFFE://acme/prod/agent").is_err());
        assert!(canonical_spiffe_id("spiffe://ACME/prod/agent").is_err());
        assert!(canonical_spiffe_id("spiffe://acme/prod/../admin").is_err());
        assert!(canonical_spiffe_id("spiffe://acme").is_err());
    }
}

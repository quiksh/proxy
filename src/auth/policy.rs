//! Claim requirements checked after a token's signature and standard claims.
//!
//! Two layers use the same [`Requirements`] type:
//! - an `[[auth]]` block's own `claim_equals` / `claim_contains` - what every
//!   token from that issuer must satisfy, wherever the block is used;
//! - a route's `[routes.require]` - what that route needs on top, including
//!   authentication strength (`amr`) and recency (`max_auth_age_seconds`).
//!
//! Claim rules are authorisation (failure → 403). `amr` / auth age are
//! authentication (failure → step up). [`Requirements::check`] runs claim
//! rules first so nobody is sent to step up for a route they couldn't use.

use crate::config::{AuthBlockConfig, ClaimValue, RouteRequireConfig};

use super::{AuthError, Claims};

/// Same leeway jsonwebtoken gives `exp`, for small clock skew on `auth_time`.
const CLOCK_LEEWAY_SECS: i64 = 60;

#[derive(Debug, Default)]
pub struct Requirements {
    claim_equals: Vec<(String, ClaimValue)>,
    claim_contains: Vec<(String, String)>,
    amr: Vec<String>,
    max_auth_age_secs: Option<u64>,
}

impl Requirements {
    /// An `[[auth]]` block's issuer-wide claim rules (no step-up fields).
    pub fn from_block(cfg: &AuthBlockConfig) -> Self {
        Self {
            claim_equals: pairs(&cfg.claim_equals),
            claim_contains: pairs(&cfg.claim_contains),
            ..Default::default()
        }
    }

    pub fn from_route(cfg: &RouteRequireConfig) -> Self {
        Self {
            claim_equals: pairs(&cfg.claim_equals),
            claim_contains: pairs(&cfg.claim_contains),
            amr: cfg.amr.clone(),
            max_auth_age_secs: cfg.max_auth_age_seconds,
        }
    }

    /// Required `amr` values, for telling the sign-in service what to ask for.
    pub fn amr(&self) -> &[String] {
        &self.amr
    }

    pub fn max_auth_age_secs(&self) -> Option<u64> {
        self.max_auth_age_secs
    }

    /// Whether this asks anything of *how* the user authenticated.
    pub fn has_step_up(&self) -> bool {
        !self.amr.is_empty() || self.max_auth_age_secs.is_some()
    }

    /// Claim rules first (403), then authentication strength and age (step up).
    pub fn check(&self, claims: &Claims) -> Result<(), AuthError> {
        self.check_claims(claims)?;
        self.check_authentication(claims, unix_now())
    }

    fn check_claims(&self, claims: &Claims) -> Result<(), AuthError> {
        for (name, want) in &self.claim_equals {
            if !claim_equals(claims.get(name.as_str()), want) {
                return Err(AuthError::ClaimMismatch(format!(
                    "claim '{name}' does not equal the required value"
                )));
            }
        }
        for (name, want) in &self.claim_contains {
            if !claim_contains(claims.get(name.as_str()), want) {
                return Err(AuthError::ClaimMismatch(format!(
                    "claim '{name}' does not contain '{want}'"
                )));
            }
        }
        Ok(())
    }

    fn check_authentication(&self, claims: &Claims, now: i64) -> Result<(), AuthError> {
        for method in &self.amr {
            if !claims
                .get("amr")
                .and_then(|v| v.as_array())
                .is_some_and(|a| a.iter().any(|m| m.as_str() == Some(method)))
            {
                return Err(AuthError::InsufficientAuthentication(format!(
                    "amr lacks '{method}'"
                )));
            }
        }
        if let Some(max_age) = self.max_auth_age_secs {
            let Some(auth_time) = claims.get("auth_time").and_then(|v| v.as_i64()) else {
                return Err(AuthError::InsufficientAuthentication(
                    "missing auth_time".into(),
                ));
            };
            if auth_time > now + CLOCK_LEEWAY_SECS {
                return Err(AuthError::InsufficientAuthentication(
                    "auth_time is in the future".into(),
                ));
            }
            if now - auth_time > max_age as i64 {
                return Err(AuthError::InsufficientAuthentication(
                    "auth_time older than max_auth_age_seconds".into(),
                ));
            }
        }
        Ok(())
    }
}

fn pairs<V: Clone>(m: &std::collections::BTreeMap<String, V>) -> Vec<(String, V)> {
    m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Typed comparison: `true` never equals `"true"`, `2` never equals `"2"`.
fn claim_equals(v: Option<&serde_json::Value>, want: &ClaimValue) -> bool {
    match (v, want) {
        (Some(serde_json::Value::String(s)), ClaimValue::String(w)) => s == w,
        (Some(serde_json::Value::Bool(b)), ClaimValue::Bool(w)) => b == w,
        (Some(serde_json::Value::Number(n)), ClaimValue::Integer(w)) => n.as_i64() == Some(*w),
        _ => false,
    }
}

/// Array claims match on an element; string claims on a whitespace-separated
/// token (OAuth `scope = "read write"`). Anything else never matches.
fn claim_contains(v: Option<&serde_json::Value>, want: &str) -> bool {
    match v {
        Some(serde_json::Value::Array(a)) => a.iter().any(|x| x.as_str() == Some(want)),
        Some(serde_json::Value::String(s)) => s.split_ascii_whitespace().any(|t| t == want),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn route(amr: &[&str], max_age: Option<u64>) -> Requirements {
        Requirements {
            amr: amr.iter().map(|s| s.to_string()).collect(),
            max_auth_age_secs: max_age,
            ..Default::default()
        }
    }

    #[test]
    fn auth_time_boundaries() {
        let r = route(&[], Some(300));
        let at = |t: i64| json!({ "auth_time": t });
        let now = 1_000_000;
        assert!(r.check_authentication(&at(now - 300), now).is_ok());
        assert!(r.check_authentication(&at(now - 301), now).is_err());
        assert!(r.check_authentication(&at(now + 60), now).is_ok());
        assert!(r.check_authentication(&at(now + 61), now).is_err());
        assert!(r.check_authentication(&json!({}), now).is_err());
        assert!(
            r.check_authentication(&json!({ "auth_time": "1000000" }), now)
                .is_err()
        );
    }

    #[test]
    fn amr_needs_every_listed_method_in_an_array() {
        let r = route(&["hwk", "pin"], None);
        assert!(
            r.check_authentication(&json!({ "amr": ["hwk", "pin", "x"] }), 0)
                .is_ok()
        );
        assert!(
            r.check_authentication(&json!({ "amr": ["hwk"] }), 0)
                .is_err()
        );
        // A string amr is not a list of methods.
        assert!(
            r.check_authentication(&json!({ "amr": "hwk pin" }), 0)
                .is_err()
        );
    }

    #[test]
    fn claim_rules_run_before_step_up() {
        let r = Requirements {
            claim_contains: vec![("groups".into(), "admins".into())],
            amr: vec!["hwk".into()],
            ..Default::default()
        };
        let err = r.check(&json!({ "groups": ["staff"] })).unwrap_err();
        assert!(matches!(err, AuthError::ClaimMismatch(_)), "{err}");
    }

    #[test]
    fn typed_equality_and_token_containment() {
        assert!(claim_equals(Some(&json!(true)), &ClaimValue::Bool(true)));
        assert!(!claim_equals(Some(&json!("true")), &ClaimValue::Bool(true)));
        assert!(!claim_equals(Some(&json!("2")), &ClaimValue::Integer(2)));
        assert!(!claim_equals(None, &ClaimValue::String("x".into())));
        assert!(claim_contains(Some(&json!("read write")), "write"));
        assert!(!claim_contains(Some(&json!("read writer")), "write"));
        assert!(!claim_contains(Some(&json!({ "write": true })), "write"));
    }
}

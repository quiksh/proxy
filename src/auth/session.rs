//! Browser-session plumbing for `[[auth]]` blocks with `token_cookie` /
//! `login_redirect`: reading the token from a cookie, removing it before the
//! request goes upstream, and deciding when (and where) to redirect a browser
//! to sign in.
//!
//! quik only *validates* sessions. Issuing them - the sign-in page, the IdP
//! round trip, minting and signing the JWT - belongs to a separate service;
//! see `docs/identity-aware-proxy.md` for the contract between the two.

use http::header::{ACCEPT, COOKIE, HOST};
use http::{HeaderMap, HeaderValue, Method};

use crate::config::LOGIN_REDIRECT_URL_PLACEHOLDER;

/// The value of cookie `name`, searching every `Cookie` header (HTTP/2 clients
/// may split cookies across several). First match wins. Empty values count as
/// absent.
pub fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|pair| {
            let (k, v) = pair.trim().split_once('=')?;
            (k == name && !v.is_empty()).then_some(v)
        })
}

/// Remove cookie `name` from every `Cookie` header, dropping headers left
/// empty and leaving all other cookies untouched. No-op (and no allocation)
/// when the cookie isn't present.
pub fn strip_cookie(headers: &mut HeaderMap, name: &str) {
    let has = |pair: &str| pair.trim().split_once('=').is_some_and(|(k, _)| k == name);
    let present = headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.split(';').any(has));
    if !present {
        return;
    }
    let kept: Vec<HeaderValue> = headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| {
            let rest: Vec<&str> = v
                .split(';')
                .map(str::trim)
                .filter(|p| !p.is_empty() && !has(p))
                .collect();
            (!rest.is_empty()).then(|| rest.join("; "))
        })
        .filter_map(|v| HeaderValue::try_from(v).ok())
        .collect();
    headers.remove(COOKIE);
    for v in kept {
        headers.append(COOKIE, v);
    }
}

/// Whether this request is a browser loading a page, as opposed to `fetch`,
/// XHR, an image or a script client. Only page loads are worth redirecting to
/// a login page: anything else would follow the redirect invisibly (or fail
/// CORS) and should get a 401 the caller can act on.
///
/// `Sec-Fetch-Mode: navigate` is authoritative where sent (all current
/// browsers). Without it, fall back to "GET/HEAD that accepts HTML".
pub fn is_navigation(method: &Method, headers: &HeaderMap) -> bool {
    if method != Method::GET && method != Method::HEAD {
        return false;
    }
    if let Some(mode) = headers.get("sec-fetch-mode") {
        return mode.as_bytes().eq_ignore_ascii_case(b"navigate");
    }
    headers
        .get(ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/html"))
}

/// The `Location` for a login redirect: `template` with `{url}` replaced by
/// the percent-encoded original URL (`https://{host}{path?query}`). The
/// listener is TLS-only - and behind a load balancer the client was on HTTPS
/// too - so the scheme is always `https`. `None` without a usable host.
///
/// The host comes from the client, so the sign-in service must validate the
/// return URL against its own allow-list before redirecting back to it.
pub fn login_location(template: &str, headers: &HeaderMap, uri: &http::Uri) -> Option<HeaderValue> {
    let host = headers
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| uri.authority().map(|a| a.as_str()))
        .filter(|h| !h.is_empty())?;
    let paq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let original = format!("https://{host}{paq}");
    let location = template.replace(LOGIN_REDIRECT_URL_PLACEHOLDER, &percent_encode(&original));
    HeaderValue::try_from(location).ok()
}

/// Percent-encode everything except RFC 3986 unreserved characters, so the
/// result is safe as a single query-parameter value.
fn percent_encode(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len() * 3);
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0xf) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn cookie_value_finds_exact_name_across_headers() {
        let h = headers(&[("cookie", "a=1; sess_x=no"), ("cookie", "sess=tok; b=2")]);
        assert_eq!(cookie_value(&h, "sess"), Some("tok"));
        assert_eq!(cookie_value(&h, "a"), Some("1"));
        assert_eq!(cookie_value(&h, "missing"), None);
        // Prefix of another cookie's name must not match.
        assert_eq!(
            cookie_value(&headers(&[("cookie", "sess_x=no")]), "sess"),
            None
        );
        assert_eq!(cookie_value(&headers(&[("cookie", "sess=")]), "sess"), None);
    }

    #[test]
    fn strip_cookie_removes_only_the_named_cookie() {
        let mut h = headers(&[("cookie", "a=1; sess=tok; b=2"), ("cookie", "sess=again")]);
        strip_cookie(&mut h, "sess");
        let all: Vec<_> = h.get_all(COOKIE).iter().collect();
        assert_eq!(all, vec!["a=1; b=2"]);

        let mut only = headers(&[("cookie", "sess=tok")]);
        strip_cookie(&mut only, "sess");
        assert!(only.get(COOKIE).is_none());

        let mut untouched = headers(&[("cookie", "sess_x=1;other=2")]);
        strip_cookie(&mut untouched, "sess");
        assert_eq!(untouched.get(COOKIE).unwrap(), "sess_x=1;other=2");
    }

    #[test]
    fn navigation_detection() {
        let nav = headers(&[("sec-fetch-mode", "navigate"), ("accept", "*/*")]);
        assert!(is_navigation(&Method::GET, &nav));
        assert!(!is_navigation(&Method::POST, &nav));
        // Sec-Fetch-Mode wins over Accept when present.
        let fetch = headers(&[("sec-fetch-mode", "cors"), ("accept", "text/html")]);
        assert!(!is_navigation(&Method::GET, &fetch));
        // Fallback for clients without Fetch Metadata.
        let html = headers(&[("accept", "text/html,application/xhtml+xml")]);
        assert!(is_navigation(&Method::GET, &html));
        assert!(!is_navigation(
            &Method::GET,
            &headers(&[("accept", "application/json")])
        ));
        assert!(!is_navigation(&Method::GET, &HeaderMap::new()));
    }

    #[test]
    fn login_location_encodes_original_url() {
        let h = headers(&[("host", "admin.corp.example.com")]);
        let uri: http::Uri = "/a/b?x=1&y=two words".replace(' ', "%20").parse().unwrap();
        let loc = login_location("https://auth.corp.example.com/login?rd={url}", &h, &uri).unwrap();
        assert_eq!(
            loc,
            "https://auth.corp.example.com/login?rd=https%3A%2F%2Fadmin.corp.example.com%2Fa%2Fb%3Fx%3D1%26y%3Dtwo%2520words"
        );
    }

    #[test]
    fn login_location_uses_h2_authority_and_needs_a_host() {
        let uri: http::Uri = "https://admin.corp.example.com/".parse().unwrap();
        let loc = login_location("https://auth/l?rd={url}", &HeaderMap::new(), &uri).unwrap();
        assert_eq!(
            loc,
            "https://auth/l?rd=https%3A%2F%2Fadmin.corp.example.com%2F"
        );

        let no_host: http::Uri = "/".parse().unwrap();
        assert!(login_location("https://auth/l?rd={url}", &HeaderMap::new(), &no_host).is_none());
    }

    #[test]
    fn hostile_host_cannot_inject_into_location() {
        // Whatever the client puts in Host is percent-encoded into one value.
        let h = headers(&[("host", "evil.com/x?rd=https://attacker")]);
        let uri: http::Uri = "/".parse().unwrap();
        let loc = login_location("https://auth/l?rd={url}", &h, &uri).unwrap();
        let s = loc.to_str().unwrap();
        assert!(s.starts_with("https://auth/l?rd=https%3A%2F%2Fevil.com%2Fx%3Frd%3D"));
        assert_eq!(s.matches('?').count(), 1);
    }
}

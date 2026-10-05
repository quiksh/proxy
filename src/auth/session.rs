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

/// The cookie pairs in one `Cookie` header value, as raw bytes. Works on bytes
/// rather than `to_str()` so an unrelated cookie with non-ASCII (obs-text)
/// bytes can't hide or drop the others.
fn pairs(v: &HeaderValue) -> impl Iterator<Item = &[u8]> {
    v.as_bytes().split(|&b| b == b';').map(<[u8]>::trim_ascii)
}

fn is_named(pair: &[u8], name: &str) -> bool {
    pair.split(|&b| b == b'=')
        .next()
        .is_some_and(|k| k == name.as_bytes())
        && pair.contains(&b'=')
}

/// The value of cookie `name`, searching every `Cookie` header (HTTP/2 clients
/// may split cookies across several). First match wins. Empty or non-UTF-8
/// values count as absent.
pub fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .flat_map(pairs)
        .filter(|p| is_named(p, name))
        .find_map(|p| {
            let v = &p[name.len() + 1..];
            (!v.is_empty())
                .then(|| std::str::from_utf8(v).ok())
                .flatten()
        })
}

/// Remove cookie `name` from every `Cookie` header. Headers that don't carry
/// it are kept byte-for-byte; headers left empty are dropped. No-op (and no
/// allocation) when the cookie isn't present.
pub fn strip_cookie(headers: &mut HeaderMap, name: &str) {
    let carries = |v: &HeaderValue| pairs(v).any(|p| is_named(p, name));
    if !headers.get_all(COOKIE).iter().any(carries) {
        return;
    }
    let kept: Vec<HeaderValue> = headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| {
            if !carries(v) {
                return Some(v.clone());
            }
            let rest: Vec<&[u8]> = pairs(v)
                .filter(|p| !p.is_empty() && !is_named(p, name))
                .collect();
            if rest.is_empty() {
                return None;
            }
            // Bytes came from a valid HeaderValue, so rejoining them is too.
            HeaderValue::from_bytes(&rest.join(&b"; "[..])).ok()
        })
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
///
/// `params` are appended to the query (percent-encoded) - how the route's
/// step-up requirements reach the sign-in service. Config validation rejects
/// templates with a fragment, so appending is always safe.
pub fn login_location(
    template: &str,
    headers: &HeaderMap,
    uri: &http::Uri,
    params: &[(&str, &str)],
) -> Option<HeaderValue> {
    let host = headers
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| uri.authority().map(|a| a.as_str()))
        .filter(|h| !h.is_empty())?;
    let paq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let original = format!("https://{host}{paq}");
    let mut location = template.replace(LOGIN_REDIRECT_URL_PLACEHOLDER, &percent_encode(&original));
    for (k, v) in params {
        location.push(if location.contains('?') { '&' } else { '?' });
        location.push_str(k);
        location.push('=');
        location.push_str(&percent_encode(v));
    }
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
    fn non_ascii_cookies_neither_hide_nor_lose_others() {
        let mut h = HeaderMap::new();
        h.append(
            COOKIE,
            HeaderValue::from_bytes("lang=fr-\u{e9}; sess=tok".as_bytes()).unwrap(),
        );
        h.append(
            COOKIE,
            HeaderValue::from_bytes("city=K\u{f6}ln".as_bytes()).unwrap(),
        );
        assert_eq!(cookie_value(&h, "sess"), Some("tok"));

        strip_cookie(&mut h, "sess");
        let all: Vec<&[u8]> = h.get_all(COOKIE).iter().map(|v| v.as_bytes()).collect();
        assert_eq!(
            all,
            vec!["lang=fr-\u{e9}".as_bytes(), "city=K\u{f6}ln".as_bytes()]
        );
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
        let h = headers(&[("host", "admin.corp.example.test")]);
        let uri: http::Uri = "/a/b?x=1&y=two words".replace(' ', "%20").parse().unwrap();
        let loc = login_location(
            "https://auth.corp.example.test/login?rd={url}",
            &h,
            &uri,
            &[],
        )
        .unwrap();
        assert_eq!(
            loc,
            "https://auth.corp.example.test/login?rd=https%3A%2F%2Fadmin.corp.example.test%2Fa%2Fb%3Fx%3D1%26y%3Dtwo%2520words"
        );
    }

    #[test]
    fn login_location_uses_h2_authority_and_needs_a_host() {
        let uri: http::Uri = "https://admin.corp.example.test/".parse().unwrap();
        let loc = login_location("https://auth/l?rd={url}", &HeaderMap::new(), &uri, &[]).unwrap();
        assert_eq!(
            loc,
            "https://auth/l?rd=https%3A%2F%2Fadmin.corp.example.test%2F"
        );

        let no_host: http::Uri = "/".parse().unwrap();
        assert!(
            login_location("https://auth/l?rd={url}", &HeaderMap::new(), &no_host, &[]).is_none()
        );
    }

    #[test]
    fn step_up_params_are_appended_and_encoded() {
        let h = headers(&[("host", "a.example.test")]);
        let uri: http::Uri = "/".parse().unwrap();
        let loc = login_location(
            "https://auth/l?rd={url}",
            &h,
            &uri,
            &[("amr_values", "hwk pin"), ("max_age", "300")],
        )
        .unwrap();
        assert_eq!(
            loc,
            "https://auth/l?rd=https%3A%2F%2Fa.example.test%2F&amr_values=hwk%20pin&max_age=300"
        );
        // A template without a query gets one.
        let loc = login_location("https://auth/login", &h, &uri, &[("max_age", "5")]).unwrap();
        assert_eq!(loc, "https://auth/login?max_age=5");
    }

    #[test]
    fn hostile_host_cannot_inject_into_location() {
        // Whatever the client puts in Host is percent-encoded into one value.
        let h = headers(&[("host", "evil.invalid/x?rd=https://attacker")]);
        let uri: http::Uri = "/".parse().unwrap();
        let loc = login_location("https://auth/l?rd={url}", &h, &uri, &[]).unwrap();
        let s = loc.to_str().unwrap();
        assert!(s.starts_with("https://auth/l?rd=https%3A%2F%2Fevil.invalid%2Fx%3Frd%3D"));
        assert_eq!(s.matches('?').count(), 1);
    }
}

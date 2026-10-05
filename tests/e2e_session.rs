//! End-to-end tests for browser sessions on `[[auth]]` blocks: token from a
//! cookie, session-cookie stripping, login redirects for page loads, claim
//! value policy on the block and the route, and step-up via
//! `[routes.require]` (`amr` / `max_auth_age_seconds`).

mod common;

use std::net::SocketAddr;

use http::StatusCode;
use quik::config::{AuthBlockConfig, ClaimValue, RouteConfig, RouteRequireConfig};

use common::{ProxySpec, TestJwtSigner};

const COOKIE: &str = "__Secure-corp_session";
const LOGIN: &str = "https://auth.corp.example.test/login?rd={url}";

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn claims() -> serde_json::Value {
    serde_json::json!({
        "iss": "https://auth.corp.example.test",
        "aud": "corp",
        "sub": "u-1",
        "email": "alice@example.test",
        "hd": "example.test",
        "groups": ["staff", "admin-api-users"],
        "scope": "read write",
        "amr": ["google", "hwk"],
        "auth_time": now() - 30,
        "iat": now() - 30,
        "exp": now() + 600,
    })
}

fn with(mut base: serde_json::Value, key: &str, v: serde_json::Value) -> serde_json::Value {
    base[key] = v;
    base
}

fn without(mut base: serde_json::Value, key: &str) -> serde_json::Value {
    base.as_object_mut().unwrap().remove(key);
    base
}

/// A session block as the sign-in service contract describes it.
fn session_block(jwks: SocketAddr) -> AuthBlockConfig {
    AuthBlockConfig {
        name: "corp".into(),
        jwks_url: format!("http://{jwks}/jwks.json"),
        issuer: Some("https://auth.corp.example.test".into()),
        audience: Some("corp".into()),
        algorithms: vec!["EdDSA".into()],
        token_cookie: Some(COOKIE.into()),
        login_redirect: Some(LOGIN.into()),
        inject_headers: vec![quik::config::ClaimHeaderMapping {
            claim: "email".into(),
            header: "x-auth-email".into(),
            required: true,
        }],
        ..Default::default()
    }
}

struct Harness {
    backend: common::Backend,
    signer: TestJwtSigner,
    proxy: common::ProxyHandle,
    client: reqwest::Client,
}

impl Harness {
    async fn new(tweak: impl FnOnce(&mut AuthBlockConfig)) -> Self {
        Self::with_require(tweak, None).await
    }

    /// As [`new`](Self::new), with `[routes.require]` on the single route.
    async fn with_require(
        tweak: impl FnOnce(&mut AuthBlockConfig),
        require: Option<RouteRequireConfig>,
    ) -> Self {
        let signer = TestJwtSigner::with_kid("k1");
        let (jwks, _) = common::spawn_jwks_server(signer.jwks_json());
        let backend = common::Backend::spawn("app").await;
        let mut block = session_block(jwks);
        tweak(&mut block);
        let proxy = common::spawn_proxy_with_auth(
            ProxySpec {
                pools: vec![common::Backends::http("p", vec![backend.addr])],
                routes: vec![RouteConfig {
                    path_prefix: Some("/".into()),
                    auth: Some("corp".into()),
                    require,
                    upstream: "p".into(),
                    ..Default::default()
                }],
            },
            vec![block],
        )
        .await;
        // Redirects must be observed, not followed.
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        Self {
            backend,
            signer,
            proxy,
            client,
        }
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.client
            .get(format!(
                "https://localhost:{}{path}",
                self.proxy.addr.port()
            ))
            .header("host", "admin.corp.example.test")
    }

    fn cookie(&self, claims: serde_json::Value) -> String {
        format!("{COOKIE}={}", self.signer.sign(claims))
    }
}

fn navigate(rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    rb.header("sec-fetch-mode", "navigate")
        .header("accept", "text/html,application/xhtml+xml")
}

#[tokio::test]
async fn session_cookie_authenticates_and_is_stripped_upstream() {
    let h = Harness::new(|_| {}).await;
    let resp = h
        .get("/dash")
        .header(
            "cookie",
            format!("theme=dark; {}; lang=en", h.cookie(claims())),
        )
        .header("authorization", "Bearer app-token-123")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let calls = h.backend.calls();
    assert_eq!(calls.len(), 1);
    let hdrs = &calls[0].headers;
    assert_eq!(hdrs.get("x-auth-email").unwrap(), "alice@example.test");
    // The app's own bearer token rides through untouched.
    assert_eq!(hdrs.get("authorization").unwrap(), "Bearer app-token-123");
    // The session token is quik's, not the app's.
    assert_eq!(hdrs.get("cookie").unwrap(), "theme=dark; lang=en");
}

#[tokio::test]
async fn forward_token_cookie_keeps_the_session_cookie() {
    let h = Harness::new(|b| b.forward_token_cookie = true).await;
    let cookie = h.cookie(claims());
    let resp = h.get("/").header("cookie", &cookie).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(h.backend.calls()[0].headers.get("cookie").unwrap(), &cookie);
}

#[tokio::test]
async fn bearer_header_is_not_a_session_when_token_cookie_is_set() {
    let h = Harness::new(|b| b.login_redirect = None).await;
    // A perfectly valid session JWT, but in the wrong place.
    let resp = h
        .get("/")
        .header(
            "authorization",
            format!("Bearer {}", h.signer.sign(claims())),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn page_load_without_session_redirects_to_login_with_return_url() {
    let h = Harness::new(|_| {}).await;
    let resp = navigate(h.get("/reports?q=1")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "https://auth.corp.example.test/login?rd=https%3A%2F%2Fadmin.corp.example.test%2Freports%3Fq%3D1"
    );
    assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
    assert!(h.backend.calls().is_empty());
}

#[tokio::test]
async fn fetch_and_post_without_session_get_401_not_a_redirect() {
    let h = Harness::new(|_| {}).await;
    let fetch = h
        .get("/api/x")
        .header("sec-fetch-mode", "cors")
        .header("accept", "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(fetch.status(), StatusCode::UNAUTHORIZED);

    let post = h
        .client
        .post(format!("https://localhost:{}/form", h.proxy.addr.port()))
        .header("sec-fetch-mode", "navigate")
        .header("accept", "text/html")
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_session_redirects_page_loads_and_403s_otherwise() {
    let h = Harness::new(|_| {}).await;
    let expired = h.cookie(with(claims(), "exp", (now() - 120).into()));
    let page = navigate(h.get("/"))
        .header("cookie", &expired)
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::FOUND);
    // Non-navigations keep the long-standing bearer semantics for `exp`.
    let api = h.get("/").header("cookie", &expired).send().await.unwrap();
    assert_eq!(api.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn claim_equals_mismatch_is_403_and_never_redirects() {
    let h = Harness::new(|b| {
        b.claim_equals
            .insert("hd".into(), ClaimValue::String("example.test".into()));
    })
    .await;
    let ok = h
        .get("/")
        .header("cookie", h.cookie(claims()))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);

    let other_domain = h.cookie(with(claims(), "hd", "other.invalid".into()));
    let resp = navigate(h.get("/"))
        .header("cookie", other_domain)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let missing = h.cookie(without(claims(), "hd"));
    let resp = h.get("/").header("cookie", missing).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn claim_equals_compares_bools_and_integers_by_type() {
    let h = Harness::new(|b| {
        b.claim_equals
            .insert("email_verified".into(), ClaimValue::Bool(true));
        b.claim_equals.insert("tier".into(), ClaimValue::Integer(2));
    })
    .await;
    let good = with(
        with(claims(), "email_verified", true.into()),
        "tier",
        2.into(),
    );
    let resp = h
        .get("/")
        .header("cookie", h.cookie(good))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // "true" (string) is not true (bool).
    let stringly = with(
        with(claims(), "email_verified", "true".into()),
        "tier",
        2.into(),
    );
    let resp = h
        .get("/")
        .header("cookie", h.cookie(stringly))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn claim_contains_matches_array_elements_and_scope_tokens() {
    let h = Harness::new(|b| {
        b.claim_contains
            .insert("groups".into(), "admin-api-users".into());
        b.claim_contains.insert("scope".into(), "write".into());
    })
    .await;
    let ok = h
        .get("/")
        .header("cookie", h.cookie(claims()))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);

    let no_group = h.cookie(with(claims(), "groups", serde_json::json!(["staff"])));
    let resp = h.get("/").header("cookie", no_group).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Substring of a token is not a token.
    let narrow = h.cookie(with(claims(), "scope", "read writer".into()));
    let resp = h.get("/").header("cookie", narrow).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

fn require_hwk() -> RouteRequireConfig {
    RouteRequireConfig {
        amr: vec!["hwk".into()],
        ..Default::default()
    }
}

#[tokio::test]
async fn route_claim_rules_add_to_the_block_rules() {
    let h = Harness::with_require(
        |b| {
            b.claim_equals
                .insert("hd".into(), ClaimValue::String("example.test".into()));
        },
        Some(RouteRequireConfig {
            claim_contains: [("groups".to_string(), "admin-api-users".to_string())].into(),
            ..Default::default()
        }),
    )
    .await;
    let ok = h
        .get("/")
        .header("cookie", h.cookie(claims()))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);

    // Block rule still applies on a route with its own rules...
    let other_domain = h.cookie(with(claims(), "hd", "other.invalid".into()));
    let resp = h
        .get("/")
        .header("cookie", other_domain)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // ...and so does the route's.
    let no_group = h.cookie(with(claims(), "groups", serde_json::json!(["staff"])));
    let resp = h.get("/").header("cookie", no_group).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn missing_amr_steps_up_page_loads_and_challenges_api_calls() {
    let h = Harness::with_require(|_| {}, Some(require_hwk())).await;
    let google_only = h.cookie(with(claims(), "amr", serde_json::json!(["google"])));

    let page = navigate(h.get("/"))
        .header("cookie", &google_only)
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::FOUND);
    assert!(
        page.headers()["location"]
            .to_str()
            .unwrap()
            .ends_with("%2F&amr_values=hwk"),
        "{:?}",
        page.headers()["location"]
    );

    let api = h
        .get("/")
        .header("cookie", &google_only)
        .send()
        .await
        .unwrap();
    assert_eq!(api.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        api.headers()["www-authenticate"],
        "Bearer error=\"insufficient_user_authentication\", amr_values=\"hwk\""
    );

    let stepped_up = h
        .get("/")
        .header("cookie", h.cookie(claims()))
        .send()
        .await
        .unwrap();
    assert_eq!(stepped_up.status(), StatusCode::OK);
}

#[tokio::test]
async fn first_sign_in_on_a_step_up_route_asks_for_everything_at_once() {
    // No session at all: the redirect already carries the route's step-up
    // requirements, so the user signs in and touches the key in one trip.
    let h = Harness::with_require(
        |_| {},
        Some(RouteRequireConfig {
            amr: vec!["hwk".into()],
            max_auth_age_seconds: Some(900),
            ..Default::default()
        }),
    )
    .await;
    let page = navigate(h.get("/x")).send().await.unwrap();
    assert_eq!(page.status(), StatusCode::FOUND);
    assert_eq!(
        page.headers()["location"],
        "https://auth.corp.example.test/login?rd=https%3A%2F%2Fadmin.corp.example.test%2Fx\
         &amr_values=hwk&max_age=900"
    );
}

#[tokio::test]
async fn routes_without_require_ignore_step_up() {
    // The same block on a route without `require` accepts a Google-only
    // session - step-up is a route property, not an issuer property.
    let h = Harness::new(|_| {}).await;
    let google_only = h.cookie(with(claims(), "amr", serde_json::json!(["google"])));
    let resp = h
        .get("/")
        .header("cookie", google_only)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn max_auth_age_requires_a_recent_auth_time() {
    let h = Harness::with_require(
        |b| b.login_redirect = None,
        Some(RouteRequireConfig {
            max_auth_age_seconds: Some(300),
            ..Default::default()
        }),
    )
    .await;
    let fresh = h
        .get("/")
        .header("cookie", h.cookie(claims()))
        .send()
        .await
        .unwrap();
    assert_eq!(fresh.status(), StatusCode::OK);

    for stale in [
        with(claims(), "auth_time", (now() - 301).into()),
        without(claims(), "auth_time"),
        with(claims(), "auth_time", (now() + 3600).into()),
    ] {
        let resp = h
            .get("/")
            .header("cookie", h.cookie(stale))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()["www-authenticate"],
            "Bearer error=\"insufficient_user_authentication\", max_age=300"
        );
    }
}

#[tokio::test]
async fn claim_policy_is_checked_before_step_up() {
    // Not in the group *and* no hardware key: refuse outright rather than
    // making the user touch a key for a route they can't use.
    let h = Harness::with_require(
        |_| {},
        Some(RouteRequireConfig {
            claim_contains: [("groups".to_string(), "admins".to_string())].into(),
            amr: vec!["hwk".into()],
            ..Default::default()
        }),
    )
    .await;
    let weak = h.cookie(with(claims(), "amr", serde_json::json!(["google"])));
    let resp = navigate(h.get("/"))
        .header("cookie", weak)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn plain_bearer_block_does_not_redirect() {
    // A plain bearer block (no cookie, no redirect) still 401s page loads -
    // login_redirect is opt-in.
    let h = Harness::new(|b| {
        b.token_cookie = None;
        b.login_redirect = None;
    })
    .await;
    let resp = navigate(h.get("/")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let ok = h
        .get("/")
        .header(
            "authorization",
            format!("Bearer {}", h.signer.sign(claims())),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
}

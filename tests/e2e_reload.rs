//! Hot config reload e2e - drives `POST /admin/config/reload` against a real
//! file-backed proxy and asserts the live effect on routing, plus the
//! fail-safe behaviour (immutable change rejected, bad config rejected, the
//! proxy keeps serving the previous good config throughout).
//!
//! Unlike the rest of the suite this builds its stack from a config file on
//! disk (mirroring `main.rs`) because reload re-reads that file - the in-memory
//! `spawn_proxy` harness has no file to rewrite.

mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use http::StatusCode;
use serde_json::Value;
use tokio::net::TcpListener;

use common::{Backend, gen_cert, https_client};
use quik::shutdown::Coordinator;

/// A unique scratch dir under the system temp dir, removed on drop.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("quik-e2e-reload-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ReloadProxy {
    proxy_addr: SocketAddr,
    admin_addr: SocketAddr,
    cfg_path: PathBuf,
    _shutdown: Coordinator,
}

/// Build and serve a proxy from a config file, wiring the reload handle into
/// the admin listener - the file-backed equivalent of `main.rs`.
async fn serve_from_file(cfg_path: PathBuf) -> ReloadProxy {
    let cfg = Arc::new(quik::config::load(&cfg_path).expect("load config"));

    let routing = Arc::new(quik::routing::SharedRoutingTable::from_config(&cfg).expect("routing"));
    let upstreams = Arc::new(quik::upstream::Pool::from_config(&cfg).expect("pool"));
    let auth = Arc::new(quik::auth::SharedAuthRegistry::from_config_for_tests(&cfg).expect("auth"));
    let forwarded = Arc::new(quik::headers::SharedForwardedPolicy::from_config(
        &cfg.forwarded,
    ));

    let reload = quik::reload::ReloadHandle::new_for_tests(
        cfg_path.clone(),
        cfg.clone(),
        routing.clone(),
        forwarded.clone(),
        auth.clone(),
    );

    let shutdown = Coordinator::new(2, 0);

    let listener_cfg = cfg
        .listener
        .as_ref()
        .expect("reload e2e config has a listener");
    let proxy_listener = TcpListener::bind(listener_cfg.bind)
        .await
        .expect("bind proxy");
    let admin_listener = TcpListener::bind(cfg.admin.bind).await.expect("bind admin");
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();

    let metrics = common::shared_metrics_handle();
    let admin_auth = quik::admin::compile_auth(&cfg.admin).expect("admin auth");
    let admin_state = quik::admin::AdminState {
        metrics,
        upstreams: upstreams.clone(),
        auth_groups: admin_auth,
        reload: Some(reload),
    };
    let admin_tls = cfg.admin.tls.clone();
    let shutdown_admin = shutdown.clone();
    tokio::spawn(async move {
        quik::admin::serve(
            admin_listener,
            admin_state,
            admin_tls.as_ref(),
            shutdown_admin,
        )
        .await
    });

    let tls = quik::tls::build_acceptor(&listener_cfg.tls).expect("tls acceptor");
    let state = quik::proxy::ServerState {
        routing,
        upstreams,
        auth,
        mode: cfg.mode,
        forwarded,
        access: Arc::new(
            quik::proxy::AccessLogFields::from_logging(&cfg.logging).expect("logging"),
        ),
        limits: Arc::new(listener_cfg.limits.clone()),
    };
    tokio::spawn(quik::proxy::serve(
        proxy_listener,
        tls,
        state,
        shutdown.clone(),
    ));

    ReloadProxy {
        proxy_addr,
        admin_addr,
        cfg_path,
        _shutdown: shutdown,
    }
}

/// Render a config file. `extra_routes` is appended after the base `/api` route.
fn config_toml(
    cert: &Path,
    key: &Path,
    backend: SocketAddr,
    listener_port: u16,
    extra_routes: &str,
) -> String {
    format!(
        r#"
mode = "host"

[listener]
bind = "127.0.0.1:{listener_port}"
[listener.tls]
cert_path = "{cert}"
key_path = "{key}"

[admin]
bind = "127.0.0.1:0"

[logging]
level = "warn"

[[upstreams]]
name = "pool-a"
members = [{{ address = "{backend}", scheme = "http" }}]

[[routes]]
path_prefix = "/api"
upstream = "pool-a"
{extra_routes}
"#,
        cert = cert.display(),
        key = key.display(),
    )
}

fn proxy_url(addr: SocketAddr, path: &str) -> String {
    format!("https://localhost:{}{}", addr.port(), path)
}

async fn status(client: &reqwest::Client, addr: SocketAddr, path: &str) -> StatusCode {
    client
        .get(proxy_url(addr, path))
        .send()
        .await
        .unwrap()
        .status()
}

async fn reload(client: &reqwest::Client, admin: SocketAddr) -> reqwest::Response {
    client
        .post(format!("http://{admin}/admin/config/reload"))
        .send()
        .await
        .unwrap()
}

/// A running file-backed proxy plus the bits a test needs to rewrite its config
/// file and reload. Keeps the temp dir and backend alive for the test's scope.
struct Harness {
    proxy: ReloadProxy,
    client: reqwest::Client,
    cert_path: PathBuf,
    key_path: PathBuf,
    backend: Backend,
    _dir: TmpDir,
}

/// Boot a proxy from a fresh config file with the base `/api` route. The caller
/// asserts the baseline, then uses [`rewrite`] + [`reload`] to drive changes.
async fn setup() -> Harness {
    common::install_metrics_recorder();
    let backend = Backend::spawn("a").await;
    let dir = TmpDir::new();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    let cert = gen_cert();
    std::fs::write(&cert_path, &cert.cert_pem).unwrap();
    std::fs::write(&key_path, &cert.key_pem).unwrap();

    let cfg_path = dir.path().join("quik.toml");
    std::fs::write(
        &cfg_path,
        config_toml(&cert_path, &key_path, backend.addr, 0, ""),
    )
    .unwrap();

    let proxy = serve_from_file(cfg_path).await;
    Harness {
        proxy,
        client: https_client(),
        cert_path,
        key_path,
        backend,
        _dir: dir,
    }
}

/// Overwrite the harness's config file. `listener_port` of 0 keeps the listener
/// unchanged from the baseline (a non-zero value is a genuine immutable change).
fn rewrite(h: &Harness, listener_port: u16, extra_routes: &str) {
    std::fs::write(
        &h.proxy.cfg_path,
        config_toml(
            &h.cert_path,
            &h.key_path,
            h.backend.addr,
            listener_port,
            extra_routes,
        ),
    )
    .unwrap();
}

const CATCH_ALL_ROUTE: &str = "\n[[routes]]\npath_prefix = \"/\"\nupstream = \"pool-a\"\n";

#[tokio::test]
async fn reload_adds_route_live() {
    let h = setup().await;

    // Baseline: /api routes, / does not.
    assert_eq!(
        status(&h.client, h.proxy.proxy_addr, "/api").await,
        StatusCode::OK
    );
    assert_eq!(
        status(&h.client, h.proxy.proxy_addr, "/").await,
        StatusCode::NOT_FOUND
    );

    // Add a catch-all route, then reload via the admin API.
    rewrite(&h, 0, CATCH_ALL_ROUTE);
    let resp = reload(&h.client, h.proxy.admin_addr).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "reloaded");
    assert_eq!(body["routes"], 2);

    // The new route now serves on the same live listener.
    assert_eq!(
        status(&h.client, h.proxy.proxy_addr, "/").await,
        StatusCode::OK
    );
    assert_eq!(
        status(&h.client, h.proxy.proxy_addr, "/api").await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn reload_rejects_immutable_change_and_keeps_serving() {
    let h = setup().await;
    assert_eq!(
        status(&h.client, h.proxy.proxy_addr, "/api").await,
        StatusCode::OK
    );

    // Change the listener bind - an immutable section - plus add a route. The
    // baseline file binds port 0; a fixed non-zero port is a genuine change.
    // The whole reload must be rejected; neither change is applied.
    rewrite(&h, 19443, CATCH_ALL_ROUTE);
    let resp = reload(&h.client, h.proxy.admin_addr).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["detail"].as_str().unwrap().contains("listener"),
        "detail should name the offending section: {body:?}"
    );

    // The route addition that rode along was NOT applied, and /api still works.
    assert_eq!(
        status(&h.client, h.proxy.proxy_addr, "/").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status(&h.client, h.proxy.proxy_addr, "/api").await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn reload_rejects_bad_config_and_keeps_serving() {
    let h = setup().await;
    assert_eq!(
        status(&h.client, h.proxy.proxy_addr, "/api").await,
        StatusCode::OK
    );

    // A route referencing a non-existent pool fails validation in config::load.
    rewrite(
        &h,
        0,
        "\n[[routes]]\npath_prefix = \"/\"\nupstream = \"ghost\"\n",
    );
    let resp = reload(&h.client, h.proxy.admin_addr).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Proxy still serves the previous good config.
    assert_eq!(
        status(&h.client, h.proxy.proxy_addr, "/api").await,
        StatusCode::OK
    );
}

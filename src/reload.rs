//! Hot config reload.
//!
//! Re-reads the config file and atomically swaps the hot-reloadable subsystems
//! (routes, `[[auth]]` blocks, and the `[forwarded]` policy) without restarting
//! the process. Each swap is lock-free for readers (the proxy hot path),
//! reusing the same `ArcSwap` handles the listener already serves from, so an
//! in-flight request finishes on the config it started with and the next
//! request picks up the new one.
//!
//! Reload is **all-or-nothing**. A candidate config is fully loaded, validated,
//! and checked for changes to any section that *can't* be hot-swapped (see
//! [`crate::config::immutable_change`] - listeners, TLS, upstream pool shape,
//! egress, ...). If any immutable section changed, or the file fails to
//! load/validate, the running config is left completely untouched and the
//! reload reports an error. There is no partial application.
//!
//! Triggers: a `SIGHUP` signal (see [`install_sighup_handler`]) and the admin
//! API endpoint `POST /admin/config/reload`. Both funnel through
//! [`ReloadHandle::reload`].

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;

use crate::auth::{AuthRegistry, SharedAuthRegistry};
use crate::config::{self, Config};
use crate::headers::{ForwardedPolicy, SharedForwardedPolicy};
use crate::routing::{RoutingTable, SharedRoutingTable};

/// Why a reload could not be applied. The running config is unchanged in every
/// variant.
#[derive(Debug)]
pub enum ReloadError {
    /// The file could not be read, env-expanded, parsed, or failed validation.
    Load(anyhow::Error),
    /// A section that requires a restart changed (carries the section name).
    ImmutableChanged(&'static str),
    /// The config loaded and validated, but building the live state from it
    /// failed (e.g. an upstream address that parses in TOML but not as an
    /// `Authority`). Should be rare given validation, but kept distinct so the
    /// running config is preserved rather than half-swapped.
    Build(anyhow::Error),
}

impl std::fmt::Display for ReloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReloadError::Load(e) => write!(f, "config load failed: {e:#}"),
            ReloadError::ImmutableChanged(section) => write!(
                f,
                "section '{section}' changed - it cannot be hot-reloaded; restart to apply"
            ),
            ReloadError::Build(e) => write!(f, "building live state failed: {e:#}"),
        }
    }
}

impl ReloadError {
    /// Short, stable label for metrics and the admin audit log
    /// (`rejected` / `load_error` / `build_error`). The success label
    /// (`success`) is emitted directly on the Ok path.
    pub fn result_label(&self) -> &'static str {
        match self {
            ReloadError::ImmutableChanged(_) => "rejected",
            ReloadError::Load(_) => "load_error",
            ReloadError::Build(_) => "build_error",
        }
    }
}

impl std::error::Error for ReloadError {}

/// What a successful reload changed. Returned for logging / the admin response.
#[derive(Debug, Clone, Copy)]
pub struct ReloadOutcome {
    pub routes: usize,
    pub auth_blocks: usize,
}

struct Inner {
    path: PathBuf,
    /// The last successfully-applied config. The baseline the immutable diff
    /// compares a candidate against, so two reloads in a row don't re-reject a
    /// change already absorbed (and so the diff tracks live truth, not boot).
    current: ArcSwap<Config>,
    routing: Arc<SharedRoutingTable>,
    forwarded: Arc<SharedForwardedPolicy>,
    auth: Arc<SharedAuthRegistry>,
    /// How to build the auth registry. Production verifies JWKS TLS; the test
    /// harness injects a skip-verify builder for its self-signed JWKS server.
    build_auth: fn(&Config) -> anyhow::Result<AuthRegistry>,
}

/// Cheap-to-clone handle to the live, hot-swappable proxy state plus the config
/// path. Held by the SIGHUP task and the admin listener; both call
/// [`reload`](Self::reload).
#[derive(Clone)]
pub struct ReloadHandle {
    inner: Arc<Inner>,
}

impl ReloadHandle {
    /// Build a handle. `initial` is the config the process started with; the
    /// shared handles must be the *same* `Arc`s the proxy listener serves from,
    /// so a swap is observed by in-flight connections.
    pub fn new(
        path: PathBuf,
        initial: Arc<Config>,
        routing: Arc<SharedRoutingTable>,
        forwarded: Arc<SharedForwardedPolicy>,
        auth: Arc<SharedAuthRegistry>,
    ) -> Self {
        Self::with_auth_builder(
            path,
            initial,
            routing,
            forwarded,
            auth,
            AuthRegistry::from_config,
        )
    }

    /// Test-only: like [`new`](Self::new) but builds auth validators with JWKS
    /// certificate verification disabled, matching the integration harness.
    #[doc(hidden)]
    pub fn new_for_tests(
        path: PathBuf,
        initial: Arc<Config>,
        routing: Arc<SharedRoutingTable>,
        forwarded: Arc<SharedForwardedPolicy>,
        auth: Arc<SharedAuthRegistry>,
    ) -> Self {
        Self::with_auth_builder(
            path,
            initial,
            routing,
            forwarded,
            auth,
            AuthRegistry::from_config_for_tests,
        )
    }

    fn with_auth_builder(
        path: PathBuf,
        initial: Arc<Config>,
        routing: Arc<SharedRoutingTable>,
        forwarded: Arc<SharedForwardedPolicy>,
        auth: Arc<SharedAuthRegistry>,
        build_auth: fn(&Config) -> anyhow::Result<AuthRegistry>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                path,
                current: ArcSwap::from(initial),
                routing,
                forwarded,
                auth,
                build_auth,
            }),
        }
    }

    /// The config file this handle reloads from.
    pub fn path(&self) -> &std::path::Path {
        &self.inner.path
    }

    /// Re-read the config file and apply it, or fail leaving the running config
    /// untouched. Emits the `quik_config_reloads_total{result}` counter on
    /// every call and, on success, sets `quik_config_last_reload_timestamp_seconds`.
    pub fn reload(&self) -> Result<ReloadOutcome, ReloadError> {
        match self.reload_inner() {
            Ok(outcome) => {
                metrics::counter!("quik_config_reloads_total", "result" => "success").increment(1);
                if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
                    metrics::gauge!("quik_config_last_reload_timestamp_seconds")
                        .set(now.as_secs_f64());
                }
                tracing::info!(
                    routes = outcome.routes,
                    auth_blocks = outcome.auth_blocks,
                    path = %self.inner.path.display(),
                    "config reloaded"
                );
                Ok(outcome)
            }
            Err(e) => {
                metrics::counter!("quik_config_reloads_total", "result" => e.result_label())
                    .increment(1);
                tracing::warn!(error = %e, path = %self.inner.path.display(), "config reload failed");
                Err(e)
            }
        }
    }

    fn reload_inner(&self) -> Result<ReloadOutcome, ReloadError> {
        let new_cfg = config::load(&self.inner.path).map_err(ReloadError::Load)?;

        // Reject before mutating anything if a non-reloadable section changed.
        let current = self.inner.current.load();
        if let Some(section) = config::immutable_change(&current, &new_cfg) {
            return Err(ReloadError::ImmutableChanged(section));
        }
        drop(current);

        // Build every new piece up front. If any build fails we return without
        // having swapped anything, so the running config stays whole.
        let new_routing = RoutingTable::from_routes(&new_cfg.routes).map_err(ReloadError::Build)?;
        let new_forwarded = ForwardedPolicy::from_config(&new_cfg.forwarded);
        let new_auth = (self.inner.build_auth)(&new_cfg).map_err(ReloadError::Build)?;

        let outcome = ReloadOutcome {
            routes: new_cfg.routes.len(),
            auth_blocks: new_cfg.auth.len(),
        };

        // Swap the live handles. Each flips atomically and is lock-free for
        // readers. The three are NOT swapped as one transaction: a request that
        // crosses this boundary may read the new routing table but the old
        // forwarding policy, etc. That's benign here - these sections have no
        // cross-invariants, and each is read at a distinct point in the request
        // (route match, then auth, then forwarding), each individually consistent.
        self.inner.routing.swap(new_routing);
        self.inner.forwarded.swap(new_forwarded);
        self.inner.auth.swap(new_auth);
        self.inner.current.store(Arc::new(new_cfg));

        Ok(outcome)
    }
}

/// Spawn a task that reloads the config on every `SIGHUP`. Unix-only; the
/// signal is the conventional "re-read your config" nudge (`kill -HUP <pid>`).
/// Reload failures are logged and counted, never fatal - a bad edit leaves the
/// proxy serving the previous good config.
pub fn install_sighup_handler(handle: ReloadHandle) {
    tokio::spawn(async move {
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGHUP handler - config reload via signal disabled");
                return;
            }
        };
        while sighup.recv().await.is_some() {
            tracing::info!("received SIGHUP, reloading config");
            // Errors are already logged + counted inside reload().
            let _ = handle.reload();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A unique scratch directory under the system temp dir, removed on drop.
    /// Avoids pulling in a temp-file dev-dependency for a handful of tests.
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("quik-reload-test-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const BASE: &str = r#"
mode = "edge"

[listener]
bind = "127.0.0.1:8443"
[listener.tls]
cert_path = "tls/cert.pem"
key_path = "tls/key.pem"

[admin]
bind = "127.0.0.1:9090"

[[upstreams]]
name = "api"
members = [{ address = "127.0.0.1:8080", scheme = "http" }]

[[routes]]
path_prefix = "/"
upstream = "api"
"#;

    fn write_cfg(dir: &std::path::Path, body: &str) -> PathBuf {
        let path = dir.join("quik.toml");
        std::fs::write(&path, body).unwrap();
        path
    }

    fn handle_for(path: PathBuf) -> ReloadHandle {
        let initial = Arc::new(config::load(&path).unwrap());
        let routing = Arc::new(SharedRoutingTable::from_config(&initial).unwrap());
        let forwarded = Arc::new(SharedForwardedPolicy::from_config(&initial.forwarded));
        let auth = Arc::new(SharedAuthRegistry::from_config_for_tests(&initial).unwrap());
        ReloadHandle::new_for_tests(path, initial, routing, forwarded, auth)
    }

    #[test]
    fn reload_applies_new_route() {
        let dir = TmpDir::new();
        let path = write_cfg(dir.path(), BASE);
        let h = handle_for(path.clone());

        // Baseline: only "/" matches.
        assert!(
            h.inner
                .routing
                .load()
                .match_request(Some("h"), &http::Method::GET, "/new")
                .is_some()
        );

        // Add a more-specific exact route and reload.
        let updated = format!(
            "{BASE}\n[[routes]]\npath_exact = \"/special\"\nupstream = \"api\"\nstrip_prefix = \"/special\"\n"
        );
        std::fs::write(&path, updated).unwrap();
        let outcome = h.reload().expect("reload should succeed");
        assert_eq!(outcome.routes, 2);

        let table = h.inner.routing.load();
        let route = table
            .match_request(Some("h"), &http::Method::GET, "/special")
            .expect("new exact route present");
        assert_eq!(route.modules.strip_prefix.as_deref(), Some("/special"));
    }

    #[test]
    fn reload_applies_forwarded_change() {
        let dir = TmpDir::new();
        let path = write_cfg(dir.path(), BASE);
        let h = handle_for(path.clone());
        assert!(!h.inner.forwarded.load().emit);

        let updated =
            format!("{BASE}\n[forwarded]\nemit = true\ntrusted_proxies = [\"10.0.0.0/8\"]\n");
        std::fs::write(&path, updated).unwrap();
        h.reload().expect("reload should succeed");
        assert!(h.inner.forwarded.load().emit);
    }

    #[test]
    fn reload_rejects_listener_change() {
        let dir = TmpDir::new();
        let path = write_cfg(dir.path(), BASE);
        let h = handle_for(path.clone());

        let updated = BASE.replace("127.0.0.1:8443", "127.0.0.1:8444");
        std::fs::write(&path, updated).unwrap();
        match h.reload() {
            Err(ReloadError::ImmutableChanged("listener")) => {}
            other => panic!("expected listener rejection, got {other:?}"),
        }
    }

    #[test]
    fn reload_rejects_pool_shape_change() {
        let dir = TmpDir::new();
        let path = write_cfg(dir.path(), BASE);
        let h = handle_for(path.clone());

        // Changing the balancer is a pool-shape change, not a member change.
        let updated = BASE.replace(
            "name = \"api\"",
            "name = \"api\"\nbalancer = \"least_connections\"",
        );
        std::fs::write(&path, updated).unwrap();
        match h.reload() {
            Err(ReloadError::ImmutableChanged("upstreams")) => {}
            other => panic!("expected upstreams rejection, got {other:?}"),
        }
    }

    #[test]
    fn member_change_is_not_a_rejection() {
        // Members are admin-API-managed: editing them in the file neither
        // rejects the reload nor is applied by it. The reload should succeed
        // (the route/auth/forwarded sections are what actually reload).
        let dir = TmpDir::new();
        let path = write_cfg(dir.path(), BASE);
        let h = handle_for(path.clone());

        let updated = BASE.replace(
            "{ address = \"127.0.0.1:8080\", scheme = \"http\" }",
            "{ address = \"127.0.0.1:8080\", scheme = \"http\" }, { address = \"127.0.0.1:8081\", scheme = \"http\" }",
        );
        std::fs::write(&path, updated).unwrap();
        h.reload().expect("member-only edit should not be rejected");
    }

    #[test]
    fn bad_config_is_rejected_and_state_preserved() {
        let dir = TmpDir::new();
        let path = write_cfg(dir.path(), BASE);
        let h = handle_for(path.clone());

        // Route references a pool that doesn't exist -> validation failure.
        let updated = format!("{BASE}\n[[routes]]\npath_prefix = \"/x\"\nupstream = \"ghost\"\n");
        std::fs::write(&path, updated).unwrap();
        assert!(matches!(h.reload(), Err(ReloadError::Load(_))));

        // Original single route still serves.
        assert!(
            h.inner
                .routing
                .load()
                .match_request(Some("h"), &http::Method::GET, "/")
                .is_some()
        );
    }
}

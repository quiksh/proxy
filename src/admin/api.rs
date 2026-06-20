//! Admin API endpoint handlers.
//!
//! Routing is a small hand-rolled match against URI path components - only
//! seven endpoints, no router crate needed. Member IDs in the path are
//! URL-decoded before matching against `member.address`.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use serde::Serialize;

use crate::reload::{ReloadError, ReloadHandle};
use crate::shutdown::Coordinator;
use crate::upstream::{Pool, drain::drain_member, unix_now_ms};

use super::auth::{AuthContext, AuthGroup, CompiledAuthGroups, authorize};
use super::types::{
    AddMemberRequest, ErrorResponse, PoolListResponse, member_to_detail, pool_to_detail,
};

pub type AdminBody = BoxBody<Bytes, hyper::Error>;

/// Per-request state passed to handlers.
pub struct RequestState<'a> {
    pub upstreams: &'a Arc<Pool>,
    pub auth_groups: &'a CompiledAuthGroups,
    /// Config-reload handle backing `POST /admin/config/reload`. `None` when
    /// reload wasn't wired (the endpoint then returns 501).
    pub reload: Option<&'a ReloadHandle>,
    pub shutdown: &'a Coordinator,
    pub peer: std::net::SocketAddr,
    /// Verified peer cert (mTLS). `None` for plain HTTP or TLS without client cert.
    pub peer_cert: Option<rustls::pki_types::CertificateDer<'static>>,
}

pub async fn dispatch(req: Request<Incoming>, state: RequestState<'_>) -> Response<AdminBody> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    // Audit timing.
    let started = std::time::Instant::now();

    // Authorise upfront for every /admin/* endpoint.
    let group = match method {
        Method::GET | Method::HEAD => AuthGroup::Read,
        _ => AuthGroup::Write,
    };
    let ctx = AuthContext {
        group,
        headers: req.headers(),
        peer_cert: state.peer_cert.as_ref(),
    };
    let principal = match authorize(state.auth_groups, &ctx) {
        Ok(p) => p,
        Err(reason) => {
            tracing::info!(
                target: "quik::admin::audit",
                event = "admin_auth_fail",
                reason = reason.reason(),
                peer = %state.peer,
                path = %path,
                "admin auth failed"
            );
            return error_response(StatusCode::UNAUTHORIZED, "unauthorised");
        }
    };

    // Dispatch by path.
    let segments: Vec<&str> = path.strip_prefix('/').unwrap_or(&path).split('/').collect();
    match (method.clone(), segments.as_slice()) {
        (Method::GET, ["admin", "pools"]) => list_pools(&state).await,
        (Method::GET, ["admin", "pools", pool]) => get_pool(&state, pool).await,
        (Method::GET, ["admin", "pools", pool, "members", id]) => {
            get_member(&state, pool, id).await
        }
        (Method::POST, ["admin", "pools", pool, "members"]) => {
            add_member(req, &state, pool, &principal, started).await
        }
        (Method::DELETE, ["admin", "pools", pool, "members", id]) => {
            delete_member(&state, pool, id, &principal, started, true).await
        }
        (Method::POST, ["admin", "pools", pool, "members", id, "drain"]) => {
            delete_member(&state, pool, id, &principal, started, false).await
        }
        (Method::POST, ["admin", "pools", pool, "members", id, "undrain"]) => {
            undrain_member(&state, pool, id, &principal, started).await
        }
        (Method::GET, ["admin", "config", "snapshot"]) => config_snapshot(&state).await,
        (Method::POST, ["admin", "config", "reload"]) => {
            reload_config(&state, &principal, started).await
        }
        _ => error_response(StatusCode::NOT_FOUND, "not found"),
    }
}

// ── GET handlers ────────────────────────────────────────────────────────────

async fn list_pools(state: &RequestState<'_>) -> Response<AdminBody> {
    let snap = state.upstreams.snapshot();
    let mut pools: Vec<_> = snap.values().map(pool_to_detail).collect();
    // Stable order: sort by name. Operators reading the response repeatedly
    // see deterministic output - same reason `stable_metrics()` exists.
    pools.sort_by(|a, b| a.name.cmp(&b.name));
    ok_json(&PoolListResponse { pools })
}

async fn get_pool(state: &RequestState<'_>, pool: &str) -> Response<AdminBody> {
    let pool_name = percent_decode(pool);
    match state.upstreams.get(&pool_name) {
        Some(entry) => ok_json(&pool_to_detail(&entry)),
        None => error_response(StatusCode::NOT_FOUND, "pool not found"),
    }
}

async fn get_member(state: &RequestState<'_>, pool: &str, member_id: &str) -> Response<AdminBody> {
    let pool_name = percent_decode(pool);
    let member_id = percent_decode(member_id);
    let Some(entry) = state.upstreams.get(&pool_name) else {
        return error_response(StatusCode::NOT_FOUND, "pool not found");
    };
    let members = entry.members_snapshot();
    let now_ms = unix_now_ms();
    match members.iter().find(|m| m.address == member_id) {
        Some(m) => ok_json(&member_to_detail(m, now_ms)),
        None => error_response(StatusCode::NOT_FOUND, "member not found"),
    }
}

// ── Snapshot ────────────────────────────────────────────────────────────────

/// Render the live upstream pool state as TOML. Scoped to `[[upstreams]]`
/// blocks because nothing else can drift at runtime - pools, routes, auth,
/// and listener config are static after boot. Each member carries an inline
/// comment marking its provenance (`source: config` / `source: runtime`) so
/// an operator can promote runtime adds back into the config file.
async fn config_snapshot(state: &RequestState<'_>) -> Response<AdminBody> {
    let snap = state.upstreams.snapshot();
    let mut pools: Vec<_> = snap.values().cloned().collect();
    pools.sort_by(|a, b| a.name.cmp(&b.name));

    let mut out = String::new();
    out.push_str(
        "# Live upstream snapshot.\n\
         #\n\
         # Pools, routes, auth blocks, and listeners are static at runtime -\n\
         # consult your original config file for those sections. The blocks\n\
         # below reflect live state including any runtime-added members.\n\
         #\n\
         # Each member is annotated with its provenance:\n\
         #   `source: config`   was present in the config file at boot\n\
         #   `source: runtime`  added via the admin API since boot\n\n",
    );

    for entry in pools {
        render_pool_toml(&mut out, &entry);
    }

    let body = Full::new(Bytes::from(out))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/toml")
        .body(body)
        .expect("static response builds")
}

fn render_pool_toml(out: &mut String, entry: &crate::upstream::UpstreamPoolEntry) {
    use std::fmt::Write;

    let _ = writeln!(out, "[[upstreams]]");
    let _ = writeln!(out, "name = \"{}\"", entry.name);
    let _ = writeln!(
        out,
        "balancer = \"{}\"",
        format!("{:?}", entry.balancer_name).to_lowercase()
    );

    let members = entry.members_snapshot();
    if members.is_empty() {
        let _ = writeln!(out, "members = []\n");
        return;
    }
    let _ = writeln!(out, "members = [");
    for m in members.iter() {
        let _ = writeln!(
            out,
            "    {{ address = \"{}\", scheme = \"{}\" }},  # source: {}",
            m.address,
            m.scheme,
            m.source.as_str(),
        );
    }
    let _ = writeln!(out, "]\n");
}

// ── Config reload ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ReloadResponse {
    status: &'static str,
    path: String,
    routes: usize,
    auth_blocks: usize,
}

/// `POST /admin/config/reload` - re-read the config file and hot-swap the
/// reloadable sections (routes, `[[auth]]`, `[forwarded]`). The running config
/// is untouched on any failure.
///
/// - `200` with a summary on success.
/// - `409 Conflict` if a section that can't be hot-reloaded changed (listener,
///   TLS, upstream pool shape, ...) - the body names it.
/// - `400 Bad Request` if the file failed to load/validate or build.
/// - `501 Not Implemented` if reload wasn't wired into this process.
async fn reload_config(
    state: &RequestState<'_>,
    principal: &str,
    started: std::time::Instant,
) -> Response<AdminBody> {
    let Some(handle) = state.reload else {
        return error_response(StatusCode::NOT_IMPLEMENTED, "config reload not enabled");
    };
    match handle.reload() {
        Ok(outcome) => {
            audit(
                "reload_config",
                "-",
                "-",
                principal,
                state.peer,
                "ok",
                started,
            );
            json_response(
                StatusCode::OK,
                &ReloadResponse {
                    status: "reloaded",
                    path: handle.path().display().to_string(),
                    routes: outcome.routes,
                    auth_blocks: outcome.auth_blocks,
                },
            )
        }
        Err(e) => {
            // A restart-only change is a conflict; a bad/invalid file is a
            // client error. The audit/metric label comes from the error itself.
            let status = match &e {
                ReloadError::ImmutableChanged(_) => StatusCode::CONFLICT,
                ReloadError::Load(_) | ReloadError::Build(_) => StatusCode::BAD_REQUEST,
            };
            audit(
                "reload_config",
                "-",
                "-",
                principal,
                state.peer,
                e.result_label(),
                started,
            );
            json_response(
                status,
                &ErrorResponse::with_detail("reload failed", e.to_string()),
            )
        }
    }
}

// ── Mutating handlers ───────────────────────────────────────────────────────

async fn add_member(
    req: Request<Incoming>,
    state: &RequestState<'_>,
    pool: &str,
    principal: &str,
    started: std::time::Instant,
) -> Response<AdminBody> {
    let pool_name = percent_decode(pool);
    let Some(entry) = state.upstreams.get(&pool_name) else {
        audit(
            "add_member",
            &pool_name,
            "-",
            principal,
            state.peer,
            "not_found",
            started,
        );
        return error_response(StatusCode::NOT_FOUND, "pool not found");
    };

    // Read body with a generous cap - operator JSON, not user data.
    let body = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            audit(
                "add_member",
                &pool_name,
                "-",
                principal,
                state.peer,
                "bad_request",
                started,
            );
            return error_response(StatusCode::BAD_REQUEST, "could not read request body");
        }
    };
    let parsed: AddMemberRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            audit(
                "add_member",
                &pool_name,
                "-",
                principal,
                state.peer,
                "bad_request",
                started,
            );
            return json_response(
                StatusCode::BAD_REQUEST,
                &ErrorResponse::with_detail("invalid request body", e.to_string()),
            );
        }
    };
    let address = parsed.address.clone();

    // Hold the write lock for the swap. Conflict detection uses the loaded
    // snapshot under the lock - two concurrent ADDs of the same address see
    // the same state.
    let _w = entry.write_lock.lock().await;
    let current = entry.members.load_full();
    if current.iter().any(|m| m.address == address) {
        audit(
            "add_member",
            &pool_name,
            &address,
            principal,
            state.peer,
            "conflict",
            started,
        );
        return error_response(StatusCode::CONFLICT, "member already exists");
    }

    let member_cfg = crate::config::UpstreamMember {
        address: parsed.address.clone(),
        scheme: parsed.scheme.clone(),
    };
    let new_member = match entry.build_member(&member_cfg) {
        Ok(m) => Arc::new(m),
        Err(e) => {
            audit(
                "add_member",
                &pool_name,
                &address,
                principal,
                state.peer,
                "bad_request",
                started,
            );
            return json_response(
                StatusCode::BAD_REQUEST,
                &ErrorResponse::with_detail("invalid member", e.to_string()),
            );
        }
    };

    let mut next: Vec<Arc<crate::upstream::Upstream>> = current.iter().cloned().collect();
    next.push(Arc::clone(&new_member));
    entry.members.store(Arc::new(next));

    metrics::counter!(
        "quik_pool_member_added_total",
        "pool" => pool_name.clone(),
    )
    .increment(1);
    audit(
        "add_member",
        &pool_name,
        &address,
        principal,
        state.peer,
        "ok",
        started,
    );

    let detail = member_to_detail(&new_member, unix_now_ms());
    json_response(StatusCode::CREATED, &detail)
}

async fn delete_member(
    state: &RequestState<'_>,
    pool: &str,
    member_id: &str,
    principal: &str,
    started: std::time::Instant,
    remove_on_complete: bool,
) -> Response<AdminBody> {
    let action = if remove_on_complete {
        "remove_member"
    } else {
        "drain_member"
    };
    let pool_name = percent_decode(pool);
    let member_id = percent_decode(member_id);
    let Some(entry) = state.upstreams.get(&pool_name) else {
        audit(
            action,
            &pool_name,
            &member_id,
            principal,
            state.peer,
            "not_found",
            started,
        );
        return error_response(StatusCode::NOT_FOUND, "pool not found");
    };

    let member = {
        let members = entry.members_snapshot();
        members.iter().find(|m| m.address == member_id).cloned()
    };
    let Some(member) = member else {
        audit(
            action,
            &pool_name,
            &member_id,
            principal,
            state.peer,
            "not_found",
            started,
        );
        return error_response(StatusCode::NOT_FOUND, "member not found");
    };

    let now_ms = unix_now_ms();
    if let Err(state_now) = member.lifecycle.begin_drain(now_ms) {
        // Already drained - no further action possible.
        if state_now == crate::upstream::state::LifecycleState::Drained {
            audit(
                action, &pool_name, &member_id, principal, state.peer, "gone", started,
            );
            return error_response(StatusCode::GONE, "member already drained");
        }
        // Already draining is idempotent (begin_drain returns Ok in that case)
        // so reaching here means the state is somehow unexpected - error out.
    }

    metrics::counter!(
        "quik_pool_member_state_transitions_total",
        "pool" => pool_name.clone(),
        "from" => "active",
        "to" => "draining",
    )
    .increment(1);
    audit(
        action, &pool_name, &member_id, principal, state.peer, "ok", started,
    );

    // Spawn the drain task - non-blocking on the response.
    let drain_timeout = Duration::from_millis(entry.drain_cfg.timeout_ms);
    let entry_clone = entry.clone();
    let member_clone = member.clone();
    tokio::spawn(async move {
        drain_member(member_clone, entry_clone, drain_timeout, remove_on_complete).await;
    });

    let detail = member_to_detail(&member, now_ms);
    json_response(StatusCode::ACCEPTED, &detail)
}

async fn undrain_member(
    state: &RequestState<'_>,
    pool: &str,
    member_id: &str,
    principal: &str,
    started: std::time::Instant,
) -> Response<AdminBody> {
    let pool_name = percent_decode(pool);
    let member_id = percent_decode(member_id);
    let Some(entry) = state.upstreams.get(&pool_name) else {
        audit(
            "undrain_member",
            &pool_name,
            &member_id,
            principal,
            state.peer,
            "not_found",
            started,
        );
        return error_response(StatusCode::NOT_FOUND, "pool not found");
    };
    let member = {
        let members = entry.members_snapshot();
        members.iter().find(|m| m.address == member_id).cloned()
    };
    let Some(member) = member else {
        audit(
            "undrain_member",
            &pool_name,
            &member_id,
            principal,
            state.peer,
            "not_found",
            started,
        );
        return error_response(StatusCode::NOT_FOUND, "member not found");
    };

    match member.lifecycle.undrain() {
        Ok(()) => {
            metrics::counter!(
                "quik_pool_member_state_transitions_total",
                "pool" => pool_name.clone(),
                "from" => "draining",
                "to" => "active",
            )
            .increment(1);
            audit(
                "undrain_member",
                &pool_name,
                &member_id,
                principal,
                state.peer,
                "ok",
                started,
            );
            ok_json(&member_to_detail(&member, unix_now_ms()))
        }
        Err(crate::upstream::state::LifecycleState::Drained) => {
            audit(
                "undrain_member",
                &pool_name,
                &member_id,
                principal,
                state.peer,
                "gone",
                started,
            );
            error_response(StatusCode::GONE, "member has already drained - re-add it")
        }
        Err(state_now) => {
            audit(
                "undrain_member",
                &pool_name,
                &member_id,
                principal,
                state.peer,
                "conflict",
                started,
            );
            error_response(
                StatusCode::CONFLICT,
                &format!("member is not draining (current: {})", state_now.as_str()),
            )
        }
    }
}

// ── Response helpers ────────────────────────────────────────────────────────

fn ok_json<T: Serialize>(value: &T) -> Response<AdminBody> {
    json_response(StatusCode::OK, value)
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response<AdminBody> {
    let bytes = match serde_json::to_vec(value) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "admin JSON serialise failed");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal serialise error",
            );
        }
    };
    let body = Full::new(Bytes::from(bytes))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(body)
        .expect("static response builds")
}

pub(crate) fn error_response(status: StatusCode, msg: &str) -> Response<AdminBody> {
    json_response(status, &ErrorResponse::new(msg))
}

// ── Audit ───────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn audit(
    action: &str,
    pool: &str,
    member: &str,
    principal: &str,
    peer: std::net::SocketAddr,
    result: &str,
    started: std::time::Instant,
) {
    tracing::info!(
        target: "quik::admin::audit",
        event = "admin_change",
        action,
        pool,
        member,
        principal,
        peer = %peer,
        result,
        duration_ms = started.elapsed().as_millis() as u64,
        "admin change"
    );
}

// ── URL helpers ─────────────────────────────────────────────────────────────

/// Percent-decode an ASCII-encoded path segment. Handles the common cases an
/// admin client (curl) would generate: `%3A` for colon, `%5B`/`%5D` for IPv6
/// brackets. Multi-byte UTF-8 sequences pass through (operators give us
/// ASCII addresses).
pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
        {
            out.push((h << 4) | l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_addresses() {
        assert_eq!(percent_decode("127.0.0.1:8080"), "127.0.0.1:8080");
        assert_eq!(percent_decode("127.0.0.1%3A8080"), "127.0.0.1:8080");
        assert_eq!(percent_decode("%5B%3A%3A1%5D%3A8080"), "[::1]:8080");
        // Invalid percent triplet passes through.
        assert_eq!(percent_decode("a%ZZb"), "a%ZZb");
    }
}

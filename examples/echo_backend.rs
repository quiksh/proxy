//! Echo backend used by docker-compose and ad-hoc poking at the proxy.
//!
//! Responds to every request with a JSON document describing what the backend
//! saw: method, path, query, version, headers, parsed cookies, peer address,
//! and the request body if it's UTF-8 (truncated past 8 KiB).
//!
//! Environment:
//!   BIND_ADDR     (default: 0.0.0.0:8080)
//!   BACKEND_NAME  (default: echo)

use std::convert::Infallible;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperServer;
use serde_json::{Map, Value, json};
use tokio::net::TcpListener;

const MAX_BODY_ECHO_BYTES: usize = 8 * 1024;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let bind: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()
        .context("parsing BIND_ADDR")?;
    let name = std::env::var("BACKEND_NAME").unwrap_or_else(|_| "echo".to_string());

    let listener = TcpListener::bind(bind).await.context("binding listener")?;
    eprintln!("echo_backend '{name}' listening on {bind}");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let name = name.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: Request<Incoming>| {
                let name = name.clone();
                async move { Ok::<_, Infallible>(handle(req, &name, peer).await) }
            });
            if let Err(e) = HyperServer::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await
            {
                eprintln!("conn error from {peer}: {e}");
            }
        });
    }
}

async fn handle(req: Request<Incoming>, name: &str, peer: SocketAddr) -> Response<Full<Bytes>> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let version = req.version();
    let headers = req.headers().clone();

    let body_bytes = req
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();

    let headers_json: Map<String, Value> = headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                Value::String(v.to_str().unwrap_or("<non-utf8 value>").to_string()),
            )
        })
        .collect();

    let cookies_json = parse_cookies(&headers);

    let body_field: Value = if body_bytes.is_empty() {
        Value::Null
    } else if body_bytes.len() > MAX_BODY_ECHO_BYTES {
        Value::String(format!(
            "<truncated, {} bytes total - only the first {} were considered>",
            body_bytes.len(),
            MAX_BODY_ECHO_BYTES
        ))
    } else {
        match std::str::from_utf8(&body_bytes) {
            Ok(s) => Value::String(s.to_string()),
            Err(_) => Value::String(format!("<non-utf8 body of {} bytes>", body_bytes.len())),
        }
    };

    let response = json!({
        "backend": name,
        "method": method.as_str(),
        "path": uri.path(),
        "query": uri.query(),
        "version": format!("{:?}", version),
        "peer": peer.to_string(),
        "headers": headers_json,
        "cookies": cookies_json,
        "body": body_field,
        "body_bytes": body_bytes.len(),
    });

    let json_str = serde_json::to_string_pretty(&response).expect("serialize response");

    Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .header("x-backend-name", name)
        .body(Full::new(Bytes::from(json_str + "\n")))
        .expect("build response")
}

fn parse_cookies(headers: &http::HeaderMap) -> Map<String, Value> {
    let mut out = Map::new();
    for cookie_value in headers.get_all("cookie").iter() {
        let Ok(s) = cookie_value.to_str() else {
            continue;
        };
        for pair in s.split(';') {
            let Some((k, v)) = pair.trim().split_once('=') else {
                continue;
            };
            out.insert(k.trim().to_string(), Value::String(v.trim().to_string()));
        }
    }
    out
}

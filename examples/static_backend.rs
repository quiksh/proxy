//! Fixed-size static responder for throughput benchmarks: answers every
//! request with the same pre-built body of `BODY_BYTES` bytes, so backend
//! cost is as close to zero as hyper allows and the proxy is what's measured.
//!
//! Environment:
//!   BIND_ADDR   (default: 127.0.0.1:8080)
//!   BODY_BYTES  (default: 1024)
//!   TOKIO_WORKER_THREADS  (default: all cores)

use std::convert::Infallible;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperServer;
use tokio::net::TcpListener;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let bind: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()
        .context("parsing BIND_ADDR")?;
    let size: usize = std::env::var("BODY_BYTES")
        .unwrap_or_else(|_| "1024".into())
        .parse()
        .context("parsing BODY_BYTES")?;
    let body = Bytes::from(vec![b'x'; size]);

    let listener = TcpListener::bind(bind).await.context("binding")?;
    eprintln!("static_backend on {bind}, {size}-byte bodies");
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let _ = stream.set_nodelay(true);
        let body = body.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |_req: Request<Incoming>| {
                let body = body.clone();
                async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header("content-type", "application/octet-stream")
                            .body(Full::new(body))
                            .unwrap(),
                    )
                }
            });
            let _ = HyperServer::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
    }
}

#![warn(rust_2018_idioms)]
#![warn(missing_docs)]
#![allow(dead_code)]

//! Signaling helpers for the WebRTC.rs examples.
//!
//! The examples in this workspace exchange SDP by hand: one side prints a base64 blob, you
//! paste it into the other. This crate holds the few functions that make that work, so the
//! examples can stay focused on the WebRTC parts.
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let json = r#"{"type":"offer","sdp":"v=0\r\n"}"#;
//!
//! // The examples print this blob for you to paste into the other peer.
//! let blob = rtc_signal::encode(json);
//! assert_eq!(rtc_signal::decode(&blob)?, json);
//! # Ok(())
//! # }
//! ```
//!
//! It is a support crate for the examples, not part of the WebRTC API — nothing here is
//! needed to use [`rtc`](https://docs.rs/rtc) or [`webrtc`](https://docs.rs/webrtc).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use self::http::BodyExt;
use anyhow::Result;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use tokio::sync::{Mutex, mpsc};

/// The HTTP plumbing the examples share: an HTTP/1 server loop and a client, on hyper 1.
pub mod http {
    use std::error::Error as StdError;
    use std::net::SocketAddr;

    pub use http_body_util::{BodyExt, Full};
    pub use hyper::body::{Bytes, Incoming};
    use hyper::server::conn::http1;
    use hyper::service::Service;
    use hyper::{Request, Response};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tokio::net::TcpListener;

    /// The body every example response and request carries: the whole thing, in memory.
    pub type Body = Full<Bytes>;

    /// An empty body.
    pub fn empty() -> Body {
        Full::new(Bytes::new())
    }

    /// Serves `service` on `addr` over HTTP/1 until accepting fails, one task per connection.
    pub async fn serve<S>(addr: SocketAddr, service: S) -> std::io::Result<()>
    where
        S: Service<Request<Incoming>, Response = Response<Body>> + Clone + Send + 'static,
        S::Future: Send + 'static,
        S::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        let listener = TcpListener::bind(addr).await?;
        loop {
            let (stream, _) = listener.accept().await?;
            let service = service.clone();
            tokio::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    eprintln!("http connection error: {err}");
                }
            });
        }
    }

    /// Sends `req` and returns the response, its body still to be read.
    pub async fn request(
        req: Request<Body>,
    ) -> Result<Response<Incoming>, hyper_util::client::legacy::Error> {
        Client::builder(TokioExecutor::new())
            .build_http::<Body>()
            .request(req)
            .await
    }

    /// Reads a whole request or response body.
    pub async fn to_bytes(body: Incoming) -> Result<Bytes, hyper::Error> {
        Ok(body.collect().await?.to_bytes())
    }
}

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref SDP_CHAN_TX_MUTEX: Arc<Mutex<Option<mpsc::Sender<String>>>> =
        Arc::new(Mutex::new(None));
}

// HTTP Listener to get sdp
async fn remote_handler(
    req: Request<http::Incoming>,
) -> Result<Response<http::Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        // A HTTP handler that processes a SessionDescription given to us from the other WebRTC-rs or Pion process
        (&Method::POST, "/sdp") => {
            //println!("remote_handler receive from /sdp");
            let sdp_str = match std::str::from_utf8(&req.into_body().collect().await?.to_bytes()) {
                Ok(s) => s.to_owned(),
                Err(err) => panic!("{}", err),
            };

            {
                let sdp_chan_tx = SDP_CHAN_TX_MUTEX.lock().await;
                if let Some(tx) = &*sdp_chan_tx {
                    let _ = tx.send(sdp_str).await;
                }
            }

            let mut response = Response::new(http::empty());
            *response.status_mut() = StatusCode::OK;
            Ok(response)
        }
        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

/// http_sdp_server starts a HTTP Server that consumes SDPs
pub async fn http_sdp_server(port: u16) -> mpsc::Receiver<String> {
    let (sdp_chan_tx, sdp_chan_rx) = mpsc::channel::<String>(1);
    {
        let mut tx = SDP_CHAN_TX_MUTEX.lock().await;
        *tx = Some(sdp_chan_tx);
    }

    tokio::spawn(async move {
        let addr = SocketAddr::from_str(&format!("0.0.0.0:{port}")).unwrap();
        // Run this server for... forever!
        if let Err(e) = http::serve(addr, service_fn(remote_handler)).await {
            eprintln!("server error: {e}");
        }
    });

    sdp_chan_rx
}

/// Note that macOS Terminal may have issue to paste large size of SDP line
/// How to fix it? echo $BROWSER_SDP | ./target/debug/examples/$example
/// must_read_stdin blocks until input is received from stdin
#[allow(clippy::assigning_clones)]
pub fn must_read_stdin() -> Result<String> {
    let mut line = String::new();

    std::io::stdin().read_line(&mut line)?;
    line = line.trim().to_owned();
    println!();

    Ok(line)
}

/// encode encodes the input in base64
/// It can optionally zip the input before encoding
pub fn encode(b: &str) -> String {
    BASE64_STANDARD.encode(b)
}

/// decode decodes the input from base64
/// It can optionally unzip the input after decoding
///
/// Surrounding whitespace is ignored. The examples take this blob either from stdin — where
/// [`must_read_stdin`] has already trimmed it — or from a file named by `--input-sdp-file`, which
/// has not been trimmed by anything. Every text editor writes a trailing newline, so without this
/// the file path fails on a blob that pastes into stdin perfectly well.
pub fn decode(s: &str) -> Result<String> {
    let b = BASE64_STANDARD.decode(s.trim())?;
    let s = String::from_utf8(b)?;
    Ok(s)
}

/// Best-effort discovery of this host's primary local IPv4 address.
///
/// Opens a UDP socket toward a public address and reads back the local address the OS
/// picked — no packet is sent. Falls back to `127.0.0.1` if that fails, which is what the
/// examples want when running offline.
pub fn get_local_ip() -> IpAddr {
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0")
        && socket.connect("8.8.8.8:80").is_ok()
        && let Ok(addr) = socket.local_addr()
        && let IpAddr::V4(ip) = addr.ip()
    {
        ip.into()
    } else {
        Ipv4Addr::new(127, 0, 0, 1).into()
    }
}

//! The reborn of the SOCKS4/5 connector for Hyper library
//!
//! # Example
//! ```
//! use hyper::{client::Client, Body};
//! use hyper_socks2::Proxy;
//!
//! # use hyper_socks2::Error;
//! # fn hidden() -> Result<(), Error> {
//! let proxy = Proxy::Socks5 {
//!     addrs: "your.socks5.proxy:1080",
//!     auth: None,
//! };
//!
//! // with TLS support
//! let proxy = proxy.with_tls()?;
//!
//! let client = Client::builder().build::<_, Body>(proxy);
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//! * `tls` feature enabled by default. It adds TLS support using `hyper-tls`.

use futures::{Async, Future, Poll};
use hyper::client::connect::{Connect, Connected, Destination};
#[cfg(feature = "tls")]
use native_tls::TlsConnector;
use socks::{Socks4Stream, Socks5Stream};
use std::{io, net::ToSocketAddrs};
use tokio::{net::TcpStream, reactor::Handle};

#[cfg(feature = "tls")]
pub use {hyper_tls::HttpsConnector, native_tls::Error};

/// A future with ready TCP stream
pub struct Connection {
    inner: Option<Poll<(TcpStream, Connected), io::Error>>,
}

impl Connection {
    fn result(result: Result<(TcpStream, Connected), io::Error>) -> Self {
        let inner = Some(result.map(Async::Ready));
        Connection { inner }
    }

    fn error(error: io::Error) -> Self {
        Connection::result(Err(error))
    }
}

impl Future for Connection {
    type Item = (TcpStream, Connected);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.inner.take().expect("cannot take Poll twice")
    }
}

/// A SOCKS4/5 proxy information and TCP connector
#[derive(Debug, Clone)]
pub enum Proxy<T: ToSocketAddrs> {
    Socks4 { addrs: T, user_id: String },
    Socks5 { addrs: T, auth: Option<Auth> },
}

/// An authentication information
#[derive(Debug, Clone)]
pub struct Auth {
    pub user: String,
    pub pass: String,
}

impl<T> Proxy<T>
where
    T: ToSocketAddrs,
{
    /// Create a new connector with TLS support
    #[cfg(feature = "tls")]
    pub fn with_tls(self) -> Result<HttpsConnector<Self>, Error> {
        let args = (self, TlsConnector::new()?);
        Ok(HttpsConnector::from(args))
    }
}

impl<T> Connect for Proxy<T>
where
    T: ToSocketAddrs + Send + Sync,
{
    type Transport = TcpStream;
    type Error = io::Error;
    type Future = Connection;

    fn connect(&self, dst: Destination) -> Self::Future {
        let scheme = dst.scheme();
        let port = if let Some(p) = dst.port() {
            p
        } else if scheme == "http" {
            80
        } else if scheme == "https" {
            443
        } else {
            return Connection::error(io::Error::new(io::ErrorKind::InvalidInput, "missing port"));
        };
        let target = (dst.host(), port);

        let res = match self {
            Proxy::Socks4 {
                ref addrs,
                ref user_id,
            } => Socks4Stream::connect(addrs, target, &user_id).map(Socks4Stream::into_inner),
            Proxy::Socks5 {
                ref addrs,
                ref auth,
            } => {
                let res = match auth {
                    Some(auth) => {
                        Socks5Stream::connect_with_password(addrs, target, &auth.user, &auth.pass)
                    }
                    None => Socks5Stream::connect(addrs, target),
                };
                res.map(Socks5Stream::into_inner)
            }
        };
        let res = res
            .and_then(|stream| TcpStream::from_std(stream, &Handle::default()))
            .map(|stream| (stream, Connected::new()));

        Connection::result(res)
    }
}

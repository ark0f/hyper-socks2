//! The Reborn of the SOCKS4/5 connector for Hyper library
//!
//! # Example
//! ```no_run
//! use hyper::{client::Client, Body};
//! use hyper_socks2::{Connector, Proxy};
//!
//! let proxy = Proxy::Socks5 {
//!     addrs: "your.socks5.proxy:1080",
//!     auth: None,
//! };
//! let connector = Connector::new(proxy);
//! let client = Client::builder().build::<_, Body>(connector);
//! ```

use futures::{future, Future, Poll};
use hyper::client::connect::{Connect, Connected, Destination};
use socks::{Socks4Stream, Socks5Stream};
use std::{io, net::ToSocketAddrs};
use tokio::{net::TcpStream, reactor::Handle};

/// A future with ready TCP stream
pub struct Connection(Box<Future<Item = (TcpStream, Connected), Error = io::Error> + Send>);

impl Connection {
    fn new<F>(f: F) -> Self
    where
        F: Future<Item = (TcpStream, Connected), Error = io::Error> + Send + 'static,
    {
        Connection(Box::new(f))
    }
}

impl Future for Connection {
    type Item = (TcpStream, Connected);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

/// A SOCKS4/5 proxy information
#[derive(Debug)]
pub enum Proxy<T: ToSocketAddrs> {
    Socks4 { addrs: T, user_id: String },
    Socks5 { addrs: T, auth: Option<Auth> },
}

/// An authentication information
#[derive(Debug)]
pub struct Auth {
    pub user: String,
    pub pass: String,
}

/// A TCP connector working through proxy
pub struct Connector<T: ToSocketAddrs>(Proxy<T>);

impl<T> Connector<T>
where
    T: ToSocketAddrs,
{
    /// Create a new connector with a given proxy information
    pub fn new(proxy: Proxy<T>) -> Self {
        Connector(proxy)
    }
}

impl<T> Connect for Connector<T>
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
            return Connection::new(future::err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing port",
            )));
        };
        let target = (dst.host(), port);

        let fut = match self.0 {
            Proxy::Socks4 {
                ref addrs,
                ref user_id,
            } => {
                let res = Socks4Stream::connect(addrs, target, user_id.as_str())
                    .map(|stream| stream.into_inner());
                future::result(res)
            }
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
                let res = res.map(|stream| stream.into_inner());
                future::result(res)
            }
        };
        let fut = fut
            .and_then(|stream| TcpStream::from_std(stream, &Handle::default()))
            .map(|stream| (stream, Connected::new()));

        Connection::new(fut)
    }
}

//! A SOCKS5 connector for hyper library
//!
//! # Example
//! ```no_run
//! # use std::error::Error;
//! # fn hidden() -> Result<(), Box<dyn Error>> {
//! use hyper::{client::Client, Body};
//! use hyper_socks2::SocksConnector;
//!
//! let proxy = SocksConnector {
//!     proxy_addr: "your.socks5.proxy:1080",
//!     auth: None,
//! };
//!
//! // with TLS support
//! let proxy = proxy.with_tls()?;
//!
//! let client = Client::builder().build::<_, Body>(proxy);
//!
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//! * `tls` feature is enabled by default. It adds TLS support using `hyper-tls`.

use async_socks5::AddrKind;
use futures::task::{Context, Poll};
use http::uri::Scheme;
use hyper::{service::Service, Uri};
use hyper_tls::HttpsConnector;
use std::{future::Future, io, pin::Pin};
use tokio::net::{TcpStream, ToSocketAddrs};

pub use async_socks5::Auth;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{}", &0)]
    Socks(
        #[from]
        #[source]
        async_socks5::Error,
    ),
    #[error("{}", &0)]
    Io(
        #[from]
        #[source]
        io::Error,
    ),
    #[error("Missing host")]
    MissingHost,
}

/// A future is returned from [`SocksConnector`] service
///
/// [`SocksConnector`]: struct.SocksConnector.html
pub type SocksFuture = Pin<Box<dyn Future<Output = Result<TcpStream, Error>> + Send>>;

/// A SOCKS5 proxy information and TCP connector
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SocksConnector<T> {
    pub proxy_addr: T,
    pub auth: Option<Auth>,
}

impl<T> SocksConnector<T> {
    /// Create a new connector with TLS support
    #[cfg(feature = "tls")]
    pub fn with_tls(self) -> Result<HttpsConnector<Self>, hyper_tls::native_tls::Error> {
        let args = (self, hyper_tls::native_tls::TlsConnector::new()?.into());
        Ok(HttpsConnector::from(args))
    }
}

impl<T> SocksConnector<T>
where
    T: ToSocketAddrs,
{
    async fn call_async(self, target_addr: Uri) -> Result<TcpStream, Error> {
        let host = target_addr
            .host()
            .map(str::to_string)
            .ok_or(Error::MissingHost)?;
        let port =
            target_addr
                .port_u16()
                .unwrap_or(if target_addr.scheme() == Some(&Scheme::HTTPS) {
                    443
                } else {
                    80
                });
        let target_addr = AddrKind::Domain(host, port);

        let mut stream = TcpStream::connect(self.proxy_addr).await?;
        let _ = async_socks5::connect(&mut stream, target_addr, self.auth).await?;
        Ok(stream)
    }
}

impl<T> Service<Uri> for SocksConnector<T>
where
    T: ToSocketAddrs + Clone + Send + Sync + 'static,
{
    type Response = TcpStream;
    type Error = Error;
    type Future = SocksFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { this.call_async(req).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{Body, Client};

    const PROXY_ADDR: &str = "127.0.0.1:1080";
    const PROXY_USERNAME: &str = "hyper";
    const PROXY_PASSWORD: &str = "proxy";
    const HTTP_ADDR: &str = "http://google.com";
    const HTTPS_ADDR: &str = "https://google.com";

    struct Tester {
        uri: Uri,
        auth: Option<Auth>,
        swap_connector: bool,
    }

    impl Tester {
        fn uri(uri: Uri) -> Tester {
            Self {
                uri,
                auth: None,
                swap_connector: false,
            }
        }

        fn http() -> Self {
            Self::uri(Uri::from_static(HTTP_ADDR))
        }

        fn https() -> Self {
            Self::uri(Uri::from_static(HTTPS_ADDR))
        }

        fn with_auth(mut self) -> Self {
            self.auth = Some(Auth {
                username: PROXY_USERNAME.to_string(),
                password: PROXY_PASSWORD.to_string(),
            });
            self
        }

        fn swap_connector(mut self) -> Self {
            self.swap_connector = true;
            self
        }

        async fn test(self) {
            let socks = SocksConnector {
                proxy_addr: PROXY_ADDR,
                auth: self.auth,
            };

            let fut = if (self.uri.scheme() == Some(&Scheme::HTTP)) ^ self.swap_connector {
                Client::builder().build::<_, Body>(socks).get(self.uri)
            } else {
                Client::builder()
                    .build::<_, Body>(socks.with_tls().unwrap())
                    .get(self.uri)
            };
            let _ = fut.await.unwrap();
        }
    }

    #[tokio::test]
    async fn http_no_auth() {
        Tester::http().test().await
    }

    #[tokio::test]
    async fn https_no_auth() {
        Tester::https().test().await
    }

    #[tokio::test]
    async fn http_auth() {
        Tester::http().with_auth().test().await
    }

    #[tokio::test]
    async fn https_auth() {
        Tester::https().with_auth().test().await
    }

    #[tokio::test]
    async fn http_no_auth_swap() {
        Tester::http().swap_connector().test().await
    }

    #[should_panic = "IncompleteMessage"]
    #[tokio::test]
    async fn https_no_auth_swap() {
        Tester::https().swap_connector().test().await
    }

    #[tokio::test]
    async fn http_auth_swap() {
        Tester::http().with_auth().swap_connector().test().await
    }

    #[should_panic = "IncompleteMessage"]
    #[tokio::test]
    async fn https_auth_swap() {
        Tester::https().with_auth().swap_connector().test().await
    }
}

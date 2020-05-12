//! A SOCKS5 connector for hyper library
//!
//! # Example
//! ```no_run
//! # use std::error::Error;
//! # fn hidden() -> Result<(), Box<dyn Error>> {
//! use hyper::{Body, Uri};
//! use hyper::client::{Client, HttpConnector};
//! use hyper_socks2::SocksConnector;
//!
//! let mut connector = HttpConnector::new();
//! connector.enforce_http(false);
//! let proxy = SocksConnector {
//!     proxy_addr: Uri::from_static("socks5://your.socks5.proxy:1080"), // scheme is required by HttpConnector
//!     auth: None,
//!     connector,
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
//! * `rustls` feature adds TLS support using `hyper-rustls`.

#[cfg(all(feature = "tls", feature = "rustls"))]
compile_error!(
    "`tls` and `rustls` features are mutually exclusive. You should enable only one of them"
);

use async_socks5::AddrKind;
use futures::{
    ready,
    task::{Context, Poll},
};
use http::uri::Scheme;
use hyper::{service::Service, Uri};
#[cfg(feature = "rustls")]
use hyper_rustls::HttpsConnector;
#[cfg(feature = "tls")]
use hyper_tls::HttpsConnector;
use std::{future::Future, io, pin::Pin};
use tokio::io::{AsyncRead, AsyncWrite};

pub use async_socks5::Auth;

#[cfg(feature = "tls")]
pub use hyper_tls::native_tls::Error as TlsError;

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
    #[error("{}", &0)]
    Connector(
        #[from]
        #[source]
        BoxedError,
    ),
    #[error("Missing host")]
    MissingHost,
}

/// A future is returned from [`SocksConnector`] service
///
/// [`SocksConnector`]: struct.SocksConnector.html
pub type SocksFuture<R> = Pin<Box<dyn Future<Output = Result<R, Error>> + Send>>;

pub type BoxedError = Box<dyn std::error::Error + Send + Sync>;

/// A SOCKS5 proxy information and TCP connector
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SocksConnector<C> {
    pub proxy_addr: Uri,
    pub auth: Option<Auth>,
    pub connector: C,
}

impl<C> SocksConnector<C> {
    /// Create a new connector with TLS support
    #[cfg(feature = "tls")]
    pub fn with_tls(self) -> Result<HttpsConnector<Self>, TlsError> {
        let args = (self, hyper_tls::native_tls::TlsConnector::new()?.into());
        Ok(HttpsConnector::from(args))
    }

    /// Create a new connector with TLS support
    #[cfg(feature = "rustls")]
    pub fn with_tls(self) -> Result<HttpsConnector<Self>, io::Error> {
        use rusttls::ClientConfig;
        use std::sync::Arc;

        let mut config = ClientConfig::new();
        config.root_store = match rustls_native_certs::load_native_certs() {
            Ok(store) => store,
            Err((_, err)) => return Err(err),
        };

        let config = Arc::new(config);

        let args = (self, config);
        Ok(HttpsConnector::from(args))
    }
}

impl<C> SocksConnector<C>
where
    C: Service<Uri>,
    C::Response: AsyncRead + AsyncWrite + Send + Unpin,
    C::Error: Into<BoxedError>,
{
    async fn call_async(mut self, target_addr: Uri) -> Result<C::Response, Error> {
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

        let mut stream = self
            .connector
            .call(self.proxy_addr)
            .await
            .map_err(Into::<BoxedError>::into)?;
        let _ = async_socks5::connect(&mut stream, target_addr, self.auth).await?;
        Ok(stream)
    }
}

impl<C> Service<Uri> for SocksConnector<C>
where
    C: Service<Uri> + Clone + Send + 'static,
    C::Response: AsyncRead + AsyncWrite + Send + Unpin,
    C::Error: Into<BoxedError>,
    C::Future: Send,
{
    type Response = C::Response;
    type Error = Error;
    type Future = SocksFuture<C::Response>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.connector.poll_ready(cx)).map_err(Into::<BoxedError>::into)?;
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
    use hyper::{client::HttpConnector, Body, Client};

    const PROXY_ADDR: &str = "socks5://127.0.0.1:1080";
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
            let mut connector = HttpConnector::new();
            connector.enforce_http(false);
            let socks = SocksConnector {
                proxy_addr: Uri::from_static(PROXY_ADDR),
                auth: self.auth,
                connector,
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

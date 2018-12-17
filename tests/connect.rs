use futures::future::Future;
use hyper::{client::Client, Body};
use hyper_socks2::{Auth, Connector as SocksConnector, Proxy};
use hyper_tls::HttpsConnector;
use native_tls::TlsConnector;
use tokio::runtime::current_thread::Runtime;

macro_rules! test {
    (
        name: $name:ident,
        proxy: $proxy:tt,
        auth: $auth:expr,
        https: $https:expr,
    ) => {
        #[test]
        fn $name() {
            let addrs = "127.0.0.1:1080";

            let proxy = if $proxy == "socks5" {
                Proxy::Socks5 {
                    addrs,
                    auth: if $auth {
                        Some(Auth {
                            user: "hyper".to_owned(),
                            pass: "proxy".to_owned(),
                        })
                    } else {
                        None
                    },
                }
            } else {
                Proxy::Socks4 {
                    addrs,
                    user_id: String::new(),
                }
            };
            let socks = SocksConnector::new(proxy);
            let tls = TlsConnector::new().unwrap();
            let https = HttpsConnector::from((socks, tls));

            let (scheme, code) = if $https {
                ("https", 200)
            } else {
                ("http", 302)
            };

            let fut = Client::builder()
                .build::<_, Body>(https)
                .get(format!("{}://ya.ru", scheme).parse().unwrap())
                .map(move |resp| {
                    assert_eq!(resp.status(), code);
                });

            Runtime::new().unwrap().block_on(fut).unwrap();
        }
    };
}

test! {
    name: v4_http,
    proxy: "socks4",
    auth: false,
    https: false,
}

test! {
    name: v4_https,
    proxy: "socks4",
    auth: false,
    https: true,
}

test! {
    name: v5_http,
    proxy: "socks5",
    auth: false,
    https: false,
}

test! {
    name: v5_https,
    proxy: "socks5",
    auth: false,
    https: true,
}

test! {
    name: v5_http_auth,
    proxy: "socks5",
    auth: true,
    https: false,
}

test! {
    name: v5_https_auth,
    proxy: "socks5",
    auth: true,
    https: true,
}

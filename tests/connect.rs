use futures::future::Future;
use hyper::{
    client::{connect::Connect, Client},
    Body,
};
use hyper_socks2::{Auth, Connector, Proxy};
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

            let connector = Connector::with_tls(proxy).unwrap();
            let scheme = if $https { "https" } else { "http" };
            let url = format!("{}://google.com", scheme).parse().unwrap()

            let fut = Client::builder()
                .build::<_, Body>(connector)
                .get(url)
                .map(move |resp| {
                    assert!(resp.status().is_success());
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

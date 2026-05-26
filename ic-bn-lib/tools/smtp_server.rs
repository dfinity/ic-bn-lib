use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use ic_bn_lib::{
    smtp::{inbound::SessionConfig, server::Server},
    tests::{TEST_CERT_1, TEST_KEY_2},
    tls::resolver::StubResolver,
};
use rustls::ServerConfig;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let rustls_server_cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(
            StubResolver::new(TEST_CERT_1.as_bytes(), TEST_KEY_2.as_bytes()).unwrap(),
        ));

    let mut cfg = SessionConfig::new("mail.icp.net");
    //cfg.helo_delay = Some(Duration::from_secs(1));
    //params.max_message_size = 16;
    //params.max_session_duration = Duration::from_secs(30);
    //params.max_session_data = 16;
    cfg.tls_mode = ic_bn_lib::smtp::inbound::SessionTlsMode::Allowed(Arc::new(rustls_server_cfg));

    let server = Server::new(SocketAddr::from_str("127.0.0.1:1025").unwrap(), cfg).unwrap();

    server.serve(CancellationToken::new()).await.unwrap();
}

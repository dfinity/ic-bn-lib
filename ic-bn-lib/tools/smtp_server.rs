use std::{net::SocketAddr, str::FromStr, time::Duration};

use ic_bn_lib::smtp::{inbound::SessionConfig, server::Server};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let mut cfg = SessionConfig::new("mail.icp.net");
    //cfg.helo_delay = Some(Duration::from_secs(1));
    //params.max_message_size = 16;
    //params.max_session_duration = Duration::from_secs(30);
    //params.max_session_data = 16;
    cfg.max_errors = 3;

    let server = Server::new(SocketAddr::from_str("127.0.0.1:1025").unwrap(), cfg).unwrap();

    server.serve(CancellationToken::new()).await.unwrap();
}

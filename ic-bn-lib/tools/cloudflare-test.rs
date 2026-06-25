use clap::Parser;
use ic_bn_lib::tls::acme::dns::cloudflare::Cloudflare;

#[derive(Parser)]
pub struct Cli {
    #[clap(env, long)]
    pub zone: String,

    #[clap(env, long)]
    pub token: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let client = Cloudflare::new(
        "https://api.cloudflare.com/".parse().unwrap(),
        cli.token.clone(),
    )
    .unwrap();

    let zone_id = client.find_zone(&cli.zone).await.unwrap();
    println!("Zone {} found with id {zone_id}", cli.zone);

    let records = client
        .find_records(&zone_id, "boundary.dfinity.network")
        .await
        .unwrap();
    println!("Records: {records:?}");
}

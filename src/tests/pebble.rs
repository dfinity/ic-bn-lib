use std::{
    env,
    net::IpAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Error, anyhow};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tempdir::TempDir;
use tokio::fs;

use crate::{
    download_url_async,
    http::dns::{Options, Protocol, Resolver, Resolves},
    tests::{TEST_CERT_1, TEST_KEY_1},
};

const VER: &str = "2.8.0";
const PEBBLE_KEY: &str = "pebble-key.pem";
const PEBBLE_CERT: &str = "pebble-cert.pem";

/// Extracts given file from the .tar.gz archive represented by `targz` Bytes
fn untar(targz: Bytes, file: &str) -> Result<Bytes, Error> {
    let gzip = flate2::read::GzDecoder::new(targz.reader());
    let mut tar = tar::Archive::new(gzip);

    for f in tar.entries().context("unable to get TAR entries")? {
        let mut f = f.context("unable to get file from TAR")?;
        let p = f.path().context("unable to get file path")?;

        if p.file_name()
            .context("unable to get file name")?
            .to_string_lossy()
            == file
        {
            let buf = BytesMut::with_capacity(f.size() as usize);
            let mut writer = buf.writer();
            std::io::copy(&mut f, &mut writer).context("unable to copy file to buffer")?;
            return Ok(writer.into_inner().freeze());
        }
    }

    Err(anyhow!("File not found in the archive"))
}

/// Downloads pebble & pebble-challtestsrv to the given directory, checks hashes & extracts the binaries.
/// If the binaries already exist - then we don't download anything.
pub async fn download(path: &Path) -> Result<(), Error> {
    use anyhow::{Context, anyhow};

    let urls = json!({
        "pebble": {
            "linux": {
                "url": format!("https://github.com/letsencrypt/pebble/releases/download/v{VER}/pebble-linux-amd64.tar.gz"),
                "sha": "34595d915bbc2fc827affb3f58593034824df57e95353b031c8d5185724485ce",
            },
            "macos": {
                "url": format!("https://github.com/letsencrypt/pebble/releases/download/v{VER}/pebble-darwin-arm64.tar.gz"),
                "sha": "39e07d63dc776521f2ffe0584e5f4f081c984ac02742c882b430891d89f0c866",
            }
        },
        "pebble-challtestsrv": {
            "linux": {
                "url": format!("https://github.com/letsencrypt/pebble/releases/download/v{VER}/pebble-challtestsrv-linux-amd64.tar.gz"),
                "sha": "a817449d1f05ae58bcb7bf073b4cebe5d31512f859ba4b83951bd825d28d2114",
            },
            "macos": {
                "url": format!("https://github.com/letsencrypt/pebble/releases/download/v{VER}/pebble-challtestsrv-darwin-arm64.tar.gz"),
                "sha": "1bc5a6cfa062d9756e98d67825daf67f61dd655bcb6025efca2138fe836c9bbc",
            }
        }
    });

    let os = std::env::consts::OS;

    let process = async |name: &str| -> Result<(), Error> {
        let path = path.join(name);

        if fs::try_exists(&path).await? {
            return Ok(());
        }

        // Download the .tar.gz and check hash
        let buf = download_url_async(urls[name][os]["url"].as_str().unwrap())
            .await
            .context(format!("unable to download {name}"))?;
        let hash = Sha256::digest(&buf);
        if hash[..] != hex::decode(urls[name][os]["sha"].as_str().unwrap()).unwrap()[..] {
            return Err(anyhow!("{name} hash mismatch"));
        }

        // Extract the binary & store it
        let binary = untar(buf, name).context(format!("unable to extract {name}"))?;
        fs::write(&path, binary)
            .await
            .context(format!("unable to write {name}"))?;

        // Make executable
        let mut perms = fs::metadata(&path)
            .await
            .context("unable to get perms")?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms)
            .await
            .context("unable to set perms")?;

        Ok(())
    };

    // Download stuff
    process("pebble").await?;
    process("pebble-challtestsrv").await?;

    Ok(())
}

fn stop_process(p: &mut Child) -> ExitStatus {
    let pid = p.id() as i32;
    match kill(Pid::from_raw(pid), Signal::SIGTERM) {
        Ok(_) => println!("Sent SIGTERM to process {pid}"),
        Err(e) => println!("Failed to send SIGTERM: {e}"),
    }
    p.wait().expect("failed to wait on child process")
}

/// Waits until socket becomes connectable
async fn wait_for_server(addr: &str) {
    for i in 0..20 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }

        tokio::time::sleep(Duration::from_millis(i * 100)).await;
    }

    panic!("failed to connect to {addr:?} after 20 tries");
}

/// Generate Pebble config
fn pebble_config(dir: &Path, listen: String) -> String {
    json!({
    "pebble": {
        "listenAddress": listen,
        "managementListenAddress": "",
        "certificate": dir.join(PEBBLE_CERT).to_string_lossy(),
        "privateKey": dir.join(PEBBLE_KEY).to_string_lossy(),
        "httpPort": 0,
        "tlsPort": 0,
        "ocspResponderURL": "",
        "externalAccountBindingRequired": false,
        "domainBlocklist": [],
        "retryAfter": {
            "authz": 3,
            "order": 5
        },
        "profiles": {
            "default": {
                "description": "The profile you know and love",
                "validityPeriod": 7776000
            },
        }
    }})
    .to_string()
}

pub struct DnsOpts {
    pub path: PathBuf,
    pub ip: IpAddr,
    pub port_man: u16,
    pub port_dns: u16,
}

pub struct Dns {
    process: Option<Child>,
    opts: DnsOpts,
}

impl Dns {
    pub async fn new(opts: DnsOpts) -> Self {
        println!("Starting DNS server...");

        // Try to download the binaries if they don't exist
        if !fs::try_exists(&opts.path).await.unwrap() {
            download(opts.path.parent().unwrap())
                .await
                .expect("unable to download binaries");
        }

        let mut cmd = Command::new(&opts.path);
        cmd.arg("-management");
        cmd.arg(format!("{}:{}", opts.ip, opts.port_man));
        cmd.arg("-dns01");
        cmd.arg(format!("{}:{}", opts.ip, opts.port_dns));
        // Disable the rest
        cmd.arg("-doh");
        cmd.arg("");
        cmd.arg("-http01");
        cmd.arg("");
        cmd.arg("-https01");
        cmd.arg("");
        cmd.arg("-tlsalpn01");
        cmd.arg("");

        let process = cmd.spawn().expect("failed to start DNS service");
        wait_for_server(&format!("{}:{}", opts.ip, opts.port_man)).await;

        println!("DNS service started");

        Self {
            process: Some(process),
            opts,
        }
    }
}

pub struct PebbleOpts {
    pub path: PathBuf,
    pub ip: IpAddr,
    pub port_dir: u16,
    pub dns_server: String,
}

pub struct Pebble {
    opts: PebbleOpts,
    process: Option<Child>,
    _dir: TempDir,
}

impl Pebble {
    pub async fn new(opts: PebbleOpts) -> Self {
        println!("Starting Pebble...");

        let dir = TempDir::new("pebble").expect("unable to create temp dir");

        fs::write(
            dir.path().join("pebble.conf"),
            pebble_config(dir.path(), format!("{}:{}", opts.ip, opts.port_dir)),
        )
        .await
        .expect("unable to write Pebble config");

        fs::write(dir.path().join("pebble-cert.pem"), TEST_CERT_1.as_bytes())
            .await
            .expect("unable to write Pebble cert");

        fs::write(dir.path().join("pebble-key.pem"), TEST_KEY_1.as_bytes())
            .await
            .expect("unable to write Pebble key");

        // Try to download the binaries if they don't exist
        if !fs::try_exists(&opts.path).await.unwrap() {
            download(opts.path.parent().unwrap())
                .await
                .expect("unable to download binaries");
        }

        let mut cmd = Command::new(&opts.path);
        cmd.arg("-dnsserver");
        cmd.arg(&opts.dns_server);
        cmd.arg("-config");
        cmd.arg(dir.path().join("pebble.conf"));
        cmd.arg("-strict");

        // Lower rejected nonces chance from 5% to 1% since sometimes
        // even with 3 retries instant-acme hits the badNonce error 3 times in a row
        cmd.env("PEBBLE_WFE_NONCEREJECT", "1");

        let process = cmd.spawn().expect("failed to start Pebble");
        wait_for_server(&format!("{}:{}", opts.ip, opts.port_dir)).await;
        println!("Pebble started");

        Self {
            process: Some(process),
            _dir: dir,
            opts,
        }
    }
}

pub struct Env {
    pub pebble: Pebble,
    pub dns: Dns,
}

impl Env {
    pub async fn new_with_paths(path_pebble: &str, path_dns: &str) -> Self {
        let dns_opts = DnsOpts {
            ip: "127.0.0.1".parse().unwrap(),
            path: path_dns.into(),
            port_dns: 38053,
            port_man: 38055,
        };

        let pebble_opts = PebbleOpts {
            ip: "127.0.0.1".parse().unwrap(),
            path: path_pebble.into(),
            port_dir: 34000,
            dns_server: "127.0.0.1:38053".to_string(),
        };

        let dns = Dns::new(dns_opts).await;
        let pebble = Pebble::new(pebble_opts).await;

        Self { dns, pebble }
    }

    pub async fn new() -> Self {
        let path_pebble = env::var("PEBBLE").unwrap_or_else(|_| "./pebble".to_owned());
        let path_dns =
            env::var("CHALLTESTSRV").unwrap_or_else(|_| "./pebble-challtestsrv".to_owned());

        Self::new_with_paths(&path_pebble, &path_dns).await
    }

    pub const fn port_dns_cleartext(&self) -> u16 {
        self.dns.opts.port_dns
    }

    pub const fn ip_dns_cleartext(&self) -> IpAddr {
        self.dns.opts.ip
    }

    pub fn addr_dns_management(&self) -> String {
        format!("{}:{}", self.dns.opts.ip, self.dns.opts.port_man)
    }

    pub fn addr_acme(&self) -> String {
        format!("{}:{}", self.pebble.opts.ip, self.pebble.opts.port_dir)
    }

    /// Returns a ready-to-use DNS resolver targeting pebble-challtestsrv
    pub fn resolver(&self) -> Arc<dyn Resolves> {
        let mut opts = Options::default();
        opts.protocol = Protocol::Clear(self.port_dns_cleartext());
        opts.servers = vec![self.ip_dns_cleartext()];

        Arc::new(Resolver::new(opts))
    }

    pub fn stop(&mut self) {
        if let Some(mut v) = self.pebble.process.take() {
            println!("Stopping Pebble...");
            println!("Pebble process exited with: {:?}", stop_process(&mut v));
        }

        if let Some(mut v) = self.dns.process.take() {
            println!("Stopping DNS process");
            println!("DNS process exited with: {:?}", stop_process(&mut v));
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[ignore]
    #[tokio::test]
    async fn test_download() {
        let dir = TempDir::new("pebble_download").unwrap();
        download(dir.path()).await.unwrap();
    }
}

pub mod dns {
    use anyhow::{Error, anyhow};
    use async_trait::async_trait;
    use serde_json::json;
    use url::Url;

    use crate::tls::acme::TokenManager;

    #[cfg(feature = "acme_dns")]
    use crate::tls::acme::dns::{DnsManager, Record};

    /// Manages ACME tokens using Pebble Challenge Test Server.
    /// To be used for testing only.
    pub struct TokenManagerPebble {
        cli: reqwest::Client,
        url: Url,
    }

    impl TokenManagerPebble {
        pub fn new(url: Url) -> Self {
            Self {
                cli: reqwest::ClientBuilder::new()
                    .danger_accept_invalid_certs(true)
                    .build()
                    .unwrap(),
                url,
            }
        }
    }

    #[async_trait]
    impl TokenManager for TokenManagerPebble {
        async fn verify(&self, _zone: &str, _token: &str) -> Result<(), Error> {
            // We can't really verify it
            Ok(())
        }

        async fn set(&self, zone: &str, token: &str) -> Result<(), Error> {
            let url = self.url.join("/set-txt").unwrap();
            let body = json!({
                "host" : format!("_acme-challenge.{zone}."),
                "value": token,
            })
            .to_string();

            let res = self.cli.post(url).body(body).send().await?;
            if !res.status().is_success() {
                return Err(anyhow!("Incorrect status code: {}", res.status()));
            }

            Ok(())
        }

        async fn unset(&self, zone: &str) -> Result<(), Error> {
            let url = self.url.join("/clear-txt").unwrap();
            let body = json!({
                "host" : format!("_acme-challenge.{zone}."),
            })
            .to_string();

            let res = self.cli.post(url).body(body).send().await?;
            if !res.status().is_success() {
                return Err(anyhow!("Incorrect status code: {}", res.status()));
            }

            Ok(())
        }
    }

    #[cfg(feature = "acme_dns")]
    #[async_trait]
    impl DnsManager for TokenManagerPebble {
        async fn create(
            &self,
            zone: &str,
            _name: &str,
            record: Record,
            _ttl: u32,
        ) -> Result<(), Error> {
            let Record::Txt(token) = record;
            self.set(zone, &token).await
        }

        async fn delete(&self, zone: &str, _name: &str) -> Result<(), Error> {
            self.unset(zone).await
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use crate::tests::pebble::Env;

        #[ignore]
        #[tokio::test]
        async fn test_token_manager_pebble() {
            let pebble_env = Env::new().await;

            let tm = TokenManagerPebble::new(
                format!("http://{}", pebble_env.addr_dns_management())
                    .parse()
                    .unwrap(),
            );
            let resolver = pebble_env.resolver();

            tm.set("foo", "bar").await.unwrap();
            let r = resolver
                .resolve("_acme-challenge.foo", "TXT")
                .await
                .unwrap();
            assert_eq!(r, vec![("TXT".to_string(), "bar".to_string())]);

            tm.unset("foo").await.unwrap();
            let r = resolver.resolve("_acme-challenge.foo", "TXT").await;
            assert!(r.is_err());

            #[cfg(feature = "acme_dns")]
            {
                tm.create("baz", "txt", Record::Txt("deadbeef".into()), 0)
                    .await
                    .unwrap();
                let r = resolver
                    .resolve("_acme-challenge.baz", "TXT")
                    .await
                    .unwrap();
                assert_eq!(r, vec![("TXT".to_string(), "deadbeef".to_string())]);

                tm.unset("baz").await.unwrap();
                let r = resolver.resolve("_acme-challenge.baz", "TXT").await;
                assert!(r.is_err());
            }
        }
    }
}

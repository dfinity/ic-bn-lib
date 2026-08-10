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
use tempfile::{TempDir, tempdir};
use tokio::fs;

use crate::{
    dns::{
        Options as DnsOptions,
        resolvers::{Resolver, Resolves},
    },
    download_url_async,
    tests::{TEST_CERT_1, TEST_KEY_1},
};

const VER: &str = "2.10.1";
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
                "x86_64": {
                    "url": format!("https://github.com/letsencrypt/pebble/releases/download/v{VER}/pebble-linux-amd64.tar.gz"),
                    "sha": "4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed",
                },
                "aarch64": {
                    "url": format!("https://github.com/letsencrypt/pebble/releases/download/v{VER}/pebble-linux-arm64.tar.gz"),
                    "sha": "b53fd072a69eb7692451de4e8b0667e0bdf5cccd7e36fc51b8eaf2fcc135ed9f",
                }
            },
            "macos": {
                "x86_64": {
                    "url": format!("https://github.com/letsencrypt/pebble/releases/download/v{VER}/pebble-darwin-amd64.tar.gz"),
                    "sha": "e670ff869886022637e077502a62e7f23be693c45a5a6727ebd76da8fdce64dc",
                },
                "aarch64": {
                    "url": format!("https://github.com/letsencrypt/pebble/releases/download/v{VER}/pebble-darwin-arm64.tar.gz"),
                    "sha": "09a3a4e6ebed71e8d83294a26d361232262f45a7488f5de7bccb5887b395217f",
                }
            }
        },
        "pebble-challtestsrv": {
            "linux": {
                "x86_64": {
                    "url": format!("https://github.com/letsencrypt/pebble/releases/download/v{VER}/pebble-challtestsrv-linux-amd64.tar.gz"),
                    "sha": "e93a5aa25ecdf3af2f9fbb2de32b0173e64a2eae81002a4ccfe35fa6f4f60b92",
                },
                "aarch64": {
                    "url": format!("https://github.com/letsencrypt/pebble/releases/download/v{VER}/pebble-challtestsrv-linux-arm64.tar.gz"),
                    "sha": "db8e1a79ccdb2195c489fbe4f40fddb7f30e86f9cd8a07912566ee5025094d6c",
                }
            },
            "macos": {
                "x86_64": {
                    "url": format!("https://github.com/letsencrypt/pebble/releases/download/v{VER}/pebble-challtestsrv-darwin-amd64.tar.gz"),
                    "sha": "796bd923f2c595dd7bf15ae693096abfb1df962cb3673c7981ff306daa5c4a52",
                },
                "aarch64": {
                    "url": format!("https://github.com/letsencrypt/pebble/releases/download/v{VER}/pebble-challtestsrv-darwin-arm64.tar.gz"),
                    "sha": "59bf917fe39c96e2edca980fc2899f4f04aa1ce5485f28d419d18237b902cf82",
                }
            }
        }
    });

    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    let process = async |name: &str| -> Result<(), Error> {
        let path = path.join(name);

        if fs::try_exists(&path).await? {
            return Ok(());
        }

        let url = &urls[name][os][arch];

        // Download the .tar.gz and check hash
        let buf = download_url_async(url["url"].as_str().unwrap())
            .await
            .context(format!("unable to download {name}"))?;
        let hash = Sha256::digest(&buf);
        if hash[..] != hex::decode(url["sha"].as_str().unwrap()).unwrap()[..] {
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
        "httpPort": 5002,
        "tlsPort": 5001,
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

/// DNS options for `Pebble`'s DNS server
pub struct DnsOpts {
    pub path: PathBuf,
    pub ip: IpAddr,
    pub port_man: u16,
    pub port_dns: u16,
}

/// Wrapper to run `Pebble`'s DNS server
pub struct Dns {
    process: Option<Child>,
    opts: DnsOpts,
}

impl Dns {
    /// Create new `Dns`
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
        cmd.arg("-dnsserver");
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

/// Options for `Pebble`
pub struct PebbleOpts {
    pub path: PathBuf,
    pub ip: IpAddr,
    pub port_dir: u16,
    pub dns_server: String,
}

/// Wrapper to run `Pebble`
pub struct Pebble {
    opts: PebbleOpts,
    process: Option<Child>,
    _dir: TempDir,
}

impl Pebble {
    /// Create new `Pebble`
    pub async fn new(opts: PebbleOpts) -> Self {
        println!("Starting Pebble...");

        let dir = tempdir().expect("unable to create temp dir");

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

/// Pebble + DNS environment
pub struct Env {
    pub pebble: Pebble,
    pub dns: Dns,
}

impl Env {
    /// Create new `Env` with paths to the binaries
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

    /// Create new `Env` with paths from env vars
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
        let opts = DnsOptions::simple(&[self.ip_dns_cleartext()], self.port_dns_cleartext());
        Arc::new(Resolver::new(opts).unwrap())
    }

    /// Stops the environment
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
        let dir = tempdir().unwrap();
        download(dir.path()).await.unwrap();
    }
}

pub mod dns {
    use crate::tls::acme::TokenManager;
    use anyhow::{Error, anyhow};
    use async_trait::async_trait;

    #[cfg(feature = "acme-dns")]
    use crate::tls::acme::{Record, dns::DnsManager};
    use serde_json::json;
    use url::Url;

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

        /// pebble-challtestsrv doesn't allow to delete specific TXT record, so we nuke them all
        async fn unset(&self, zone: &str, _token: &str) -> Result<(), Error> {
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

    #[cfg(feature = "acme-dns")]
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

        async fn delete(&self, zone: &str, _name: &str, _record: &Record) -> Result<(), Error> {
            self.unset(zone, "").await
        }
    }

    #[cfg(test)]
    mod test {
        use hickory_proto::rr::RecordType;

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
                .resolve(RecordType::TXT, "_acme-challenge.foo")
                .await
                .unwrap();
            assert_eq!(r[0].record_type(), RecordType::TXT);
            assert_eq!(r[0].data.to_string(), "bar");

            tm.unset("foo", "").await.unwrap();
            let r = resolver
                .resolve(RecordType::TXT, "_acme-challenge.foo")
                .await;
            assert!(r.is_err());

            #[cfg(feature = "acme-dns")]
            {
                tm.create("baz", "txt", Record::Txt("deadbeef".into()), 0)
                    .await
                    .unwrap();
                let r = resolver
                    .resolve(RecordType::TXT, "_acme-challenge.baz")
                    .await
                    .unwrap();
                assert_eq!(r[0].record_type(), RecordType::TXT);
                assert_eq!(r[0].data.to_string(), "deadbeef");

                tm.unset("baz", "").await.unwrap();
                let r = resolver
                    .resolve(RecordType::TXT, "_acme-challenge.baz")
                    .await;
                assert!(r.is_err());
            }
        }
    }
}

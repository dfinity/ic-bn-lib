use std::{
    env, fs,
    net::{IpAddr, TcpStream},
    path::Path,
    process::{Child, Command, ExitStatus},
    sync::Arc,
    thread::sleep,
    time::Duration,
};

use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use serde_json::json;
use tempdir::TempDir;

use crate::{
    http::dns::{Options, Protocol, Resolver, Resolves},
    tests::{TEST_CERT, TEST_KEY},
};

const PEBBLE_KEY: &str = "pebble-key.pem";
const PEBBLE_CERT: &str = "pebble-cert.pem";

fn stop_process(p: &mut Child) -> ExitStatus {
    let pid = p.id() as i32;
    match kill(Pid::from_raw(pid), Signal::SIGTERM) {
        Ok(_) => println!("Sent SIGTERM to process {pid}"),
        Err(e) => println!("Failed to send SIGTERM: {}", e),
    }
    p.wait().expect("failed to wait on child process")
}

/// Waits until socket becomes connectable
fn wait_for_server(addr: &str) {
    for i in 0..20 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }

        sleep(Duration::from_millis(i * 100))
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
    pub path: String,
    pub ip: IpAddr,
    pub port_man: u16,
    pub port_dns: u16,
}

pub struct Dns {
    process: Option<Child>,
    opts: DnsOpts,
}

impl Dns {
    pub fn new(opts: DnsOpts) -> Self {
        println!("Starting DNS server...");

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
        wait_for_server(&format!("{}:{}", opts.ip, opts.port_man));

        println!("DNS service started");

        Self {
            process: Some(process),
            opts,
        }
    }
}

pub struct PebbleOpts {
    pub path: String,
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
    pub fn new(opts: PebbleOpts) -> Self {
        println!("Starting Pebble...");

        let dir = TempDir::new("pebble").expect("unable to create temp dir");

        fs::write(
            dir.path().join("pebble.conf"),
            pebble_config(dir.path(), format!("{}:{}", opts.ip, opts.port_dir)),
        )
        .expect("unable to write Pebble config");

        fs::write(dir.path().join("pebble-cert.pem"), TEST_CERT.as_bytes())
            .expect("unable to write Pebble cert");

        fs::write(dir.path().join("pebble-key.pem"), TEST_KEY.as_bytes())
            .expect("unable to write Pebble key");

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
        wait_for_server(&format!("{}:{}", opts.ip, opts.port_dir));
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

impl Default for Env {
    fn default() -> Self {
        Self::new()
    }
}

impl Env {
    pub fn new_with_paths(path_pebble: &str, path_dns: &str) -> Self {
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

        let dns = Dns::new(dns_opts);
        let pebble = Pebble::new(pebble_opts);

        Self { dns, pebble }
    }

    pub fn new() -> Self {
        let path_pebble = env::var("PEBBLE").unwrap_or_else(|_| "./pebble".to_owned());
        let path_dns =
            env::var("CHALLTESTSRV").unwrap_or_else(|_| "./pebble-challtestsrv".to_owned());

        Self::new_with_paths(&path_pebble, &path_dns)
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
        Arc::new(Resolver::new(Options {
            protocol: Protocol::Clear(self.port_dns_cleartext()),
            servers: vec![self.ip_dns_cleartext()],
            tls_name: "".into(),
            cache_size: 0,
        }))
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

#[cfg(feature = "acme")]
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
            let pebble_env = Env::new();

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

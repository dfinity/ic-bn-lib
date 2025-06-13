use std::{
    env, fs,
    net::TcpStream,
    path::Path,
    process::{Child, Command, ExitStatus},
    thread::sleep,
    time::Duration,
};

use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use serde_json::json;
use tempdir::TempDir;

use crate::tests::{TEST_CERT, TEST_KEY};

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
        "managementListenAddress": "0.0.0.0:15000",
        "certificate": dir.join(PEBBLE_CERT).to_string_lossy(),
        "privateKey": dir.join(PEBBLE_KEY).to_string_lossy(),
        "httpPort": 5002,
        "tlsPort": 5001,
        "ocspResponderURL": "",
        "externalAccountBindingRequired": false,
        "domainBlocklist": ["blocked-domain.example"],
        "retryAfter": {
            "authz": 3,
            "order": 5
        },
        "profiles": {
            "default": {
                "description": "The profile you know and love",
                "validityPeriod": 7776000
            },
            "shortlived": {
                "description": "A short-lived cert profile, without actual enforcement",
                "validityPeriod": 518400
            }
        }
    }})
    .to_string()
}

pub struct DnsOpts {
    pub path: String,
    pub ip: String,
    pub port_man: u16,
    pub port_dns: u16,
}

pub struct Dns {
    process: Child,
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

        let process = cmd.spawn().expect("failed to start DNS service");
        wait_for_server(&format!("{}:{}", opts.ip, opts.port_man));

        println!("DNS service started");

        Self { process, opts }
    }
}

pub struct PebbleOpts {
    pub path: String,
    pub ip: String,
    pub port_dir: u16,
    pub dns_server: String,
}

pub struct Pebble {
    opts: PebbleOpts,
    process: Child,
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

        let process = cmd.spawn().expect("failed to start Pebble");
        wait_for_server(&format!("{}:{}", opts.ip, opts.port_dir));
        println!("Pebble started");

        Self {
            process,
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
            ip: "127.0.0.1".to_string(),
            path: path_dns.into(),
            port_dns: 38053,
            port_man: 38055,
        };

        let pebble_opts = PebbleOpts {
            ip: "127.0.0.1".to_string(),
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

    pub fn addr_dns_management(&self) -> String {
        format!("{}:{}", self.dns.opts.ip, self.dns.opts.port_man)
    }

    pub fn addr_acme(&self) -> String {
        format!("{}:{}", self.pebble.opts.ip, self.pebble.opts.port_dir)
    }

    #[allow(clippy::cognitive_complexity)]
    pub fn stop(&mut self) {
        println!("Stopping Pebble...");
        println!(
            "DNS process exited with: {:?}",
            stop_process(&mut self.pebble.process)
        );

        println!("Stopping DNS process");
        println!(
            "DNS process exited with: {:?}",
            stop_process(&mut self.dns.process)
        );
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        self.stop();
    }
}

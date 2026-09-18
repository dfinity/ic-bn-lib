use std::{net::IpAddr, time::Duration};

use clap::Args;
use humantime::parse_duration;

use crate::dns::{DEFAULT_RESOLVERS, LookupStrategy, Protocol};

/// DNS CLI parameters
#[derive(Args)]
pub struct DnsCli {
    /// List of DNS servers to use
    #[clap(env, long, value_delimiter = ',', default_values_t = DEFAULT_RESOLVERS)]
    pub dns_servers: Vec<IpAddr>,

    /// DNS protocol to use (clear/tls/https) with an optional port separated by a colon.
    /// E.g. "clear:8053". If the port is omitted then the default is used.
    #[clap(env, long, default_value = "clear")]
    pub dns_protocol: Protocol,

    /// Cache size for the resolver (in number of DNS records)
    #[clap(env, long, default_value = "2048")]
    pub dns_cache_size: u64,

    /// Timeout for resolving
    #[clap(env, long, default_value = "5s", value_parser = parse_duration)]
    pub dns_timeout: Duration,

    /// Number of resolving attempts to do
    #[clap(env, long, default_value = "3")]
    pub dns_attempts: usize,

    /// TLS name to expect for TLS and HTTPS protocols (e.g. "dns.google" or "cloudflare-dns.com")
    #[clap(env, long, default_value = "cloudflare-dns.com")]
    pub dns_tls_name: String,

    /// IP Lookup strategy to use. Can be one of `ipv4_only`, `ipv6_only`, `ipv4_and_ipv6`, `ipv4_then_ipv6` or `ipv6_then_ipv4`.
    /// Default is to look up IPv4 and IPv6 in parallel.
    #[clap(env, long, default_value = "ipv4_and_ipv6")]
    pub dns_lookup_strategy: LookupStrategy,

    /// Disable DNSSEC validation for DNS queries (DNSSEC is enabled by default)
    #[clap(env, long)]
    pub dns_dnssec_disabled: bool,
}

#[cfg(test)]
mod test {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        sync::Arc,
    };

    use clap::{CommandFactory, Parser, error::ErrorKind};
    use hickory_resolver::config::{
        LookupIpStrategy, ProtocolConfig, ResolveHosts, ResolverConfig, ResolverOpts,
    };

    use super::*;

    /// `DnsCli` is an `Args` group, so it needs a `Parser` host to be parsed standalone.
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        dns: DnsCli,
    }

    fn try_parse(args: &[&str]) -> Result<DnsCli, clap::Error> {
        let mut argv = vec!["test"];
        argv.extend_from_slice(args);
        Cli::try_parse_from(argv).map(|x| x.dns)
    }

    fn parse(args: &[&str]) -> DnsCli {
        try_parse(args).unwrap()
    }

    #[test]
    fn cli_definition_is_valid() {
        // Catches e.g. a duplicated argument id or a `requires` pointing nowhere
        Cli::command().debug_assert();
    }

    #[test]
    fn defaults() {
        let c = parse(&[]);

        // The CLI default must be exactly the crate's default resolver list
        assert_eq!(c.dns_servers.as_slice(), DEFAULT_RESOLVERS);
        assert_eq!(c.dns_servers.len(), 6);
        assert_eq!(c.dns_servers[0], IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));

        assert_eq!(c.dns_protocol, Protocol::Clear(53));
        assert_eq!(c.dns_cache_size, 2048);
        assert_eq!(c.dns_timeout, Duration::from_secs(5));
        assert_eq!(c.dns_attempts, 3);
        assert_eq!(c.dns_tls_name, "cloudflare-dns.com");
        assert_eq!(c.dns_lookup_strategy, LookupStrategy::Ipv4AndIpv6);
        // Doc comment promises DNSSEC validation is on by default
        assert!(!c.dns_dnssec_disabled);
    }

    #[test]
    fn every_flag_takes_an_explicit_value() {
        // Distinct values everywhere, so a mis-wired flag shows up
        let c = parse(&[
            "--dns-servers=127.0.0.1,::1",
            "--dns-protocol=tls:8853",
            "--dns-cache-size=7",
            "--dns-timeout=1m 30s",
            "--dns-attempts=11",
            "--dns-tls-name=dns.example.com",
            "--dns-lookup-strategy=ipv6_then_ipv4",
            "--dns-dnssec-disabled",
        ]);

        assert_eq!(
            c.dns_servers,
            vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            ]
        );
        assert_eq!(c.dns_protocol, Protocol::Tls(8853));
        assert_eq!(c.dns_cache_size, 7);
        assert_eq!(c.dns_timeout, Duration::from_secs(90));
        assert_eq!(c.dns_attempts, 11);
        assert_eq!(c.dns_tls_name, "dns.example.com");
        assert_eq!(c.dns_lookup_strategy, LookupStrategy::Ipv6ThenIpv4);
        assert!(c.dns_dnssec_disabled);
    }

    #[test]
    fn dns_servers_is_comma_delimited_and_replaces_the_defaults() {
        // A single occurrence is split on commas and wholly replaces the defaults
        let c = parse(&["--dns-servers=127.0.0.1,8.8.4.4,::1"]);
        assert_eq!(
            c.dns_servers,
            vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ]
        );

        // Repeated occurrences accumulate, keeping the given order
        let c = parse(&[
            "--dns-servers",
            "10.0.0.1",
            "--dns-servers",
            "10.0.0.2,10.0.0.3",
        ]);
        assert_eq!(
            c.dns_servers,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            ]
        );
    }

    #[test]
    fn dns_servers_rejects_anything_that_is_not_a_bare_ip() {
        for v in [
            "",
            "not-an-ip",
            "256.1.1.1",
            "1.2.3.4.5",
            "1.2.3.4:53",
            "1.2.3.0/24",
            "localhost",
            "1.2.3.4 ",
        ] {
            assert!(
                try_parse(&[&format!("--dns-servers={v}")]).is_err(),
                "{v:?} should not parse as an IP"
            );
        }

        // One bad entry in an otherwise valid list fails the whole list
        assert!(try_parse(&["--dns-servers=127.0.0.1,nope,::1"]).is_err());
    }

    #[test]
    fn dns_protocol_uses_the_protocol_default_port_when_omitted() {
        assert_eq!(
            parse(&["--dns-protocol=clear"]).dns_protocol,
            Protocol::Clear(53)
        );
        assert_eq!(
            parse(&["--dns-protocol=tls"]).dns_protocol,
            Protocol::Tls(853)
        );
        assert_eq!(
            parse(&["--dns-protocol=https"]).dns_protocol,
            Protocol::Https(443)
        );

        // An explicit port overrides it, including the boundary values
        assert_eq!(
            parse(&["--dns-protocol=clear:8053"]).dns_protocol,
            Protocol::Clear(8053)
        );
        assert_eq!(
            parse(&["--dns-protocol=tls:0"]).dns_protocol,
            Protocol::Tls(0)
        );
        assert_eq!(
            parse(&["--dns-protocol=https:65535"]).dns_protocol,
            Protocol::Https(65535)
        );
    }

    #[test]
    fn dns_protocol_rejects_unknown_protocols_and_bad_ports() {
        for v in [
            "",
            "quic",
            "CLEAR",
            "clear ",
            "clear:",
            "clear:65536",
            "clear:-1",
            "clear:abc",
        ] {
            assert!(
                try_parse(&[&format!("--dns-protocol={v}")]).is_err(),
                "{v:?} should not parse as a protocol"
            );
        }
    }

    #[test]
    fn dns_timeout_is_a_humantime_duration() {
        assert_eq!(parse(&["--dns-timeout=0s"]).dns_timeout, Duration::ZERO);
        assert_eq!(
            parse(&["--dns-timeout=250ms"]).dns_timeout,
            Duration::from_millis(250)
        );
        assert_eq!(
            parse(&["--dns-timeout=1h 30m"]).dns_timeout,
            Duration::from_secs(5400)
        );

        for v in ["", "5", "abc", "-1s", "1h30", "5 sekunden"] {
            assert!(
                try_parse(&[&format!("--dns-timeout={v}")]).is_err(),
                "{v:?} should not parse as a duration"
            );
        }
    }

    #[test]
    fn dns_lookup_strategy_accepts_exactly_the_documented_snake_case_names() {
        for (arg, expected) in [
            ("ipv4_only", LookupStrategy::Ipv4Only),
            ("ipv6_only", LookupStrategy::Ipv6Only),
            ("ipv4_and_ipv6", LookupStrategy::Ipv4AndIpv6),
            ("ipv4_then_ipv6", LookupStrategy::Ipv4ThenIpv6),
            ("ipv6_then_ipv4", LookupStrategy::Ipv6ThenIpv4),
        ] {
            assert_eq!(
                parse(&[&format!("--dns-lookup-strategy={arg}")]).dns_lookup_strategy,
                expected
            );
        }

        // Anything else - including other casings and spellings - is rejected
        for v in [
            "",
            "ipv4",
            "Ipv4Only",
            "IPV4_ONLY",
            "ipv4-only",
            "ipv4_and_ipv6 ",
        ] {
            assert!(
                try_parse(&[&format!("--dns-lookup-strategy={v}")]).is_err(),
                "{v:?} should not parse as a lookup strategy"
            );
        }
    }

    #[test]
    fn numeric_arguments_are_bounded_by_their_types() {
        assert_eq!(parse(&["--dns-cache-size=0"]).dns_cache_size, 0);
        assert_eq!(
            parse(&[&format!("--dns-cache-size={}", u64::MAX)]).dns_cache_size,
            u64::MAX
        );
        assert!(try_parse(&["--dns-cache-size=18446744073709551616"]).is_err());
        assert!(try_parse(&["--dns-cache-size=-1"]).is_err());
        assert!(try_parse(&["--dns-cache-size=2048.0"]).is_err());
        assert!(try_parse(&["--dns-cache-size="]).is_err());

        assert_eq!(parse(&["--dns-attempts=0"]).dns_attempts, 0);
        assert!(try_parse(&["--dns-attempts=-1"]).is_err());
        assert!(try_parse(&["--dns-attempts=abc"]).is_err());
    }

    #[test]
    fn dnssec_disabled_is_a_value_less_flag() {
        // No value needed, and it is off unless given
        assert!(!parse(&[]).dns_dnssec_disabled);
        assert!(parse(&["--dns-dnssec-disabled"]).dns_dnssec_disabled);
        // A bare value after the flag is not consumed by it - there are no positionals
        assert!(try_parse(&["--dns-dnssec-disabled", "true"]).is_err());
    }

    #[test]
    fn every_argument_is_also_settable_via_its_env_var() {
        let cmd = Cli::command();
        let env_of = |id: &str| -> String {
            cmd.get_arguments()
                .find(|x| x.get_id().as_str() == id)
                .unwrap_or_else(|| panic!("no argument with id {id}"))
                .get_env()
                .unwrap_or_else(|| panic!("argument {id} has no env var"))
                .to_string_lossy()
                .into_owned()
        };

        for id in [
            "dns_servers",
            "dns_protocol",
            "dns_cache_size",
            "dns_timeout",
            "dns_attempts",
            "dns_tls_name",
            "dns_lookup_strategy",
            "dns_dnssec_disabled",
        ] {
            assert_eq!(env_of(id), id.to_uppercase());
        }
    }

    #[test]
    fn repeating_a_single_value_argument_conflicts() {
        // `--dns-servers` appends, but the scalar arguments do not: a second
        // occurrence is an error rather than a last-one-wins override
        for arg in [
            "--dns-cache-size=7",
            "--dns-protocol=tls",
            "--dns-timeout=1s",
        ] {
            match try_parse(&[arg, arg]) {
                Ok(_) => panic!("{arg} given twice should have been rejected"),
                Err(e) => assert_eq!(e.kind(), ErrorKind::ArgumentConflict, "{arg}: {e}"),
            }
        }
    }

    #[test]
    fn unknown_flags_are_rejected() {
        assert!(try_parse(&["--dns-server=127.0.0.1"]).is_err());
        assert!(try_parse(&["--dns-timeouts=1s"]).is_err());
    }

    #[test]
    fn resolver_opts_are_derived_from_the_cli() {
        let opts = ResolverOpts::from(&parse(&[
            "--dns-cache-size=13",
            "--dns-timeout=7s",
            "--dns-attempts=4",
            "--dns-lookup-strategy=ipv6_only",
        ]));

        assert_eq!(opts.cache_size, 13);
        assert_eq!(opts.timeout, Duration::from_secs(7));
        assert_eq!(opts.attempts, 4);
        assert_eq!(opts.ip_strategy, LookupIpStrategy::Ipv6Only);
        // Invariants that do not come from the CLI
        assert_eq!(opts.use_hosts_file, ResolveHosts::Never);
        assert!(!opts.preserve_intermediates);
        assert!(opts.try_tcp_on_error);
    }

    #[test]
    fn dnssec_flag_is_inverted_into_resolver_validation() {
        // The flag disables validation, so the polarity must flip
        assert!(ResolverOpts::from(&parse(&[])).validate);
        assert!(!ResolverOpts::from(&parse(&["--dns-dnssec-disabled"])).validate);
    }

    #[test]
    fn resolver_config_gets_one_name_server_per_cli_server() {
        let cfg = ResolverConfig::from(&parse(&["--dns-servers=127.0.0.1,::1"]));
        let servers = cfg.name_servers();

        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(servers[1].ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert!(servers.iter().all(|x| x.trust_negative_responses));
    }

    #[test]
    fn cleartext_protocol_yields_udp_and_tcp_connections_on_the_same_port() {
        let cfg = ResolverConfig::from(&parse(&[
            "--dns-servers=127.0.0.1",
            "--dns-protocol=clear:5353",
        ]));
        let conns = &cfg.name_servers()[0].connections;

        assert_eq!(conns.len(), 2);
        assert_eq!(conns[0].protocol, ProtocolConfig::Udp);
        assert_eq!(conns[1].protocol, ProtocolConfig::Tcp);
        assert!(conns.iter().all(|x| x.port == 5353));
    }

    #[test]
    fn encrypted_protocols_carry_the_configured_tls_name() {
        let cfg = ResolverConfig::from(&parse(&[
            "--dns-servers=127.0.0.1",
            "--dns-protocol=tls",
            "--dns-tls-name=dns.example.com",
        ]));
        let conns = &cfg.name_servers()[0].connections;
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].port, 853);
        assert_eq!(
            conns[0].protocol,
            ProtocolConfig::Tls {
                server_name: Arc::from("dns.example.com")
            }
        );

        let cfg = ResolverConfig::from(&parse(&[
            "--dns-servers=127.0.0.1",
            "--dns-protocol=https:8443",
            "--dns-tls-name=dns.example.com",
        ]));
        let conns = &cfg.name_servers()[0].connections;
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].port, 8443);
        assert_eq!(
            conns[0].protocol,
            ProtocolConfig::Https {
                server_name: Arc::from("dns.example.com"),
                path: Arc::from("/dns-query"),
            }
        );
    }
}

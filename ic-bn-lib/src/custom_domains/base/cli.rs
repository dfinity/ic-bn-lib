use std::{path::PathBuf, time::Duration};

use candid::Principal;
use clap::Args;
use fqdn::FQDN;
use humantime::parse_duration;
use reqwest::Url;

use crate::tls::acme::{AcmeUrl, dns::cloudflare::DEFAULT_CLOUDFLARE_URL};

#[derive(Debug, Args)]
pub struct CustomDomainsCli {
    /// Domain name to access the IC (used to interact with the Custom Domains management canister).
    #[clap(env, long, default_value = "icp0.io")]
    pub custom_domains_ic_domain: FQDN,

    /// Comma-separated validation domains used to verify canister ownership via
    /// https://<canister-id>.<validation-domain>/.well-known/ic-domains (tried in order until one succeeds).
    #[clap(env, long, value_delimiter = ',', default_values = ["icp0.io", "ic0.app"])]
    pub custom_domains_validation_domains: Vec<FQDN>,

    /// Path to an IC identity file (PEM-encoded)
    #[clap(env, long, required = false)]
    pub custom_domains_ic_identity: PathBuf,

    /// Path to an IC root key.
    /// If not specified - hardcoded one will be used.
    #[clap(env, long)]
    pub custom_domains_ic_root_key: Option<PathBuf>,

    /// ID of the management canister
    #[clap(env, long, required = false)]
    pub custom_domains_canister_id: Principal,

    /// How frequently the canister client would poll it for changes to the data.
    #[clap(env, long, value_parser = parse_duration, default_value = "5s")]
    pub custom_domains_canister_poll_interval: Duration,

    /// How frequently to perform the full sync of the certificates from the canister irrespecive
    /// of the the changes timestamp
    #[clap(env, long, value_parser = parse_duration, default_value = "5m")]
    pub custom_domains_canister_refresh_interval: Duration,

    /// Cloudflare API URL
    #[clap(env, long, default_value = DEFAULT_CLOUDFLARE_URL)]
    pub custom_domains_cloudflare_url: Url,

    /// Token to access Cloudflare API
    #[clap(env, long, required = false)]
    pub custom_domains_cloudflare_token: String,

    /// Encryption key to encrypt/decrypt certificates in the canister storage.
    /// Must be exactly 256 bits / 32 bytes and Base64-encoded.
    #[clap(env, long, required = false)]
    pub custom_domains_encryption_key: String,

    /// Domain that the clients delegate their entries (ACME & canister) to
    #[clap(env, long, default_value = "icp2.io")]
    pub custom_domains_delegation_domain: FQDN,

    /// Which ACME provider URL to use. Can be "le_stag", "le_prod" for LetsEncrypt, or a custom URL.
    /// Defaults to "le_stag".
    #[clap(env, long, default_value = "le_stag")]
    pub custom_domains_acme_url: AcmeUrl,

    /// Path to a JSON file with ACME account data
    #[clap(env, long, required = false)]
    pub custom_domains_acme_account: PathBuf,

    /// How many worker tasks to spawn
    #[clap(env, long, default_value = "1")]
    pub custom_domains_workers_count: usize,
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use clap::{CommandFactory, Parser, error::ErrorKind};

    use super::*;
    use crate::principal;

    /// `CustomDomainsCli` is an `Args` group, so it needs a `Parser` host to be parsed standalone.
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        custom_domains: CustomDomainsCli,
    }

    /// The arguments that have neither a default nor an `Option` type: parsing fails without them.
    const REQUIRED: &[&str] = &[
        "--custom-domains-ic-identity=/nonexistent/identity.pem",
        "--custom-domains-canister-id=rrkah-fqaaa-aaaaa-aaaaq-cai",
        "--custom-domains-cloudflare-token=cf-token",
        "--custom-domains-encryption-key=c2VjcmV0",
        "--custom-domains-acme-account=/nonexistent/acme.json",
    ];

    /// Parses `args` with the required arguments filled in. Clap rejects a repeated
    /// single-value argument outright (see `repeating_a_single_value_argument_conflicts`),
    /// so a required argument that `args` already carries is not added a second time.
    fn try_parse(args: &[&str]) -> Result<CustomDomainsCli, clap::Error> {
        let flag_of = |arg: &str| arg.split('=').next().unwrap_or(arg).to_string();
        let given = args.iter().map(|x| flag_of(x)).collect::<Vec<_>>();

        let mut argv = vec!["test".to_string()];
        argv.extend(
            REQUIRED
                .iter()
                .filter(|x| !given.contains(&flag_of(x)))
                .map(|x| (*x).to_string()),
        );
        argv.extend(args.iter().map(|x| (*x).to_string()));

        Cli::try_parse_from(argv).map(|x| x.custom_domains)
    }

    fn parse(args: &[&str]) -> CustomDomainsCli {
        try_parse(args).unwrap()
    }

    fn fqdn(v: &str) -> FQDN {
        FQDN::from_str(v).unwrap()
    }

    #[test]
    fn cli_definition_is_valid() {
        // Catches e.g. a duplicated argument id or a `requires` pointing nowhere
        Cli::command().debug_assert();
    }

    #[test]
    fn defaults() {
        let c = parse(&[]);

        assert_eq!(c.custom_domains_ic_domain, fqdn("icp0.io"));
        assert_eq!(
            c.custom_domains_validation_domains,
            vec![fqdn("icp0.io"), fqdn("ic0.app")]
        );
        assert_eq!(c.custom_domains_ic_root_key, None);
        assert_eq!(
            c.custom_domains_canister_poll_interval,
            Duration::from_secs(5)
        );
        assert_eq!(
            c.custom_domains_canister_refresh_interval,
            Duration::from_secs(300)
        );
        assert_eq!(
            c.custom_domains_cloudflare_url.as_str(),
            "https://api.cloudflare.com/"
        );
        assert_eq!(
            c.custom_domains_cloudflare_url,
            Url::parse(DEFAULT_CLOUDFLARE_URL).unwrap()
        );
        assert_eq!(c.custom_domains_delegation_domain, fqdn("icp2.io"));
        // Doc comment promises the staging ACME endpoint by default
        assert_eq!(c.custom_domains_acme_url, AcmeUrl::LetsEncryptStaging);
        assert_eq!(c.custom_domains_workers_count, 1);

        // And the required ones come through verbatim
        assert_eq!(
            c.custom_domains_ic_identity,
            PathBuf::from("/nonexistent/identity.pem")
        );
        assert_eq!(
            c.custom_domains_canister_id,
            principal!("rrkah-fqaaa-aaaaa-aaaaq-cai")
        );
        assert_eq!(c.custom_domains_cloudflare_token, "cf-token");
        assert_eq!(c.custom_domains_encryption_key, "c2VjcmV0");
        assert_eq!(
            c.custom_domains_acme_account,
            PathBuf::from("/nonexistent/acme.json")
        );
    }

    #[test]
    fn dropping_a_required_argument_is_a_missing_argument_error() {
        for (i, missing) in REQUIRED.iter().enumerate() {
            let mut argv = vec!["test"];
            argv.extend(
                REQUIRED
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, x)| *x),
            );

            match Cli::try_parse_from(argv) {
                Ok(_) => panic!("{missing} is supposed to be required"),
                Err(e) => {
                    assert_eq!(
                        e.kind(),
                        ErrorKind::MissingRequiredArgument,
                        "unexpected error for missing {missing}: {e}"
                    );

                    // ...and the error has to name the argument that is actually
                    // missing, not merely some argument. Separators are folded out so
                    // this holds for both the `custom_domains_foo` and the
                    // `--custom-domains-foo <CUSTOM_DOMAINS_FOO>` spelling.
                    let fold = |v: &str| v.to_lowercase().replace(['-', '_'], "");
                    let flag = missing.split('=').next().unwrap();
                    assert!(
                        fold(&e.to_string()).contains(&fold(flag)),
                        "error for missing {flag} does not name it: {e}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_flag_takes_an_explicit_value() {
        // Distinct values everywhere, so a mis-wired flag shows up
        let c = parse(&[
            "--custom-domains-ic-domain=ic0.app",
            "--custom-domains-validation-domains=a.io,b.io",
            "--custom-domains-ic-identity=/tmp/id.pem",
            "--custom-domains-ic-root-key=/tmp/root.key",
            "--custom-domains-canister-id=aaaaa-aa",
            "--custom-domains-canister-poll-interval=250ms",
            "--custom-domains-canister-refresh-interval=1h 30m",
            "--custom-domains-cloudflare-url=http://127.0.0.1:8080/api/",
            "--custom-domains-cloudflare-token=tok",
            "--custom-domains-encryption-key=a2V5",
            "--custom-domains-delegation-domain=deleg.example.com",
            "--custom-domains-acme-url=le_prod",
            "--custom-domains-acme-account=/tmp/acme.json",
            "--custom-domains-workers-count=16",
        ]);

        assert_eq!(c.custom_domains_ic_domain, fqdn("ic0.app"));
        assert_eq!(
            c.custom_domains_validation_domains,
            vec![fqdn("a.io"), fqdn("b.io")]
        );
        assert_eq!(c.custom_domains_ic_identity, PathBuf::from("/tmp/id.pem"));
        assert_eq!(
            c.custom_domains_ic_root_key,
            Some(PathBuf::from("/tmp/root.key"))
        );
        assert_eq!(c.custom_domains_canister_id, principal!("aaaaa-aa"));
        assert_eq!(
            c.custom_domains_canister_poll_interval,
            Duration::from_millis(250)
        );
        assert_eq!(
            c.custom_domains_canister_refresh_interval,
            Duration::from_secs(5400)
        );
        assert_eq!(
            c.custom_domains_cloudflare_url.as_str(),
            "http://127.0.0.1:8080/api/"
        );
        assert_eq!(c.custom_domains_cloudflare_token, "tok");
        assert_eq!(c.custom_domains_encryption_key, "a2V5");
        assert_eq!(
            c.custom_domains_delegation_domain,
            fqdn("deleg.example.com")
        );
        assert_eq!(c.custom_domains_acme_url, AcmeUrl::LetsEncryptProduction);
        assert_eq!(
            c.custom_domains_acme_account,
            PathBuf::from("/tmp/acme.json")
        );
        assert_eq!(c.custom_domains_workers_count, 16);
    }

    #[test]
    fn validation_domains_are_comma_delimited_and_replace_the_defaults() {
        // A single occurrence is split on commas and wholly replaces the two defaults
        let c = parse(&["--custom-domains-validation-domains=a.io,b.io,c.io"]);
        assert_eq!(
            c.custom_domains_validation_domains,
            vec![fqdn("a.io"), fqdn("b.io"), fqdn("c.io")]
        );

        // Repeated occurrences accumulate, and the doc comment promises the order is kept
        let c = parse(&[
            "--custom-domains-validation-domains",
            "one.io",
            "--custom-domains-validation-domains",
            "two.io,three.io",
        ]);
        assert_eq!(
            c.custom_domains_validation_domains,
            vec![fqdn("one.io"), fqdn("two.io"), fqdn("three.io")]
        );

        // A single bad entry fails the whole list
        assert!(try_parse(&["--custom-domains-validation-domains=a.io,a..b,c.io"]).is_err());
    }

    #[test]
    fn fqdn_arguments_are_normalized_and_validated() {
        // Case is folded and a trailing root dot is accepted
        assert_eq!(
            parse(&["--custom-domains-ic-domain=ICP0.IO"]).custom_domains_ic_domain,
            fqdn("icp0.io")
        );
        assert_eq!(
            parse(&["--custom-domains-ic-domain=icp0.io."]).custom_domains_ic_domain,
            fqdn("icp0.io")
        );
        assert_eq!(
            parse(&["--custom-domains-delegation-domain=SUB.Icp2.IO."])
                .custom_domains_delegation_domain,
            fqdn("sub.icp2.io")
        );

        // Malformed domains are rejected
        // Note: the `fqdn` crate accepts non-ASCII labels, so "büro.io" is *not* in here
        for v in ["a..b", "a b.io", "a.io/x", "a.io:53"] {
            assert!(
                try_parse(&[&format!("--custom-domains-ic-domain={v}")]).is_err(),
                "{v:?} should not parse as an FQDN"
            );
            assert!(
                try_parse(&[&format!("--custom-domains-delegation-domain={v}")]).is_err(),
                "{v:?} should not parse as an FQDN"
            );
        }
    }

    #[test]
    fn canister_id_must_be_a_textual_principal() {
        // The management canister id is the shortest valid principal
        assert_eq!(
            parse(&["--custom-domains-canister-id=aaaaa-aa"]).custom_domains_canister_id,
            Principal::management_canister()
        );

        // The textual form is case-insensitive and normalizes to lower case
        assert_eq!(
            parse(&["--custom-domains-canister-id=RRKAH-FQAAA-AAAAA-AAAAQ-CAI"])
                .custom_domains_canister_id,
            principal!("rrkah-fqaaa-aaaaa-aaaaq-cai")
        );

        for v in [
            "",
            "notaprincipal",
            "rrkah-fqaaa-aaaaa-aaaaq-ca",
            "rrkah_fqaaa_aaaaa_aaaaq_cai",
            "rrkahfqaaaaaaaaaaaaqcai",
        ] {
            assert!(
                try_parse(&[&format!("--custom-domains-canister-id={v}")]).is_err(),
                "{v:?} should not parse as a principal"
            );
        }
    }

    #[test]
    fn cloudflare_url_must_be_absolute() {
        assert_eq!(
            parse(&["--custom-domains-cloudflare-url=https://cf.example.com/client/v4/"])
                .custom_domains_cloudflare_url
                .as_str(),
            "https://cf.example.com/client/v4/"
        );

        // A missing scheme makes the URL relative, which `Url` refuses
        for v in ["", "api.cloudflare.com", "/client/v4", "not a url", "###"] {
            assert!(
                try_parse(&[&format!("--custom-domains-cloudflare-url={v}")]).is_err(),
                "{v:?} should not parse as a URL"
            );
        }
    }

    #[test]
    fn acme_url_accepts_the_two_aliases_or_a_custom_url() {
        assert_eq!(
            parse(&["--custom-domains-acme-url=le_stag"]).custom_domains_acme_url,
            AcmeUrl::LetsEncryptStaging
        );
        assert_eq!(
            parse(&["--custom-domains-acme-url=le_prod"]).custom_domains_acme_url,
            AcmeUrl::LetsEncryptProduction
        );
        assert_eq!(
            parse(&["--custom-domains-acme-url=https://acme.example.com/dir"])
                .custom_domains_acme_url,
            AcmeUrl::Custom(Url::parse("https://acme.example.com/dir").unwrap())
        );

        // The aliases are case-sensitive and anything that is not a URL is rejected
        for v in ["", "LE_STAG", "le-stag", "le_staging", "###"] {
            assert!(
                try_parse(&[&format!("--custom-domains-acme-url={v}")]).is_err(),
                "{v:?} should not parse as an ACME URL"
            );
        }
    }

    #[test]
    fn interval_arguments_are_humantime_durations() {
        assert_eq!(
            parse(&["--custom-domains-canister-poll-interval=0s"])
                .custom_domains_canister_poll_interval,
            Duration::ZERO
        );
        assert_eq!(
            parse(&["--custom-domains-canister-refresh-interval=2m 30s"])
                .custom_domains_canister_refresh_interval,
            Duration::from_secs(150)
        );

        for v in ["", "5", "abc", "-1s", "1h30"] {
            assert!(
                try_parse(&[&format!("--custom-domains-canister-poll-interval={v}")]).is_err(),
                "{v:?} should not parse as a duration"
            );
            assert!(
                try_parse(&[&format!("--custom-domains-canister-refresh-interval={v}")]).is_err(),
                "{v:?} should not parse as a duration"
            );
        }
    }

    #[test]
    fn workers_count_is_an_unvalidated_usize() {
        // No lower bound is enforced by the CLI itself
        assert_eq!(
            parse(&["--custom-domains-workers-count=0"]).custom_domains_workers_count,
            0
        );
        assert_eq!(
            parse(&[&format!("--custom-domains-workers-count={}", usize::MAX)])
                .custom_domains_workers_count,
            usize::MAX
        );

        for v in ["-1", "1.5", "abc", "", "18446744073709551616"] {
            assert!(
                try_parse(&[&format!("--custom-domains-workers-count={v}")]).is_err(),
                "{v:?} should not parse as a worker count"
            );
        }
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
            "custom_domains_ic_domain",
            "custom_domains_validation_domains",
            "custom_domains_ic_identity",
            "custom_domains_ic_root_key",
            "custom_domains_canister_id",
            "custom_domains_canister_poll_interval",
            "custom_domains_canister_refresh_interval",
            "custom_domains_cloudflare_url",
            "custom_domains_cloudflare_token",
            "custom_domains_encryption_key",
            "custom_domains_delegation_domain",
            "custom_domains_acme_url",
            "custom_domains_acme_account",
            "custom_domains_workers_count",
        ] {
            assert_eq!(env_of(id), id.to_uppercase());
        }
    }

    #[test]
    fn string_and_path_arguments_are_taken_verbatim() {
        let c = parse(&[
            "--custom-domains-cloudflare-token= to ken ",
            "--custom-domains-encryption-key==not+base64=",
            "--custom-domains-acme-account=relative/dir with space/acme.json",
        ]);

        // No trimming, and the value is not re-parsed in any way
        assert_eq!(c.custom_domains_cloudflare_token, " to ken ");
        assert_eq!(c.custom_domains_encryption_key, "=not+base64=");
        assert_eq!(
            c.custom_domains_acme_account,
            PathBuf::from("relative/dir with space/acme.json")
        );
    }

    #[test]
    fn repeating_a_single_value_argument_conflicts() {
        // None of the scalar arguments use clap's `Append` action, so a second
        // occurrence is an error rather than a last-one-wins override
        for arg in [
            "--custom-domains-workers-count=2",
            "--custom-domains-acme-url=le_prod",
            "--custom-domains-canister-id=aaaaa-aa",
        ] {
            let mut argv = vec!["test"];
            argv.extend_from_slice(REQUIRED);
            argv.push(arg);
            argv.push(arg);

            match Cli::try_parse_from(argv) {
                Ok(_) => panic!("{arg} given twice should have been rejected"),
                Err(e) => assert_eq!(e.kind(), ErrorKind::ArgumentConflict, "{arg}: {e}"),
            }
        }
    }

    #[test]
    fn unknown_flags_are_rejected() {
        assert!(try_parse(&["--custom-domains-ic-domains=icp0.io"]).is_err());
        assert!(try_parse(&["--custom-domains-workers=2"]).is_err());
    }
}

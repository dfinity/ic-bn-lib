use std::{fmt::Display, net::IpAddr, ops::Deref, path::PathBuf};

use anyhow::Context;
use arrayvec::ArrayString;
use clap::ArgAction::Count;
use maxminddb::geoip2;
use serde::{Deserialize, Serialize};

use crate::{Error, TruncatesString};

const CITY_NAME_MAX_LENGTH: usize = 32;

/// Two-letter country code.
/// See https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
pub struct CountryCode(pub ArrayString<2>);

impl Deref for CountryCode {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl Display for CountryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Location representation
pub struct Location {
    pub lat: f64,
    pub lon: f64,
}

/// GeoIP lookup city representation.
pub struct City {
    pub name: Option<ArrayString<CITY_NAME_MAX_LENGTH>>,
    pub country_code: Option<CountryCode>,
    pub location: Option<Location>,
}

/// Looks up the client's country using his IP address
pub struct GeoIp {
    db: maxminddb::Reader<Vec<u8>>,
}

impl GeoIp {
    /// Creates a new GeoIp instance from a provided database
    pub fn new(db_path: &PathBuf) -> Result<Self, Error> {
        Ok(Self {
            db: maxminddb::Reader::open_readfile(db_path).context("unable to load GeoIP DB")?,
        })
    }

    /// Looks up the country code from an IP
    pub fn lookup_country(&self, ip: IpAddr) -> Option<CountryCode> {
        let country: Option<geoip2::Country> = self.db.lookup(ip).ok()?.decode().ok()?;
        // Country code should always fit into 2-letter ArrayString.
        // If for whatever reason it does not - return None.
        Some(CountryCode(country?.country.iso_code?.try_into().ok()?))
    }

    /// Looks up the city from an IP
    pub fn lookup_city(&self, ip: IpAddr) -> Option<City> {
        let city: geoip2::City = self.db.lookup(ip).ok()?.decode().ok()??;

        Some(City {
            // Try English, then German, otherwise None
            name: city
                .city
                .names
                .english
                .or(city.city.names.german)
                // SAFETY: truncate_bytes makes the string *no longer* than CITY_NAME_MAX_LENGTH
                // so it will always fit into Arraystring
                .map(|x| x.truncate_bytes(CITY_NAME_MAX_LENGTH).try_into().unwrap()),

            country_code: city
                .country
                .iso_code
                .and_then(|x| x.try_into().ok())
                .map(CountryCode),

            // Location is Some only when both lat & lon are available
            location: city
                .location
                .latitude
                .zip(city.location.longitude)
                .map(|(lat, lon)| Location { lat, lon }),
        })
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use super::*;

    // Known entries in the MaxMind test DB
    const IP_KNOWN: Ipv4Addr = Ipv4Addr::new(89, 160, 20, 112);
    const COUNTRY_KNOWN: &str = "SE";
    const IP_UNKNOWN: Ipv4Addr = Ipv4Addr::new(10, 10, 10, 10);

    fn test_db_path() -> PathBuf {
        PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-data/geoip-test-db.mmdb"
        ))
    }

    #[test]
    fn lookup_known_ip_returns_country_code() {
        let geoip = GeoIp::new(&test_db_path()).unwrap();
        assert_eq!(
            geoip
                .lookup_country(IpAddr::V4(IP_KNOWN))
                .unwrap()
                .0
                .as_str(),
            COUNTRY_KNOWN
        );
    }

    #[test]
    fn lookup_unknown_ip_returns_none() {
        let geoip = GeoIp::new(&test_db_path()).unwrap();
        assert!(geoip.lookup_country(IpAddr::V4(IP_UNKNOWN)).is_none());
    }
}

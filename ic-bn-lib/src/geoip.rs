use anyhow::Context;
use arrayvec::ArrayString;
use ipnet::IpNet;
use maxminddb::{LookupResult, geoip2};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, net::IpAddr, ops::Deref, path::PathBuf};

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

/// GeoIP lookup city representation
pub struct City {
    pub name: Option<ArrayString<CITY_NAME_MAX_LENGTH>>,
    pub country_code: Option<CountryCode>,
    pub location: Option<Location>,
}

impl From<geoip2::City<'_>> for City {
    fn from(city: geoip2::City<'_>) -> Self {
        Self {
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
        }
    }
}

/// Looks up the client's location using his IP address
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

    fn to_ipnet(lookup: &LookupResult<'_, Vec<u8>>) -> Option<IpNet> {
        let net = lookup.network().ok()?;
        IpNet::new(net.ip(), net.prefix()).ok()
    }

    /// Looks up the country code from an IP
    pub fn lookup_country(&self, ip: IpAddr) -> Option<(CountryCode, IpNet)> {
        let lookup = self.db.lookup(ip).ok()?;
        let country: Option<geoip2::Country> = lookup.decode().ok()?;

        // Country code should always fit into 2-letter ArrayString.
        // If for whatever reason it does not - return None.
        country?
            .country
            .iso_code?
            .try_into()
            .ok()
            .zip(Self::to_ipnet(&lookup))
            .map(|(a, b)| (CountryCode(a), b))
    }

    /// Looks up the city from an IP
    pub fn lookup_city(&self, ip: IpAddr) -> Option<(City, IpNet)> {
        let lookup = self.db.lookup(ip).ok()?;
        let city: geoip2::City = lookup.decode().ok()??;

        Some((city.into(), Self::to_ipnet(&lookup)?))
    }
}

#[cfg(test)]
mod test {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    // Known entries in the MaxMind test DBs (present in both Country & City DBs)
    const IP_KNOWN: Ipv4Addr = Ipv4Addr::new(89, 160, 20, 112);
    const NET_KNOWN: &str = "89.160.20.112/28";
    const COUNTRY_KNOWN: &str = "SE";
    const CITY_KNOWN: &str = "Linköping";
    const LAT_KNOWN: f64 = 58.4167;
    const LON_KNOWN: f64 = 15.6167;
    const IP_UNKNOWN: Ipv4Addr = Ipv4Addr::new(10, 10, 10, 10);
    // City DB: country & location, but no city name
    const IP_NO_CITY_NAME: Ipv4Addr = Ipv4Addr::new(149, 101, 100, 1);
    const NET_NO_CITY_NAME: &str = "149.101.100.0/28";
    // City DB: location only, no country and no city name
    const IP_LOCATION_ONLY: Ipv6Addr = Ipv6Addr::new(0x2a02, 0xd500, 0, 0, 0, 0, 0, 1);
    const NET_LOCATION_ONLY: &str = "2a02:d500::/29";
    // City DB: record exists but is empty
    const IP_EMPTY_RECORD: Ipv4Addr = Ipv4Addr::new(2, 3, 3, 1);
    const NET_EMPTY_RECORD: &str = "2.3.3.0/24";

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    /// MaxMind GeoIP2-Country test DB
    fn test_db_path() -> PathBuf {
        PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-data/geoip-test-db.mmdb"
        ))
    }

    /// MaxMind GeoIP2-City test DB
    fn test_city_db_path() -> PathBuf {
        PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-data/geoip-city-test-db.mmdb"
        ))
    }

    /// Builds a raw MaxMind city record with only the fields we care about
    fn geoip2_city<'a>(
        english: Option<&'a str>,
        german: Option<&'a str>,
        iso_code: Option<&'a str>,
        latitude: Option<f64>,
        longitude: Option<f64>,
    ) -> geoip2::City<'a> {
        geoip2::City {
            city: geoip2::city::City {
                names: geoip2::Names {
                    english,
                    german,
                    ..Default::default()
                },
                ..Default::default()
            },
            country: geoip2::city::Country {
                iso_code,
                ..Default::default()
            },
            location: geoip2::city::Location {
                latitude,
                longitude,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn lookup_known_ip_returns_country_code_and_network() {
        let geoip = GeoIp::new(&test_db_path()).unwrap();
        let (country_code, network) = geoip.lookup_country(IpAddr::V4(IP_KNOWN)).unwrap();

        assert_eq!(country_code.0.as_str(), COUNTRY_KNOWN);
        assert_eq!(network, net(NET_KNOWN));
        assert!(network.contains(&IpAddr::V4(IP_KNOWN)));
    }

    #[test]
    fn lookup_unknown_ip_returns_none() {
        let geoip = GeoIp::new(&test_db_path()).unwrap();
        assert!(geoip.lookup_country(IpAddr::V4(IP_UNKNOWN)).is_none());
    }

    #[test]
    fn lookup_city_known_ip_returns_name_country_location_and_network() {
        let geoip = GeoIp::new(&test_city_db_path()).unwrap();
        let (city, network) = geoip.lookup_city(IpAddr::V4(IP_KNOWN)).unwrap();

        assert_eq!(city.name.unwrap().as_str(), CITY_KNOWN);
        assert_eq!(city.country_code.unwrap().0.as_str(), COUNTRY_KNOWN);

        let location = city.location.unwrap();
        assert_eq!(location.lat, LAT_KNOWN);
        assert_eq!(location.lon, LON_KNOWN);

        assert_eq!(network, net(NET_KNOWN));
        assert!(network.contains(&IpAddr::V4(IP_KNOWN)));
    }

    #[test]
    fn lookup_city_unknown_ip_returns_none() {
        let geoip = GeoIp::new(&test_city_db_path()).unwrap();
        assert!(geoip.lookup_city(IpAddr::V4(IP_UNKNOWN)).is_none());
    }

    #[test]
    fn lookup_city_without_name_returns_country_and_location() {
        let geoip = GeoIp::new(&test_city_db_path()).unwrap();
        let (city, network) = geoip.lookup_city(IpAddr::V4(IP_NO_CITY_NAME)).unwrap();

        assert!(city.name.is_none());
        assert_eq!(city.country_code.unwrap().0.as_str(), "US");

        let location = city.location.unwrap();
        assert_eq!(location.lat, 37.751);
        assert_eq!(location.lon, -97.822);

        assert_eq!(network, net(NET_NO_CITY_NAME));
    }

    #[test]
    fn lookup_city_ipv6_with_location_only() {
        let geoip = GeoIp::new(&test_city_db_path()).unwrap();
        let (city, network) = geoip.lookup_city(IpAddr::V6(IP_LOCATION_ONLY)).unwrap();

        assert!(city.name.is_none());
        assert!(city.country_code.is_none());

        let location = city.location.unwrap();
        assert_eq!(location.lat, 48.69096);
        assert_eq!(location.lon, 9.14062);

        assert_eq!(network, net(NET_LOCATION_ONLY));
    }

    #[test]
    fn lookup_city_empty_record_returns_city_without_fields() {
        let geoip = GeoIp::new(&test_city_db_path()).unwrap();
        let (city, network) = geoip.lookup_city(IpAddr::V4(IP_EMPTY_RECORD)).unwrap();

        assert!(city.name.is_none());
        assert!(city.country_code.is_none());
        assert!(city.location.is_none());

        assert_eq!(network, net(NET_EMPTY_RECORD));
    }

    #[test]
    fn lookup_city_with_country_db_returns_country_only() {
        let geoip = GeoIp::new(&test_db_path()).unwrap();
        let (city, network) = geoip.lookup_city(IpAddr::V4(IP_KNOWN)).unwrap();

        assert!(city.name.is_none());
        assert_eq!(city.country_code.unwrap().0.as_str(), COUNTRY_KNOWN);
        assert!(city.location.is_none());

        assert_eq!(network, net(NET_KNOWN));
    }

    #[test]
    fn city_from_geoip2_prefers_english_name() {
        let city = City::from(geoip2_city(
            Some("Singapore"),
            Some("Singapur"),
            None,
            None,
            None,
        ));
        assert_eq!(city.name.unwrap().as_str(), "Singapore");
    }

    #[test]
    fn city_from_geoip2_falls_back_to_german_name() {
        let city = City::from(geoip2_city(None, Some("Singapur"), None, None, None));
        assert_eq!(city.name.unwrap().as_str(), "Singapur");
    }

    #[test]
    fn city_from_geoip2_without_names_has_no_name() {
        let city = City::from(geoip2_city(None, None, None, None, None));
        assert!(city.name.is_none());
    }

    #[test]
    fn city_from_geoip2_truncates_long_name() {
        // 58 ASCII bytes, truncated to exactly CITY_NAME_MAX_LENGTH bytes
        let long = "Llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch";
        assert!(long.len() > CITY_NAME_MAX_LENGTH);
        let city = City::from(geoip2_city(Some(long), None, None, None, None));
        assert_eq!(city.name.unwrap().as_str(), &long[..CITY_NAME_MAX_LENGTH]);

        // 17 two-byte chars = 34 bytes, byte 32 is a char boundary -> 16 chars kept
        let name = "ä".repeat(17);
        let city = City::from(geoip2_city(Some(&name), None, None, None, None));
        assert_eq!(city.name.unwrap().as_str(), "ä".repeat(16).as_str());

        // 11 three-byte chars = 33 bytes, byte 32 is mid-char -> 10 chars (30 bytes) kept
        let name = "€".repeat(11);
        let city = City::from(geoip2_city(Some(&name), None, None, None, None));
        assert_eq!(city.name.unwrap().as_str(), "€".repeat(10).as_str());

        // Truncation also applies to the German fallback
        let city = City::from(geoip2_city(None, Some(long), None, None, None));
        assert_eq!(city.name.unwrap().as_str(), &long[..CITY_NAME_MAX_LENGTH]);
    }

    #[test]
    fn city_from_geoip2_country_code() {
        let city = City::from(geoip2_city(None, None, Some("SE"), None, None));
        assert_eq!(city.country_code.unwrap().0.as_str(), "SE");

        // ISO code that doesn't fit into two letters is dropped
        let city = City::from(geoip2_city(None, None, Some("SWE"), None, None));
        assert!(city.country_code.is_none());

        let city = City::from(geoip2_city(None, None, None, None, None));
        assert!(city.country_code.is_none());
    }

    #[test]
    fn city_from_geoip2_location_requires_both_coordinates() {
        let city = City::from(geoip2_city(
            None,
            None,
            None,
            Some(LAT_KNOWN),
            Some(LON_KNOWN),
        ));
        let location = city.location.unwrap();
        assert_eq!(location.lat, LAT_KNOWN);
        assert_eq!(location.lon, LON_KNOWN);

        let city = City::from(geoip2_city(None, None, None, Some(LAT_KNOWN), None));
        assert!(city.location.is_none());

        let city = City::from(geoip2_city(None, None, None, None, Some(LON_KNOWN)));
        assert!(city.location.is_none());

        let city = City::from(geoip2_city(None, None, None, None, None));
        assert!(city.location.is_none());
    }
}

//! Public AirVPN status API types and client.
//!
//! The status endpoint (`https://airvpn.org/api/status/`) returns live server
//! load, bandwidth, and health information without requiring authentication.
//! The [`fetch_status`] function and the `Deserialize` structs here correspond
//! to that JSON API. Uses a generated schema from the API example.

use serde::Deserialize;

use crate::errors::{Error, Result};

const STATUS_URL: &str = "https://airvpn.org/api/status/";

/// Top-level response from the public `/api/status/` endpoint.
#[derive(Debug, Deserialize, Clone)]
pub struct StatusResponse {
    /// An optional deprecation notice from the API.
    #[serde(default)]
    pub deprecated_warning: Option<String>,
    /// List of VPN servers with load and IP information.
    #[serde(default)]
    pub servers: Vec<Server>,
    /// List of routing/exit entries.
    #[serde(default)]
    pub routing: Vec<RoutingEntry>,
    /// List of countries with aggregate bandwidth and server counts.
    #[serde(default)]
    pub countries: Vec<Country>,
    /// List of continents with aggregate bandwidth and server counts.
    #[serde(default)]
    pub continents: Vec<Continent>,
    /// List of "planets" (top-level groupings) in the AirVPN network.
    #[serde(default)]
    pub planets: Vec<Planet>,
    /// The API result status: `"ok"` or `"error"`.
    pub result: String,
}

/// A single VPN server from the status API.
#[derive(Debug, Deserialize, Clone)]
pub struct Server {
    /// The server's display name (e.g. "Algorab").
    pub public_name: String,
    /// The country the server is located in.
    #[serde(default)]
    pub country_name: Option<String>,
    /// Two-letter country code.
    #[serde(default)]
    pub country_code: Option<String>,
    /// City or region.
    #[serde(default)]
    pub location: Option<String>,
    /// Continent name.
    #[serde(default)]
    pub continent: Option<String>,
    /// Current bandwidth in kbit/s.
    #[serde(default)]
    pub bw: Option<i32>,
    /// Maximum bandwidth in kbit/s.
    #[serde(default)]
    pub bw_max: Option<i32>,
    /// Number of currently connected users.
    #[serde(default)]
    pub users: Option<i32>,
    /// Current load percentage.
    #[serde(default)]
    pub currentload: Option<i32>,
    /// IPv4 entry address 1.
    #[serde(default)]
    pub ip_v4_in1: Option<String>,
    /// IPv4 entry address 2.
    #[serde(default)]
    pub ip_v4_in2: Option<String>,
    /// IPv4 entry address 3.
    #[serde(default)]
    pub ip_v4_in3: Option<String>,
    /// IPv4 entry address 4.
    #[serde(default)]
    pub ip_v4_in4: Option<String>,
    /// IPv6 entry address 1.
    #[serde(default)]
    pub ip_v6_in1: Option<String>,
    /// IPv6 entry address 2.
    #[serde(default)]
    pub ip_v6_in2: Option<String>,
    /// IPv6 entry address 3.
    #[serde(default)]
    pub ip_v6_in3: Option<String>,
    /// IPv6 entry address 4.
    #[serde(default)]
    pub ip_v6_in4: Option<String>,
    /// Server health status (e.g. "ok", "maintenance").
    #[serde(default)]
    pub health: Option<String>,
}

/// A routing/exit entry from the status API.
#[derive(Debug, Deserialize, Clone)]
pub struct RoutingEntry {
    /// The routing entry's display name.
    pub public_name: String,
    /// Country name.
    #[serde(default)]
    pub country_name: Option<String>,
    /// Two-letter country code.
    #[serde(default)]
    pub country_code: Option<String>,
    /// City or region.
    #[serde(default)]
    pub location: Option<String>,
    /// Continent name.
    #[serde(default)]
    pub continent: Option<String>,
    /// Current bandwidth in kbit/s.
    #[serde(default)]
    pub bw: Option<i32>,
    /// Maximum bandwidth in kbit/s.
    #[serde(default)]
    pub bw_max: Option<i32>,
    /// Current load percentage.
    #[serde(default)]
    pub currentload: Option<i32>,
    /// Health status.
    #[serde(default)]
    pub health: Option<String>,
}

/// Aggregate information about a country from the status API.
#[derive(Debug, Deserialize, Clone)]
pub struct Country {
    /// Full country name.
    pub country_name: String,
    /// Two-letter country code.
    pub country_code: String,
    /// Name of the best-performing server in this country.
    #[serde(default)]
    pub server_best: Option<String>,
    /// Current bandwidth in kbit/s.
    #[serde(default)]
    pub bw: Option<i32>,
    /// Maximum bandwidth in kbit/s.
    #[serde(default)]
    pub bw_max: Option<i32>,
    /// Number of currently connected users.
    #[serde(default)]
    pub users: Option<i32>,
    /// Number of servers in this country.
    #[serde(default)]
    pub servers: Option<i32>,
    /// Current load percentage.
    #[serde(default)]
    pub currentload: Option<i32>,
    /// IPv4 entry address 1.
    #[serde(default)]
    pub ip_v4_in1: Option<String>,
    /// IPv4 entry address 2.
    #[serde(default)]
    pub ip_v4_in2: Option<String>,
    /// IPv4 entry address 3.
    #[serde(default)]
    pub ip_v4_in3: Option<String>,
    /// IPv4 entry address 4.
    #[serde(default)]
    pub ip_v4_in4: Option<String>,
    /// IPv6 entry address 1.
    #[serde(default)]
    pub ip_v6_in1: Option<String>,
    /// IPv6 entry address 2.
    #[serde(default)]
    pub ip_v6_in2: Option<String>,
    /// IPv6 entry address 3.
    #[serde(default)]
    pub ip_v6_in3: Option<String>,
    /// IPv6 entry address 4.
    #[serde(default)]
    pub ip_v6_in4: Option<String>,
    /// Health status.
    #[serde(default)]
    pub health: Option<String>,
}

/// Aggregate information about a continent from the status API.
#[derive(Debug, Deserialize, Clone)]
pub struct Continent {
    /// Continent display name.
    pub public_name: String,
    /// Name of the best-performing server on this continent.
    #[serde(default)]
    pub server_best: Option<String>,
    /// Current bandwidth in kbit/s.
    #[serde(default)]
    pub bw: Option<i32>,
    /// Maximum bandwidth in kbit/s.
    #[serde(default)]
    pub bw_max: Option<i32>,
    /// Number of currently connected users.
    #[serde(default)]
    pub users: Option<i32>,
    /// Number of servers on this continent.
    #[serde(default)]
    pub servers: Option<i32>,
    /// Current load percentage.
    #[serde(default)]
    pub currentload: Option<i32>,
    /// IPv4 entry address 1.
    #[serde(default)]
    pub ip_v4_in1: Option<String>,
    /// IPv4 entry address 2.
    #[serde(default)]
    pub ip_v4_in2: Option<String>,
    /// IPv4 entry address 3.
    #[serde(default)]
    pub ip_v4_in3: Option<String>,
    /// IPv4 entry address 4.
    #[serde(default)]
    pub ip_v4_in4: Option<String>,
    /// IPv6 entry address 1.
    #[serde(default)]
    pub ip_v6_in1: Option<String>,
    /// IPv6 entry address 2.
    #[serde(default)]
    pub ip_v6_in2: Option<String>,
    /// IPv6 entry address 3.
    #[serde(default)]
    pub ip_v6_in3: Option<String>,
    /// IPv6 entry address 4.
    #[serde(default)]
    pub ip_v6_in4: Option<String>,
    /// Health status.
    #[serde(default)]
    pub health: Option<String>,
}

/// A top-level "planet" grouping in the AirVPN network.
#[derive(Debug, Deserialize, Clone)]
pub struct Planet {
    /// Planet display name.
    pub public_name: String,
    /// Name of the best-performing server in this planet.
    #[serde(default)]
    pub server_best: Option<String>,
    /// Current bandwidth in kbit/s.
    #[serde(default)]
    pub bw: Option<i32>,
    /// Maximum bandwidth in kbit/s.
    #[serde(default)]
    pub bw_max: Option<i32>,
    /// Number of currently connected users.
    #[serde(default)]
    pub users: Option<i32>,
    /// Number of servers in this planet.
    #[serde(default)]
    pub servers: Option<i32>,
    /// Current load percentage.
    #[serde(default)]
    pub currentload: Option<i32>,
    /// IPv4 entry address 1.
    #[serde(default)]
    pub ip_v4_in1: Option<String>,
    /// IPv4 entry address 2.
    #[serde(default)]
    pub ip_v4_in2: Option<String>,
    /// IPv4 entry address 3.
    #[serde(default)]
    pub ip_v4_in3: Option<String>,
    /// IPv4 entry address 4.
    #[serde(default)]
    pub ip_v4_in4: Option<String>,
    /// IPv6 entry address 1.
    #[serde(default)]
    pub ip_v6_in1: Option<String>,
    /// IPv6 entry address 2.
    #[serde(default)]
    pub ip_v6_in2: Option<String>,
    /// IPv6 entry address 3.
    #[serde(default)]
    pub ip_v6_in3: Option<String>,
    /// IPv6 entry address 4.
    #[serde(default)]
    pub ip_v6_in4: Option<String>,
    /// Health status.
    #[serde(default)]
    pub health: Option<String>,
}

/// Generic error structure returned by the AirVPN status API.
#[derive(Debug, Deserialize, Clone)]
pub struct ApiError {
    /// Human-readable error message.
    pub error: String,
}

/// Fetch the current server status from the public AirVPN API.
///
/// The endpoint returns live server load, bandwidth, 
/// and health information without any authentication required.
pub async fn fetch_status() -> Result<StatusResponse> {
    log::info!("fetching status from {STATUS_URL}");
    let resp = reqwest::get(STATUS_URL).await?;
    let text = resp.text().await?;
    let status: StatusResponse = serde_json::from_str(&text)?;
    if status.result == "error" {
        let err: ApiError = serde_json::from_str(&text).unwrap_or(ApiError {
            error: "unknown error".into(),
        });
        return Err(Error::Api(err.error));
    }
    log::info!(
        "received {} servers, {} countries",
        status.servers.len(),
        status.countries.len()
    );
    Ok(status)
}

#[cfg(test)]
mod tests { // generated tests
    use super::*;

    #[test]
    fn test_deserialize_minimal_status() {
        let json = r#"{"result":"ok","servers":[],"routing":[],"countries":[],"continents":[],"planets":[]}"#;
        let status: StatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(status.result, "ok");
        assert!(status.servers.is_empty());
    }

    #[test]
    fn test_deserialize_status_with_server() {
        let json = r#"{
            "result": "ok",
            "servers": [
                {
                    "public_name": "Algorab",
                    "country_name": "Netherlands",
                    "country_code": "NL",
                    "bw": 50000,
                    "bw_max": 100000,
                    "users": 42,
                    "currentload": 50,
                    "health": "ok"
                }
            ],
            "routing": [],
            "countries": [],
            "continents": [],
            "planets": []
        }"#;
        let status: StatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(status.servers.len(), 1);
        assert_eq!(status.servers[0].public_name, "Algorab");
        assert_eq!(status.servers[0].country_name.as_deref(), Some("Netherlands"));
        assert_eq!(status.servers[0].bw.unwrap(), 50000);
    }

    #[test]
    fn test_deserialize_server_defaults() {
        let json = r#"{"public_name": "TestServer"}"#;
        let server: Server = serde_json::from_str(json).unwrap();
        assert_eq!(server.public_name, "TestServer");
        assert!(server.country_name.is_none());
        assert!(server.bw.is_none());
        assert!(server.health.is_none());
    }

    #[test]
    fn test_deserialize_country() {
        let json = r#"{
            "country_name": "Netherlands",
            "country_code": "NL",
            "bw": 100000,
            "servers": 5
        }"#;
        let country: Country = serde_json::from_str(json).unwrap();
        assert_eq!(country.country_name, "Netherlands");
        assert_eq!(country.country_code, "NL");
        assert_eq!(country.bw.unwrap(), 100000);
        assert_eq!(country.servers.unwrap(), 5);
    }

    #[test]
    fn test_deserialize_continent() {
        let json = r#"{
            "public_name": "Europe",
            "bw": 500000,
            "servers": 20
        }"#;
        let continent: Continent = serde_json::from_str(json).unwrap();
        assert_eq!(continent.public_name, "Europe");
    }

    #[test]
    fn test_deserialize_planet() {
        let json = r#"{
            "public_name": "Earth",
            "bw": 1000000,
            "servers": 100
        }"#;
        let planet: Planet = serde_json::from_str(json).unwrap();
        assert_eq!(planet.public_name, "Earth");
    }

    #[test]
    fn test_deserialize_routing_entry() {
        let json = r#"{
            "public_name": "Algorab-Routing",
            "bw": 50000,
            "currentload": 30
        }"#;
        let routing: RoutingEntry = serde_json::from_str(json).unwrap();
        assert_eq!(routing.public_name, "Algorab-Routing");
    }

    #[test]
    fn test_api_error_deserialize() {
        let json = r#"{"error": "invalid credentials"}"#;
        let err: ApiError = serde_json::from_str(json).unwrap();
        assert_eq!(err.error, "invalid credentials");
    }
}
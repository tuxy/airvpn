//! WireGuard configuration extraction and server resolution.
//!
//! This module parses the XML user profile returned by AirVPN into a
//! [`WireGuardConfig`] struct, resolves server endpoints from the manifest,
//! and generates a standard WireGuard `.conf` file string.
//!
//! # Example
//!
//! ```no_run
//! use airvpn::{AirVPN, WireGuardConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = AirVPN::builder()
//!     .credentials("user", "pass")
//!     .server("Algorab")
//!     .build()
//!     .await?;
//!
//! println!("{}", config.to_conf());
//! # Ok(())
//! # }
//! ```

use crate::errors::{Error, Result};

/// A fully-resolved WireGuard configuration ready to be written to a `.conf` file.
///
/// All fields are populated by [`AirVPN::builder`], including the `endpoint`
/// and `port` resolved from the manifest.
///
/// [`AirVPN::builder`]: crate::AirVPN::builder
#[derive(Debug, Clone)]
pub struct WireGuardConfig {
    /// The WireGuard interface private key (from the user profile `<key>` element).
    pub interface_private_key: String,
    /// The WireGuard peer public key (from the user profile `wg_public_key` attribute).
    pub peer_public_key: String,
    /// The WireGuard preshared key (from the user profile `<key>` element).
    pub preshared_key: String,
    /// The IPv4 address assigned to the WireGuard interface.
    pub address_ipv4: String,
    /// The IPv6 address assigned to the WireGuard interface.
    pub address_ipv6: String,
    /// The IPv4 DNS server for the WireGuard interface.
    pub dns_ipv4: String,
    /// The IPv6 DNS server for the WireGuard interface.
    pub dns_ipv6: String,
    /// The resolved server endpoint (IP address or hostname).
    pub endpoint: String,
    /// The WireGuard port (default: [`DEFAULT_WIREGUARD_PORT`]).
    ///
    /// [`DEFAULT_WIREGUARD_PORT`]: crate::constants::DEFAULT_WIREGUARD_PORT
    pub port: u16,
}

impl WireGuardConfig {
    /// Generate a standard WireGuard `.conf` file string.
    ///
    /// Empty `address_ipv6`, `dns_ipv4`, or `dns_ipv6` fields are omitted
    /// from the output. An empty `preshared_key` is also omitted.
    pub fn to_conf(&self) -> String {
        let mut addresses: Vec<&str> = Vec::new();
        if !self.address_ipv4.is_empty() {
            addresses.push(&self.address_ipv4);
        }
        if !self.address_ipv6.is_empty() {
            addresses.push(&self.address_ipv6);
        }

        let mut dns_servers: Vec<&str> = Vec::new();
        if !self.dns_ipv4.is_empty() {
            dns_servers.push(&self.dns_ipv4);
        }
        if !self.dns_ipv6.is_empty() {
            dns_servers.push(&self.dns_ipv6);
        }

        let mut lines = vec!["[Interface]".to_string()];
        lines.push(format!("Address = {}", addresses.join(", ")));
        lines.push(format!("PrivateKey = {}", self.interface_private_key));
        if !dns_servers.is_empty() {
            lines.push(format!("DNS = {}", dns_servers.join(", ")));
        }

        lines.push(String::new());
        lines.push("[Peer]".to_string());
        lines.push(format!("PublicKey = {}", self.peer_public_key));
        if !self.preshared_key.is_empty() {
            lines.push(format!("PresharedKey = {}", self.preshared_key));
        }
        lines.push(format!("Endpoint = {}:{}", self.endpoint, self.port));
        lines.push("AllowedIPs = 0.0.0.0/0, ::/0".to_string());
        lines.push("PersistentKeepalive = 15".to_string());

        lines.join("\n") + "\n"
    }
}

/// Information about a single AirVPN server, extracted from the manifest.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    /// The display name of the server (e.g. "Algorab").
    pub name: String,
    /// The server's IP addresses. Entry IPs are preferred; exit IPs are
    /// used as a fallback.
    pub ips: Vec<String>,
}

/// Extract a [`WireGuardConfig`] from a `<user>` XML node.
///
/// `key_name` selects which `<key>` element within the user profile to use.
/// If no key with that name exists but other keys are present, the first
/// key is used as a fallback.
pub fn extract_wg_config(user_node: roxmltree::Node, key_name: &str) -> Result<WireGuardConfig> {
    let mut selected_key: Option<roxmltree::Node> = None;

    for key_node in user_node.descendants().filter(|n| n.has_tag_name("key")) {
        if key_node.attribute("name") == Some(key_name) {
            selected_key = Some(key_node);
            break;
        }
        if selected_key.is_none() {
            selected_key = Some(key_node);
        }
    }

    let key = selected_key.ok_or_else(|| {
        Error::Wireguard(format!("no key named '{}' found in user profile", key_name))
    })?;

    Ok(WireGuardConfig {
        interface_private_key: key.attribute("wg_private_key").unwrap_or("").to_string(),
        peer_public_key: user_node.attribute("wg_public_key").unwrap_or("").to_string(),
        preshared_key: key.attribute("wg_preshared").unwrap_or("").to_string(),
        address_ipv4: key.attribute("wg_ipv4").unwrap_or("").to_string(),
        address_ipv6: key.attribute("wg_ipv6").unwrap_or("").to_string(),
        dns_ipv4: key.attribute("wg_dns_ipv4").unwrap_or("").to_string(),
        dns_ipv6: key.attribute("wg_dns_ipv6").unwrap_or("").to_string(),
        endpoint: String::new(),
        port: crate::constants::DEFAULT_WIREGUARD_PORT,
    })
}

/// Look up a server by name (case-insensitive) in the manifest XML.
///
/// Entry IPs (`ips_entry`) are preferred; exit IPs (`ips_exit`) are used
/// as a fallback if no entry IPs are listed.
pub fn find_server(manifest: roxmltree::Node, server_name: &str) -> Option<ServerInfo> {
    for srv in manifest.descendants().filter(|n| n.has_tag_name("server")) {
        if srv
            .attribute("name")
            .map_or(false, |n| n.eq_ignore_ascii_case(server_name))
        {
            let ips_entry: Vec<String> = srv
                .attribute("ips_entry")
                .map(|s| {
                    s.split(',')
                        .map(|ip| ip.trim().to_string())
                        .filter(|ip| !ip.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            let ips_exit: Vec<String> = srv
                .attribute("ips_exit")
                .map(|s| {
                    s.split(',')
                        .map(|ip| ip.trim().to_string())
                        .filter(|ip| !ip.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            let ips = if !ips_entry.is_empty() {
                ips_entry
            } else {
                ips_exit
            };
            return Some(ServerInfo {
                name: srv.attribute("name").unwrap_or("").to_string(),
                ips,
            });
        }
    }
    None
}

/// List all available server names from the manifest XML, sorted case-insensitively.
pub fn list_servers(manifest: roxmltree::Node) -> Vec<String> {
    let mut names: Vec<String> = manifest
        .descendants()
        .filter(|n| n.has_tag_name("server"))
        .filter_map(|n| n.attribute("name").map(|s| s.to_string()))
        .collect();
    names.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
    names
}

/// Resolve a server endpoint IP address from the manifest.
///
/// If `server_name` is `Some`, looks up the named server and returns its
/// first entry IP, falling back to the server name itself. If `server_name`
/// is `None`, returns the first server's entry IP or an empty string if
/// no servers exist in the manifest.
pub fn resolve_endpoint(manifest: roxmltree::Node, server_name: Option<&str>) -> String {
    if let Some(name) = server_name {
        if let Some(srv) = find_server(manifest, name) {
            if !srv.ips.is_empty() {
                return srv.ips[0].clone();
            }
            return srv.name;
        }
        return name.to_string();
    }

    let first_srv = manifest.descendants().find(|n| n.has_tag_name("server"));

    if let Some(srv) = first_srv {
        let ips: Vec<String> = srv
            .attribute("ips_entry")
            .map(|s| {
                s.split(',')
                    .map(|ip| ip.trim().to_string())
                    .filter(|ip| !ip.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        if !ips.is_empty() {
            return ips[0].clone();
        }
        return srv.attribute("name").unwrap_or("").to_string();
    }

    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manifest_xml() -> &'static str {
        r#"<manifest auth_rsa_modulus="mod" auth_rsa_exponent="exp">
            <urls>
                <url address="https://example.com/api"/>
            </urls>
            <servers>
                <server name="Algorab" ips_entry="10.0.0.1,10.0.0.2" ips_exit="10.1.0.1"/>
                <server name="Aidar" ips_entry="10.0.1.1" ips_exit="10.1.1.1"/>
                <server name="Caph" ips_exit="10.1.2.1"/>
            </servers>
        </manifest>"#
    }

    fn make_user_xml() -> &'static str {
        r#"<user wg_public_key="server_pub_key">
            <keys>
                <key name="Default" wg_private_key="client_priv_key" wg_preshared="psk123" wg_ipv4="10.0.0.100/32" wg_ipv6="fd00::100/128" wg_dns_ipv4="10.0.0.1" wg_dns_ipv6="fd00::1"/>
                <key name="Alternate" wg_private_key="alt_priv_key" wg_preshared="alt_psk" wg_ipv4="10.0.0.200/32" wg_ipv6="" wg_dns_ipv4="" wg_dns_ipv6=""/>
            </keys>
        </user>"#
    }

    #[test]
    fn test_to_conf_full() {
        let config = WireGuardConfig {
            interface_private_key: "priv_key".into(),
            peer_public_key: "pub_key".into(),
            preshared_key: "psk".into(),
            address_ipv4: "10.0.0.100/32".into(),
            address_ipv6: "fd00::100/128".into(),
            dns_ipv4: "10.0.0.1".into(),
            dns_ipv6: "fd00::1".into(),
            endpoint: "10.0.0.1".into(),
            port: 51820,
        };
        let conf = config.to_conf();
        assert!(conf.contains("[Interface]"));
        assert!(conf.contains("Address = 10.0.0.100/32, fd00::100/128"));
        assert!(conf.contains("PrivateKey = priv_key"));
        assert!(conf.contains("DNS = 10.0.0.1, fd00::1"));
        assert!(conf.contains("[Peer]"));
        assert!(conf.contains("PublicKey = pub_key"));
        assert!(conf.contains("PresharedKey = psk"));
        assert!(conf.contains("Endpoint = 10.0.0.1:51820"));
        assert!(conf.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        assert!(conf.contains("PersistentKeepalive = 15"));
    }

    #[test]
    fn test_to_conf_minimal_fields() {
        let config = WireGuardConfig {
            interface_private_key: "priv_key".into(),
            peer_public_key: "pub_key".into(),
            preshared_key: String::new(),
            address_ipv4: "10.0.0.100/32".into(),
            address_ipv6: String::new(),
            dns_ipv4: String::new(),
            dns_ipv6: String::new(),
            endpoint: "1.2.3.4".into(),
            port: 1637,
        };
        let conf = config.to_conf();
        assert!(!conf.contains("PresharedKey"));
        assert!(!conf.contains("DNS"));
        assert!(conf.contains("Address = 10.0.0.100/32"));
        assert!(conf.contains("Endpoint = 1.2.3.4:1637"));
    }

    #[test]
    fn test_extract_wg_config_default_key() {
        let doc = roxmltree::Document::parse(make_user_xml()).unwrap();
        let config = extract_wg_config(doc.root_element(), "Default").unwrap();
        assert_eq!(config.interface_private_key, "client_priv_key");
        assert_eq!(config.peer_public_key, "server_pub_key");
        assert_eq!(config.preshared_key, "psk123");
        assert_eq!(config.address_ipv4, "10.0.0.100/32");
        assert_eq!(config.address_ipv6, "fd00::100/128");
        assert_eq!(config.dns_ipv4, "10.0.0.1");
        assert_eq!(config.dns_ipv6, "fd00::1");
    }

    #[test]
    fn test_extract_wg_config_alternate_key() {
        let doc = roxmltree::Document::parse(make_user_xml()).unwrap();
        let config = extract_wg_config(doc.root_element(), "Alternate").unwrap();
        assert_eq!(config.interface_private_key, "alt_priv_key");
        assert_eq!(config.preshared_key, "alt_psk");
    }

    #[test]
    fn test_extract_wg_config_fallback_to_first_key() {
        let doc = roxmltree::Document::parse(make_user_xml()).unwrap();
        let config = extract_wg_config(doc.root_element(), "NonexistentKey").unwrap();
        assert_eq!(config.interface_private_key, "client_priv_key");
    }

    #[test]
    fn test_extract_wg_config_no_keys_at_all() {
        let doc = roxmltree::Document::parse(r#"<user wg_public_key="pk"></user>"#).unwrap();
        let result = extract_wg_config(doc.root_element(), "Default");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no key named"));
    }

    #[test]
    fn test_find_server_case_insensitive() {
        let doc = roxmltree::Document::parse(make_manifest_xml()).unwrap();
        let srv = find_server(doc.root_element(), "algorab").unwrap();
        assert_eq!(srv.name, "Algorab");
        assert_eq!(srv.ips, vec!["10.0.0.1", "10.0.0.2"]);
    }

    #[test]
    fn test_find_server_exact_case() {
        let doc = roxmltree::Document::parse(make_manifest_xml()).unwrap();
        let srv = find_server(doc.root_element(), "Aidar").unwrap();
        assert_eq!(srv.name, "Aidar");
        assert_eq!(srv.ips, vec!["10.0.1.1"]);
    }

    #[test]
    fn test_find_server_fallback_to_exit_ips() {
        let doc = roxmltree::Document::parse(make_manifest_xml()).unwrap();
        let srv = find_server(doc.root_element(), "Caph").unwrap();
        assert_eq!(srv.ips, vec!["10.1.2.1"]);
    }

    #[test]
    fn test_find_server_not_found() {
        let doc = roxmltree::Document::parse(make_manifest_xml()).unwrap();
        assert!(find_server(doc.root_element(), "NonExistent").is_none());
    }

    #[test]
    fn test_list_servers_sorted() {
        let doc = roxmltree::Document::parse(make_manifest_xml()).unwrap();
        let servers = list_servers(doc.root_element());
        assert_eq!(servers, vec!["Aidar", "Algorab", "Caph"]);
    }

    #[test]
    fn test_resolve_endpoint_named_server() {
        let doc = roxmltree::Document::parse(make_manifest_xml()).unwrap();
        let result = resolve_endpoint(doc.root_element(), Some("Algorab"));
        assert_eq!(result, "10.0.0.1");
    }

    #[test]
    fn test_resolve_endpoint_named_server_no_entry_ips() {
        let doc = roxmltree::Document::parse(make_manifest_xml()).unwrap();
        let result = resolve_endpoint(doc.root_element(), Some("Caph"));
        assert_eq!(result, "10.1.2.1");
    }

    #[test]
    fn test_resolve_endpoint_unknown_server_falls_back_to_name() {
        let doc = roxmltree::Document::parse(make_manifest_xml()).unwrap();
        let result = resolve_endpoint(doc.root_element(), Some("UnknownServer"));
        assert_eq!(result, "UnknownServer");
    }

    #[test]
    fn test_resolve_endpoint_none_returns_first_server_ip() {
        let doc = roxmltree::Document::parse(make_manifest_xml()).unwrap();
        let result = resolve_endpoint(doc.root_element(), None);
        assert_eq!(result, "10.0.0.1");
    }

    #[test]
    fn test_resolve_endpoint_empty_manifest() {
        let doc = roxmltree::Document::parse("<manifest></manifest>").unwrap();
        let result = resolve_endpoint(doc.root_element(), None);
        assert!(result.is_empty());
    }
}
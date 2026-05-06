//! High-level AirVPN client with a builder-pattern API.
//!
//! The entry point is [`AirVPN::builder()`], which returns an [`AirVPNBuilder`].
//! Configure credentials, server, key name, port, etc. on the builder, then
//! call [`AirVPNBuilder::build`] to authenticate, fetch the profile, and
//! produce a complete [`WireGuardConfig`].
//!
//! For the public status API (no auth required), use [`AirVPN::fetch_status`].
//!
//! # Example
//!
//! ```no_run
//! use airvpn::AirVPN;
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

use std::time::Duration;

use log::warn;

use crate::constants::{
    DEFAULT_BOOTSTRAP_URLS, DEFAULT_RSA_EXPONENT, DEFAULT_RSA_MODULUS, DEFAULT_WIREGUARD_PORT,
    DOCUMENT_VERSION,
};
use crate::errors::{Error, Result};
use crate::protocol;
use crate::wireguard::{self, WireGuardConfig};

/// Builder for configuring and executing an AirVPN authentication + config fetch.
///
/// Obtain one via [`AirVPN::builder()`], then chain setter methods and finish
/// with [`build`](AirVPNBuilder::build).
///
/// # Defaults
///
/// | Field | Default |
/// |-------|---------|
/// | `key_name` | `"Default"` |
/// | `port` | `51820` |
/// | `bootstrap_urls` | [`DEFAULT_BOOTSTRAP_URLS`] |
/// | `timeout` | 15 seconds |
/// | RSA modulus/exponent | [`DEFAULT_RSA_MODULUS`] / [`DEFAULT_RSA_EXPONENT`] |
///
/// [`DEFAULT_BOOTSTRAP_URLS`]: crate::constants::DEFAULT_BOOTSTRAP_URLS
/// [`DEFAULT_RSA_MODULUS`]: crate::constants::DEFAULT_RSA_MODULUS
/// [`DEFAULT_RSA_EXPONENT`]: crate::constants::DEFAULT_RSA_EXPONENT
#[derive(Clone)]
pub struct AirVPNBuilder {
    username: Option<String>,
    password: Option<String>,
    server: Option<String>,
    key_name: String,
    port: u16,
    bootstrap_urls: Option<Vec<String>>,
    timeout: Duration,
    rsa_modulus: Option<String>,
    rsa_exponent: Option<String>,
}

impl AirVPNBuilder {
    /// Set the AirVPN username and password.
    ///
    /// Required. Calling [`build`](AirVPNBuilder::build) without credentials
    /// will return [`Error::MissingCredentials`].
    pub fn credentials(mut self, username: &str, password: &str) -> Self {
        self.username = Some(username.to_string());
        self.password = Some(password.to_string());
        self
    }

    /// Set the target server name (e.g. `"Algorab"`).
    ///
    /// If omitted, the first server in the manifest is used.
    pub fn server(mut self, server: &str) -> Self {
        self.server = Some(server.to_string());
        self
    }

    /// Set the WireGuard key profile name (defaults to `"Default"`).
    ///
    /// AirVPN supports multiple key profiles per account. This selects which
    /// one to use when extracting the WireGuard configuration.
    pub fn key_name(mut self, key_name: &str) -> Self {
        self.key_name = key_name.to_string();
        self
    }

    /// Set the WireGuard endpoint port (defaults to `51820`).
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Override the default bootstrap server URLs.
    ///
    /// The client will try each URL in order until one responds. After the
    /// manifest is fetched, the URL list is updated from the server.
    pub fn bootstrap_urls(mut self, urls: Vec<String>) -> Self {
        self.bootstrap_urls = Some(urls);
        self
    }

    /// Set the HTTP request timeout (defaults to 15 seconds).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Authenticate with AirVPN, fetch the manifest and user profile, and
    /// creates a [`WireGuardConfig`].
    ///
    /// This process:
    ///
    /// 1. Encrypts a `manifest` request with the current AirVPN RSA/AES keys.
    /// 2. Tries each bootstrap URL until one succeeds.
    /// 3. Decrypts and parses the XML manifest.
    /// 4. Updates RSA keys and bootstrap URLs from the manifest.
    /// 5. Repeats with a `user` request using updated keys.
    /// 6. Extracts WireGuard config from the user profile.
    /// 7. Resolves the server endpoint from the manifest.
    pub async fn build(self) -> Result<WireGuardConfig> {
        let username = self.username.ok_or(Error::MissingCredentials)?;
        let password = self.password.ok_or(Error::MissingCredentials)?;

        let rsa_modulus = self
            .rsa_modulus
            .unwrap_or_else(|| DEFAULT_RSA_MODULUS.to_string());
        let rsa_exponent = self
            .rsa_exponent
            .unwrap_or_else(|| DEFAULT_RSA_EXPONENT.to_string());
        let bootstrap_urls = self
            .bootstrap_urls
            .unwrap_or_else(|| DEFAULT_BOOTSTRAP_URLS.iter().map(|s| s.to_string()).collect());

        for url in &bootstrap_urls {
            if url.starts_with("http://") {
                warn!("Bootstrap URL \"{url}\" uses HTTP instead of HTTPS; this exposes encrypted credentials to network attackers");
            }
        }

        let http_client = reqwest::Client::builder()
            .timeout(self.timeout)
            .build()?;

        let manifest_text = fetch(
            &http_client,
            "manifest",
            &username,
            &password,
            &rsa_modulus,
            &rsa_exponent,
            &bootstrap_urls,
        )
        .await?;
        let manifest_doc = roxmltree::Document::parse(&manifest_text)?;

        let root = manifest_doc.root_element();
        if let Some(error) = root.attribute("error") {
            if !error.is_empty() {
                return Err(Error::Server(error.to_string()));
            }
        }

        let mut updated_modulus = rsa_modulus;
        let mut updated_exponent = rsa_exponent;
        if let Some(modulus) = root.attribute("auth_rsa_modulus") {
            if !modulus.is_empty() {
                updated_modulus = modulus.to_string();
            }
        }
        if let Some(exponent) = root.attribute("auth_rsa_exponent") {
            if !exponent.is_empty() {
                updated_exponent = exponent.to_string();
            }
        }

        let mut updated_urls = bootstrap_urls;
        let urls_node = root.descendants().find(|n| n.has_tag_name("urls"));
        if let Some(urls_node) = urls_node {
            let mut new_urls: Vec<String> = Vec::new();
            for url_node in urls_node.descendants().filter(|n| n.has_tag_name("url")) {
                if let Some(addr) = url_node.attribute("address") {
                    let addr = addr.trim().to_string();
                    if !addr.is_empty() {
                        new_urls.push(addr);
                    }
                }
            }
            if !new_urls.is_empty() {
                let old_urls: Vec<String> = updated_urls
                    .into_iter()
                    .filter(|u| !new_urls.contains(u))
                    .collect();
                new_urls.extend(old_urls);
                updated_urls = new_urls;
            }

            for url in updated_urls.iter().filter(|u| u.starts_with("http://")) {
                warn!("Server-provided bootstrap URL \"{url}\" uses HTTP instead of HTTPS; this exposes encrypted credentials to network attackers");
            }
        }

        let user_text = fetch(
            &http_client,
            "user",
            &username,
            &password,
            &updated_modulus,
            &updated_exponent,
            &updated_urls,
        )
        .await?;
        let user_doc = roxmltree::Document::parse(&user_text)?;

        let user_root = user_doc.root_element();
        let user_node = if user_root.has_tag_name("user") {
            user_root
        } else {
            user_root
                .descendants()
                .find(|n| n.has_tag_name("user"))
                .ok_or_else(|| Error::Wireguard("no <user> node in response".into()))?
        };

        if let Some(error) = user_node.attribute("error") {
            if !error.is_empty() {
                return Err(Error::Server(error.to_string()));
            }
        }

        let mut config = wireguard::extract_wg_config(user_node, &self.key_name)?;
        let endpoint = wireguard::resolve_endpoint(root, self.server.as_deref());
        config.endpoint = endpoint;
        config.port = self.port;

        Ok(config)
    }
}

impl Default for AirVPNBuilder {
    fn default() -> Self {
        Self {
            username: None,
            password: None,
            server: None,
            key_name: "Default".to_string(),
            port: DEFAULT_WIREGUARD_PORT,
            bootstrap_urls: None,
            timeout: Duration::from_secs(15),
            rsa_modulus: None,
            rsa_exponent: None,
        }
    }
}

/// Entry point for the AirVPN library.
///
/// Refer to [`AirVPN::builder()`] for building an authenticated request, or
/// [`AirVPN::fetch_status()`] for the public status API.
pub struct AirVPN;

impl AirVPN {
    /// Create a new [`AirVPNBuilder`] configured with defaults.
    pub fn builder() -> AirVPNBuilder {
        AirVPNBuilder::default()
    }

    /// Fetch the current server status from the public AirVPN API.
    ///
    /// This does not require authentication.
    pub async fn fetch_status() -> Result<crate::status::StatusResponse> {
        crate::status::fetch_status().await
    }
}

/// Encrypt and POST an API request, trying each bootstrap URL.
async fn fetch(
    http_client: &reqwest::Client,
    action: &str,
    login: &str,
    password: &str,
    rsa_modulus: &str,
    rsa_exponent: &str,
    bootstrap_urls: &[String],
) -> Result<String> {
    let parameters: Vec<(String, String)> = vec![
        ("act".into(), action.into()),
        ("login".into(), login.into()),
        ("password".into(), password.into()),
        ("software".into(), format!("EddieCLI_{}", DOCUMENT_VERSION)),
        ("system".into(), "linux".into()),
        ("arch".into(), "x86_64".into()),
        ("version".into(), DOCUMENT_VERSION.into()),
    ];

    let enc = protocol::encrypt_request(&parameters, rsa_modulus, rsa_exponent)?;
    let body = protocol::build_post_body(&enc.s, &enc.d);

    let mut last_error: Option<String> = None;
    for url in bootstrap_urls {
        match try_fetch(http_client, url, &body, &enc.aes_key, &enc.aes_iv).await {
            Ok(xml_text) => return Ok(xml_text),
            Err(e) => {
                last_error = Some(e.to_string());
                continue;
            }
        }
    }

    Err(Error::AllServersFailed(
        last_error.unwrap_or_else(|| "unknown error".into()),
    ))
}

// Attempt a single POST to a bootstrap URL and decrypt the response.
async fn try_fetch(
    http_client: &reqwest::Client,
    url: &str,
    body: &str,
    aes_key: &[u8],
    aes_iv: &[u8],
) -> Result<String> {
    let resp = http_client
        .post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.to_string())
        .send()
        .await?;

    if resp.status() != reqwest::StatusCode::OK {
        return Err(Error::HttpStatus(resp.status().as_u16()));
    }

    let encrypted_response = resp.bytes().await?;

    let xml_bytes = protocol::decrypt_response(&encrypted_response, aes_key, aes_iv)?;
    let xml_text = std::str::from_utf8(&xml_bytes)?;

    Ok(xml_text.to_string())
}

#[cfg(test)]
mod tests { // generated tests
    use super::*;

    #[test]
    fn test_builder_default_values() {
        let builder = AirVPNBuilder::default();
        assert!(builder.username.is_none());
        assert!(builder.password.is_none());
        assert!(builder.server.is_none());
        assert_eq!(builder.key_name, "Default");
        assert_eq!(builder.port, 51820);
        assert!(builder.bootstrap_urls.is_none());
        assert_eq!(builder.timeout, Duration::from_secs(15));
    }

    #[test]
    fn test_builder_credentials() {
        let builder = AirVPNBuilder::default().credentials("user", "pass");
        assert_eq!(builder.username.as_deref(), Some("user"));
        assert_eq!(builder.password.as_deref(), Some("pass"));
    }

    #[test]
    fn test_builder_server() {
        let builder = AirVPNBuilder::default().server("Algorab");
        assert_eq!(builder.server.as_deref(), Some("Algorab"));
    }

    #[test]
    fn test_builder_key_name() {
        let builder = AirVPNBuilder::default().key_name("MyKey");
        assert_eq!(builder.key_name, "MyKey");
    }

    #[test]
    fn test_builder_port() {
        let builder = AirVPNBuilder::default().port(1637);
        assert_eq!(builder.port, 1637);
    }

    #[test]
    fn test_builder_bootstrap_urls() {
        let builder = AirVPNBuilder::default()
            .bootstrap_urls(vec!["http://test.com".to_string()]);
        assert_eq!(builder.bootstrap_urls.as_ref().map(|v| v.as_slice()), Some(&["http://test.com".to_string()][..]));
    }

    #[test]
    fn test_builder_timeout() {
        let builder = AirVPNBuilder::default().timeout(Duration::from_secs(30));
        assert_eq!(builder.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_builder_chain() {
        let builder = AirVPNBuilder::default()
            .credentials("user", "pass")
            .server("Algorab")
            .key_name("AltKey")
            .port(1637)
            .timeout(Duration::from_secs(30));

        assert_eq!(builder.username.as_deref(), Some("user"));
        assert_eq!(builder.password.as_deref(), Some("pass"));
        assert_eq!(builder.server.as_deref(), Some("Algorab"));
        assert_eq!(builder.key_name, "AltKey");
        assert_eq!(builder.port, 1637);
        assert_eq!(builder.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_airvpn_builder_entry_point() {
        let builder = AirVPN::builder();
        assert!(builder.username.is_none());
    }

    #[test]
    fn test_build_without_credentials_returns_error() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            AirVPNBuilder::default().build().await
        });
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::MissingCredentials => {}
            e => panic!("expected MissingCredentials, got {:?}", e),
        }
    }
}
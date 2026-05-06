//! Default constants used by the AirVPN authentication protocol.
//!
//! These values are embedded in the official Eddie client and are required
//! for bootstrapping the initial connection before the manifest is fetched.

/// Default RSA public key modulus (base64-encoded).
///
/// Used to encrypt the first request before the manifest provides an updated key.
pub const DEFAULT_RSA_MODULUS: &str = "wuQXz7eZeEBwaaRsVK8iEHpueXoKyQzW8sr8qMUkZIcKtKv5iseXMrTbcGYGpRXdiqXp7FqrSjPSMDuRGaHfjWgjbnW4PwecmgJSfhkWt4xY8OnIwKkuI2Eo0MAa9lduPOQRKSfa9I1PBogIyEUrf7kSjcoJQgeY66D429m1BDWY3f65c+8HrCQ8qPg1GY+pSxuwp6+2dV7fd1tiKLQEoJg9NeWGW0he/DDkNSe4c8gFfHj3ANYwDhTQijb+VaVZqPmxVJIzLoE1JOom0/P8fKsvpx3cFOtDS4apiI+N7MyVAMcx5Jjk2AQ/tyDiybwwZ32fOqYJVGxs13guOlgI6h77QxqNIq2bGEjzSRZ4tem1uN7F8AoVKPls6yAUQK1cWM5AVu4apoNIFG+svS/2kmn0Nx8DRVDvKD+nOByXgqg01Y6r0Se8Tz9EEBTiEopdlKjmO1wlrmW3iWKeFIwZnHt2PMceJMqziV8rRGh9gUMLLJC9qdXCAS4vf5VVnZ+Pq3SK9pP87hOislIu4/Kcn06cotQChpVnALA83hFW5LXJvc85iloWJkuLGAV3CcAwoSA5CG1Uo2S76MM+GLLkVIqUk1PiJMTTlSw1SlMEflU4bZiZP8di5e2OJI6vOHjdM2oonpPi/Ul5KKmfp+jci+kGMs9+zOyjKFLVIKDE+Vc=";

/// Default RSA public key exponent (base64-encoded).
pub const DEFAULT_RSA_EXPONENT: &str = "AQAB";

/// Default bootstrap server URLs.
///
/// The client will attempt each URL in order until one responds successfully.
/// After fetching the manifest, this list is updated with fresh URLs from the server.
/// Should be HTTPS to prevent man-in-the-middle attack, but users can change this if they want
pub const DEFAULT_BOOTSTRAP_URLS: &[&str] = &[
    "https://bootme.org",
];

/// Eddie client version string sent in requests.
pub const DOCUMENT_VERSION: &str = "295";

/// Default WireGuard port used for the `Endpoint` line in generated configs.
pub const DEFAULT_WIREGUARD_PORT: u16 = 51820;
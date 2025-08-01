use crate::error::BrowserVoyageResult;
use serde::{Deserialize, Serialize};

/// Information about a web browser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserInfo {
    /// The name of the browser (e.g., "Chrome").
    pub name: String,
    /// The vendor of the browser (e.g., "Google").
    pub vendor: String,
    /// The platform the browser is running on (e.g., "Windows").
    pub platform: String,
}

/// A container for all data extracted from a single browser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedData {
    /// Information about the browser.
    pub browser: BrowserInfo,
    /// A vector of profiles found in the browser.
    pub profiles: Vec<ProfileData>,
}

/// A container for all data extracted from a single browser profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileData {
    /// The name of the profile (e.g., "Default").
    pub name: String,
    /// The path to the profile directory.
    pub path: String,
    /// A vector of cookies found in the profile.
    pub cookies: Vec<Cookie>,
    /// A vector of credentials found in the profile.
    pub credentials: Vec<Credential>,
}

/// A representation of a browser cookie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    /// The host of the cookie (e.g., "google.com").
    pub host: String,
    /// The name of the cookie (e.g., "NID").
    pub name: String,
    /// The value of the cookie.
    pub value: String,
    /// The path of the cookie (e.g., "/").
    pub path: String,
    /// The expiration date of the cookie as a Unix timestamp.
    pub expiry: i64,
    /// Whether the cookie is secure.
    pub is_secure: bool,
}

/// A representation of a saved credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// The URL of the website the credential is for.
    pub url: String,
    /// The username.
    pub username: String,
    /// The password.
    pub password: String,
}

/// A trait for browser-specific data extractors.
pub trait BrowserExtractor {
    /// Returns the name of the browser.
    fn name(&self) -> &str;
    /// Extracts all available data from the browser.
    fn extract(&mut self) -> BrowserVoyageResult<ExtractedData>;
}

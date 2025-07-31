use crate::error::BrowserVoyageResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserInfo {
    pub name: String,
    pub vendor: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedData {
    pub browser: BrowserInfo,
    pub profiles: Vec<ProfileData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileData {
    pub name: String,
    pub path: String,
    pub cookies: Vec<Cookie>,
    pub credentials: Vec<Credential>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub host: String,
    pub name: String,
    pub value: String,
    pub path: String,
    pub expiry: i64,
    pub is_secure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub url: String,
    pub username: String,
    pub password: String,
}

pub trait BrowserExtractor {
    fn name(&self) -> &str;
    fn extract(&mut self) -> BrowserVoyageResult<ExtractedData>;
}

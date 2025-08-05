//! Common types and utilities for Chrome-based browser extractors

use crate::browser_extractor::{
    BrowserExtractor, BrowserInfo, Cookie, Credential, ExtractedData, ProfileData,
};
use crate::common::{BrowserProfile, DatabaseOperations, DefaultDatabaseOps};
use crate::error::BrowserVoyageResult;
use serde::Deserialize;
use std::path::Path;
use tracing::{debug, info, warn};

/// Chrome browser configuration for different variants
#[derive(Debug, Clone)]
pub struct ChromeBrowserConfig {
    pub name: String,
    pub vendor: String,
    pub data_dir_name: String,
    pub keychain_service: String,
}

impl ChromeBrowserConfig {
    pub fn chrome() -> Self {
        Self {
            name: "Chrome".to_string(),
            vendor: "Google".to_string(),
            data_dir_name: "Google/Chrome".to_string(),
            keychain_service: "Chrome Safe Storage".to_string(),
        }
    }

    pub fn edge() -> Self {
        Self {
            name: "Edge".to_string(),
            vendor: "Microsoft".to_string(),
            data_dir_name: "Microsoft Edge".to_string(),
            keychain_service: "Microsoft Edge Safe Storage".to_string(),
        }
    }

    pub fn brave() -> Self {
        Self {
            name: "Brave".to_string(),
            vendor: "Brave Software".to_string(),
            data_dir_name: "BraveSoftware/Brave-Browser".to_string(),
            keychain_service: "Brave Safe Storage".to_string(),
        }
    }

    pub fn chromium() -> Self {
        Self {
            name: "Chromium".to_string(),
            vendor: "The Chromium Authors".to_string(),
            data_dir_name: "Chromium".to_string(),
            keychain_service: "Chromium Safe Storage".to_string(),
        }
    }
}

/// Common Chrome data structures
#[derive(Debug, Deserialize)]
pub struct LocalState {
    pub os_crypt: OsCrypt,
}

#[derive(Debug, Deserialize)]
pub struct OsCrypt {
    pub encrypted_key: Option<String>,
    pub app_bound_encrypted_key: Option<String>,
}

/// Chrome cookie structure from database
#[derive(Debug)]
pub struct ChromeCookie {
    pub host_key: String,
    pub name: String,
    pub value: Option<String>,
    pub encrypted_value: Vec<u8>,
    pub path: String,
    pub expires_utc: i64,
    pub is_secure: bool,
    pub is_httponly: Option<bool>,
}

impl From<ChromeCookie> for Cookie {
    fn from(chrome_cookie: ChromeCookie) -> Self {
        Cookie {
            host: chrome_cookie.host_key,
            name: chrome_cookie.name,
            value: chrome_cookie.value.unwrap_or_default(),
            path: chrome_cookie.path,
            expiry: chrome_cookie.expires_utc,
            is_secure: chrome_cookie.is_secure,
        }
    }
}

/// Chrome credential structure from database
#[derive(Debug)]
pub struct ChromeCredential {
    pub origin_url: String,
    pub username_value: String,
    pub password_value: Vec<u8>,
}

impl From<ChromeCredential> for Credential {
    fn from(chrome_cred: ChromeCredential) -> Self {
        Credential {
            url: chrome_cred.origin_url,
            username: chrome_cred.username_value,
            password: String::from_utf8_lossy(&chrome_cred.password_value).to_string(),
        }
    }
}

/// Base trait for Chrome-based extractors
pub trait ChromeExtractorBase: BrowserExtractor {
    /// Get the browser configuration
    fn get_config(&self) -> &ChromeBrowserConfig;

    /// Get the user data path
    fn get_user_data_path(&self) -> &Path;

    /// Decrypt Chrome data using platform-specific methods
    fn decrypt_chrome_data(&self, encrypted_data: &[u8]) -> BrowserVoyageResult<Vec<u8>>;

    /// Get Chrome master key for decryption
    fn get_master_key(&self) -> BrowserVoyageResult<Vec<u8>>;

    /// Extract cookies from Chrome database
    fn extract_cookies(&self, profile_path: &Path) -> BrowserVoyageResult<Vec<Cookie>> {
        let cookies_db = profile_path.join("Cookies");
        if !cookies_db.exists() {
            debug!("Cookies database not found at: {:?}", cookies_db);
            return Ok(Vec::new());
        }

        let db_ops = DefaultDatabaseOps;
        let conn = db_ops.open_database(&cookies_db)?;

        let mut stmt = conn.prepare(
            "SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure, is_httponly 
             FROM cookies"
        )?;

        let cookie_iter = stmt.query_map([], |row| {
            Ok(ChromeCookie {
                host_key: row.get(0)?,
                name: row.get(1)?,
                value: row.get(2)?,
                encrypted_value: row.get(3).unwrap_or_default(),
                path: row.get(4)?,
                expires_utc: row.get(5)?,
                is_secure: row.get(6)?,
                is_httponly: row.get(7)?,
            })
        })?;

        let mut cookies = Vec::new();
        for cookie_result in cookie_iter {
            if let Ok(mut chrome_cookie) = cookie_result {
                // If we have encrypted value and no plain value, try to decrypt
                if chrome_cookie.value.is_none() && !chrome_cookie.encrypted_value.is_empty() {
                    match self.decrypt_chrome_data(&chrome_cookie.encrypted_value) {
                        Ok(decrypted) => {
                            chrome_cookie.value =
                                Some(String::from_utf8_lossy(&decrypted).to_string());
                        }
                        Err(e) => {
                            warn!("Failed to decrypt cookie {}: {}", chrome_cookie.name, e);
                            continue;
                        }
                    }
                }

                if chrome_cookie.value.is_some() {
                    cookies.push(chrome_cookie.into());
                }
            }
        }

        info!(
            "Extracted {} cookies from {}",
            cookies.len(),
            self.get_config().name
        );
        Ok(cookies)
    }

    /// Extract credentials from Chrome database
    fn extract_credentials(&self, profile_path: &Path) -> BrowserVoyageResult<Vec<Credential>> {
        let login_db = profile_path.join("Login Data");
        if !login_db.exists() {
            debug!("Login Data database not found at: {:?}", login_db);
            return Ok(Vec::new());
        }

        let db_ops = DefaultDatabaseOps;
        let conn = db_ops.open_database(&login_db)?;

        let mut stmt = conn.prepare(
            "SELECT origin_url, username_value, password_value 
             FROM logins 
             WHERE blacklisted_by_user = 0",
        )?;

        let cred_iter = stmt.query_map([], |row| {
            Ok(ChromeCredential {
                origin_url: row.get(0)?,
                username_value: row.get(1)?,
                password_value: row.get(2).unwrap_or_default(),
            })
        })?;

        let mut credentials = Vec::new();
        for cred_result in cred_iter {
            if let Ok(mut chrome_cred) = cred_result {
                // Decrypt password
                if !chrome_cred.password_value.is_empty() {
                    match self.decrypt_chrome_data(&chrome_cred.password_value) {
                        Ok(decrypted) => {
                            chrome_cred.password_value = decrypted;
                            credentials.push(chrome_cred.into());
                        }
                        Err(e) => {
                            warn!(
                                "Failed to decrypt credential for {}: {}",
                                chrome_cred.origin_url, e
                            );
                        }
                    }
                }
            }
        }

        info!(
            "Extracted {} credentials from {}",
            credentials.len(),
            self.get_config().name
        );
        Ok(credentials)
    }

    /// Find all profiles for this Chrome browser
    fn find_profiles(&self) -> BrowserVoyageResult<Vec<BrowserProfile>> {
        let user_data_path = self.get_user_data_path();
        let mut profiles = Vec::new();

        // Check for Default profile
        let default_path = user_data_path.join("Default");
        if default_path.exists() && default_path.is_dir() {
            profiles.push(BrowserProfile::new(
                "Default".to_string(),
                default_path,
                true,
            ));
        }

        // Check for numbered profiles (Profile 1, Profile 2, etc.)
        for entry in std::fs::read_dir(user_data_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("Profile ") && name != "Default" {
                        profiles.push(BrowserProfile::new(name.to_string(), path, false));
                    }
                }
            }
        }

        Ok(profiles)
    }

    /// Default implementation of extract method using common logic
    fn extract_with_common_logic(&mut self) -> BrowserVoyageResult<ExtractedData> {
        let config = self.get_config().clone();
        let profiles = self.find_profiles()?;
        let mut profile_data = Vec::new();

        for profile in profiles {
            debug!("Processing profile: {} at {:?}", profile.name, profile.path);

            let cookies = self.extract_cookies(&profile.path)?;
            let credentials = self.extract_credentials(&profile.path)?;

            profile_data.push(ProfileData {
                name: profile.name.clone(),
                path: profile.path.to_string_lossy().to_string(),
                cookies,
                credentials,
            });
        }

        Ok(ExtractedData {
            browser: BrowserInfo {
                name: config.name,
                vendor: config.vendor,
                platform: std::env::consts::OS.to_string(),
            },
            profiles: profile_data,
        })
    }
}

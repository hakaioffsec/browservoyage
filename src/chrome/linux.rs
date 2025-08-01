use crate::browser_extractor::{
    BrowserExtractor, BrowserInfo, Cookie, Credential, ExtractedData, ProfileData,
};
use crate::error::{BrowserVoyageError, BrowserVoyageResult};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use directories::UserDirs;
use pbkdf2::pbkdf2_hmac;
use rusqlite::Connection;
use serde::Deserialize;

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, instrument};

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

#[derive(Debug)]
pub struct LinuxChromeExtractor {
    user_data_path: PathBuf,
    browser_name: String,
    keychain_service: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LocalState {
    os_crypt: OsCrypt,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct OsCrypt {
    encrypted_key: Option<String>,
}

/// Chrome cookie structure from database
#[derive(Debug)]
struct ChromeCookie {
    host_key: String,
    name: String,
    value: String,
    encrypted_value: Vec<u8>,
    path: String,
    expires_utc: i64,
    is_secure: bool,
}

/// Chrome credential structure from database
#[derive(Debug)]
struct ChromeCredential {
    origin_url: String,
    username_value: String,
    password_value: Vec<u8>,
}

/// Encryption mode for Chrome on Linux
#[derive(Debug)]
enum EncryptionMode {
    Basic,        // No encryption, fallback
    Gnome,        // GNOME Keyring
    Kwallet,      // KDE Wallet
}

impl LinuxChromeExtractor {
    pub fn new(browser_name: &str, keychain_service: &str) -> Self {
        let user_data_path = Self::get_user_data_path(browser_name);

        Self {
            user_data_path,
            browser_name: browser_name.to_string(),
            keychain_service: keychain_service.to_string(),
        }
    }

    pub fn chrome() -> Self {
        Self::new("Chrome", "Chrome Safe Storage")
    }

    pub fn brave() -> Self {
        Self::new("Brave", "Brave Safe Storage")
    }

    pub fn chromium() -> Self {
        Self::new("Chromium", "Chromium Safe Storage")
    }

    fn get_user_data_path(browser_name: &str) -> PathBuf {
        if let Some(user_dirs) = UserDirs::new() {
            let home = user_dirs.home_dir();
            match browser_name {
                "Chrome" => home.join(".config/google-chrome"),
                "Brave" => home.join(".config/BraveSoftware/Brave-Browser"),
                "Chromium" => home.join(".config/chromium"),
                _ => home.join(format!(".config/{}", browser_name.to_lowercase())),
            }
        } else {
            // Fallback to using HOME environment variable
            let home = env::var("HOME").unwrap_or_else(|_| "/home/unknown".to_string());
            let config_dir = match browser_name {
                "Chrome" => "google-chrome".to_string(),
                "Brave" => "BraveSoftware/Brave-Browser".to_string(),
                "Chromium" => "chromium".to_string(),
                _ => browser_name.to_lowercase(),
            };
            PathBuf::from(home).join(format!(".config/{config_dir}"))
        }
    }

    /// Detect the encryption mode available on the system
    fn detect_encryption_mode(&self) -> EncryptionMode {
        // Check for GNOME Keyring
        if env::var("GNOME_KEYRING_CONTROL").is_ok() || 
           Command::new("gnome-keyring").arg("--version").output().is_ok() {
            return EncryptionMode::Gnome;
        }

        // Check for KDE Wallet
        if Command::new("kwalletd5").arg("--version").output().is_ok() ||
           Command::new("kwallet-query").arg("--help").output().is_ok() {
            return EncryptionMode::Kwallet;
        }

        // Fallback to basic mode
        EncryptionMode::Basic
    }

    /// Get the master password from the keyring
    fn get_keyring_password(&self, mode: &EncryptionMode) -> BrowserVoyageResult<String> {
        match mode {
            EncryptionMode::Gnome => self.get_gnome_keyring_password(),
            EncryptionMode::Kwallet => self.get_kwallet_password(),
            EncryptionMode::Basic => Ok("peanuts".to_string()),
        }
    }

    /// Get password from GNOME Keyring (libsecret)
    ///
    /// This follows the same lookup strategy used by Chromium:
    /// 1. Try schema "chrome_libsecret_os_crypt_password_v2"
    /// 2. Fallback to schema "chrome_libsecret_os_crypt_password_v1"
    ///    Both queries are performed with the attribute `application=<browser>` where
    ///    `<browser>` is "chrome", "brave" or "chromium" depending on the target.
    ///
    /// If no password can be found the method returns the weak default "peanuts"
    /// which allows decryption of very old Chrome versions that had no keyring
    /// support.
    fn get_gnome_keyring_password(&self) -> BrowserVoyageResult<String> {
        // Determine the application name used in libsecret attributes
        let crypt_name = match self.browser_name.as_str() {
            "Chrome" => "chrome",
            "Brave" => "brave",
            "Chromium" => "chromium",
            _ => "chrome",
        };

        // Schemas Chromium may have stored the secret under
        const SCHEMAS: [&str; 2] = [
            "chrome_libsecret_os_crypt_password_v2",
            "chrome_libsecret_os_crypt_password_v1",
        ];

        for schema in SCHEMAS.iter() {
            let output_result = Command::new("secret-tool")
                .args([
                    "lookup",
                    "xdg:schema",
                    schema,
                    "application",
                    crypt_name,
                ])
                .output();

            match output_result {
                Ok(output) if output.status.success() => {
                    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !password.is_empty() {
                        debug!("Retrieved password from GNOME Keyring using schema {}", schema);
                        return Ok(password);
                    }
                }
                Ok(output) => {
                    debug!(
                        "secret-tool returned non-success status {} for schema {}: stdout='{}' stderr='{}'",
                        output.status,
                        schema,
                        String::from_utf8_lossy(&output.stdout).trim(),
                        String::from_utf8_lossy(&output.stderr).trim()
                    );
                }
                Err(e) => {
                    debug!("Failed to execute secret-tool for schema {}: {}", schema, e);
                }
            }
        }

        // If no password was obtained, default to "peanuts" like Chromium fallback
        Ok("peanuts".to_string())
    }

    /// Get password from KDE Wallet
    fn get_kwallet_password(&self) -> BrowserVoyageResult<String> {
        let output = Command::new("kwallet-query")
            .args([
                "kdewallet",
                "-f",
                &self.keychain_service,
                "-r",
                &self.keychain_service,
            ])
            .output()
            .map_err(|e| {
                debug!("Failed to execute kwallet-query: {}", e);
                BrowserVoyageError::AccessDenied(
                    "Failed to access KDE Wallet".to_string()
                )
            })?;

        if output.status.success() {
            let password = String::from_utf8_lossy(&output.stdout)
                .trim()
                .to_string();
            if !password.is_empty() {
                return Ok(password);
            }
        }

        // Fallback to peanuts
        Ok("peanuts".to_string())
    }

    /// Derive the encryption key using PBKDF2
    fn derive_key(&self, password: &str) -> BrowserVoyageResult<Vec<u8>> {
        let salt = b"saltysalt";
        let mut key = vec![0u8; 16]; // AES-128 key

        pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), salt, 1, &mut key);

        Ok(key)
    }

    /// Decrypt Chrome encrypted value
    fn decrypt_value(&self, value: &str, encrypted_value: &[u8], key: &[u8]) -> BrowserVoyageResult<(String, Vec<u8>)> {
        // If value is not empty, the cookie is not encrypted
        if !value.is_empty() {
            return Ok((String::new(), value.as_bytes().to_vec()));
        }
        
        if encrypted_value.is_empty() {
            return Ok((String::new(), Vec::new()));
        }

        // Chrome on Linux uses version prefixes like v10, v11, v20
        if encrypted_value.len() < 3 {
            return Err(BrowserVoyageError::DecryptionFailed(
                "Encrypted value too short".to_string()
            ));
        }

        let version_prefix = &encrypted_value[0..3];
        
        // Check for Chrome version prefixes
        // Common formats:
        // - ASCII: "v10", "v11", "v20" (bytes: ['v', '1', '0'], etc.)
        // - Binary: [0x76, 0x10], [0x76, 0x11], [0x76, 0x20]
        let version_str = String::from_utf8_lossy(version_prefix);
        let is_encrypted = version_str.starts_with("v1") || version_str.starts_with("v2");
        
        debug!("Cookie version prefix hex: {:02x?}, is_encrypted: {}, byte1: {}, byte2: {}", 
               version_prefix, is_encrypted, version_prefix[1], version_prefix[2]);
        
        if !is_encrypted {
            // Not encrypted, return the value field (not encrypted_value)
            debug!("Cookie not encrypted, returning value field");
            return Ok((String::new(), Vec::new()));
        }
        
        // Determine version string for later use
        let version = version_str.into_owned();

        // Remove version prefix (3 bytes)
        let ciphertext = &encrypted_value[3..];

        // Fixed IV of 16 spaces (0x20)
        let iv = vec![0x20u8; 16];

        // Decrypt using AES-128-CBC
        let cipher = Aes128CbcDec::new_from_slices(key, &iv)
            .map_err(|e| BrowserVoyageError::DecryptionFailed(format!("Cipher error: {e}")))?;

        let mut buffer = ciphertext.to_vec();
        let decrypted = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map_err(|e| BrowserVoyageError::DecryptionFailed(format!("Decryption error: {e}")))?;

        Ok((version, decrypted.to_vec()))
    }

    /// Get all Chrome profiles
    fn get_profiles(&self) -> BrowserVoyageResult<Vec<(String, PathBuf)>> {
        let mut profiles = Vec::new();

        // Always add Default profile
        let default_profile = self.user_data_path.join("Default");
        if default_profile.exists() {
            profiles.push(("Default".to_string(), default_profile));
        }

        // Look for additional profiles (Profile 1, Profile 2, etc.)
        if let Ok(entries) = std::fs::read_dir(&self.user_data_path) {
            for entry in entries.flatten() {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_dir() {
                        let path = entry.path();
                        if let Some(dir_name) = path.file_name() {
                            let name = dir_name.to_string_lossy();
                            if name.starts_with("Profile ") && name != "Profile State" {
                                profiles.push((name.to_string(), path));
                            }
                        }
                    }
                }
            }
        }

        if profiles.is_empty() {
            return Err(BrowserVoyageError::NoDataFound);
        }

        Ok(profiles)
    }

    /// Extract cookies from a Chrome profile
    fn extract_cookies(
        &self,
        profile_path: &Path,
        keys: &[Vec<u8>],
    ) -> BrowserVoyageResult<Vec<Cookie>> {
        let cookies_db = profile_path.join("Cookies");
        if !cookies_db.exists() {
            return Err(BrowserVoyageError::NoDataFound);
        }

        let conn = Connection::open_with_flags(
            &cookies_db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;

        let mut stmt = conn.prepare(
            "SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure 
             FROM cookies",
        )?;

        let cookie_iter = stmt.query_map([], |row| {
            Ok(ChromeCookie {
                host_key: row.get(0)?,
                name: row.get(1)?,
                value: row.get(2)?,
                encrypted_value: row.get(3)?,
                path: row.get(4)?,
                expires_utc: row.get(5)?,
                is_secure: row.get::<_, i32>(6)? != 0,
            })
        })?;

        let mut cookies = Vec::new();

        // Check database version
        if let Ok(version) = conn.query_row(
            "SELECT value FROM meta WHERE key = 'version'",
            [],
            |row| row.get::<_, i32>(0),
        ) {
            debug!("Chrome database version: {}", version);
        }

        for cookie_result in cookie_iter {
            match cookie_result {
                Ok(chrome_cookie) => {
                    let mut decrypted = false;
                    
                    // Try each key until one works
                    for (key_idx, key) in keys.iter().enumerate() {
                        match self.decrypt_value(&chrome_cookie.value, &chrome_cookie.encrypted_value, key) {
                            Ok((version, decrypted_data)) => {
                                // Check if we actually decrypted something
                                let final_value = if !decrypted_data.is_empty() {
                                    debug!("Decrypted cookie {} with key {} version: {}, data length: {}", 
                                        chrome_cookie.name, key_idx, version, decrypted_data.len());

                                    // Handle possible 32-byte domain hash prefix (v10/v11 with default key)
                                    let mut processed = decrypted_data.clone();
                                    if (version == "v10" || version == "v11") && processed.len() > 32 {
                                        use sha2::{Digest, Sha256};
                                        let mut hasher = Sha256::new();
                                        hasher.update(chrome_cookie.host_key.as_bytes());
                                        let domain_hash = hasher.finalize();
                                        if processed.starts_with(domain_hash.as_slice()) {
                                            debug!("Detected domain hash prefix – stripping first 32 bytes");
                                            processed = processed[32..].to_vec();
                                        }
                                    }
                                    
                                    // Try to decode as UTF-8 and validate
                                    let (is_valid, value_result) = match String::from_utf8(processed.clone()) {
                                        Ok(value) => {
                                            let is_valid = value.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace());
                                            (is_valid, Some(value))
                                        }
                                        Err(_) => {
                                            // UTF-8 decoding failed – for v20 try skipping first 32 bytes
                                            if version == "v20" && processed.len() > 32 {
                                                debug!("UTF-8 decode failed for v20 cookie, trying from byte 32");
                                                match String::from_utf8(processed[32..].to_vec()) {
                                                    Ok(value) => {
                                                        let is_valid = value.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace());
                                                        (is_valid, Some(value))
                                                    }
                                                    Err(_) => {
                                                        debug!("UTF-8 decode still failed after skipping 32 bytes");
                                                        (false, None)
                                                    }
                                                }
                                            } else {
                                                debug!("UTF-8 decode failed, likely wrong key");
                                                (false, None)
                                            }
                                        }
                                    };

                                    if !is_valid || value_result.is_none() {
                                        // Invalid decryption, try next key
                                        continue;
                                    }

                                    value_result.unwrap()
                                } else {
                                    // Cookie wasn't encrypted or had value in the value field
                                    // Check if this is the first key attempt and the value field is not empty
                                    if key_idx == 0 && !chrome_cookie.value.is_empty() {
                                        chrome_cookie.value.clone()
                                    } else {
                                        continue;
                                    }
                                };

                                cookies.push(Cookie {
                                    host: chrome_cookie.host_key.clone(),
                                    name: chrome_cookie.name.clone(),
                                    value: final_value,
                                    path: chrome_cookie.path.clone(),
                                    expiry: chrome_cookie.expires_utc,
                                    is_secure: chrome_cookie.is_secure,
                                });
                                
                                decrypted = true;
                                break; // Successfully decrypted with this key
                            }
                            Err(e) => {
                                debug!(
                                    "Failed to decrypt cookie {} with key {}: {:?}",
                                    chrome_cookie.name, key_idx, e
                                );
                            }
                        }
                    }
                    
                    if !decrypted {
                        debug!("Failed to decrypt cookie {} with any key", chrome_cookie.name);
                    }
                }
                Err(e) => {
                    debug!("Failed to read cookie row: {:?}", e);
                }
            }
        }

        info!(
            "Extracted {} cookies from {}",
            cookies.len(),
            self.browser_name
        );
        Ok(cookies)
    }

    /// Extract credentials from a Chrome profile
    fn extract_credentials(
        &self,
        profile_path: &Path,
        keys: &[Vec<u8>],
    ) -> BrowserVoyageResult<Vec<Credential>> {
        let login_data_db = profile_path.join("Login Data");
        if !login_data_db.exists() {
            return Err(BrowserVoyageError::NoDataFound);
        }

        let conn = Connection::open_with_flags(
            &login_data_db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;

        let mut stmt = conn.prepare(
            "SELECT origin_url, username_value, password_value 
             FROM logins WHERE password_value != ''",
        )?;

        let credential_iter = stmt.query_map([], |row| {
            Ok(ChromeCredential {
                origin_url: row.get(0)?,
                username_value: row.get(1)?,
                password_value: row.get(2)?,
            })
        })?;

        let mut credentials = Vec::new();

        for credential_result in credential_iter {
            match credential_result {
                Ok(chrome_credential) => {
                    let mut decrypted = false;
                    
                    // Try each key until one works
                    for (key_idx, key) in keys.iter().enumerate() {
                        match self.decrypt_value("", &chrome_credential.password_value, key) {
                            Ok((_version, decrypted_data)) => {
                                let password = String::from_utf8_lossy(&decrypted_data).to_string();
                                credentials.push(Credential {
                                    url: chrome_credential.origin_url.clone(),
                                    username: chrome_credential.username_value.clone(),
                                    password,
                                });
                                decrypted = true;
                                break; // Successfully decrypted with this key
                            }
                            Err(e) => {
                                debug!(
                                    "Failed to decrypt password for {} with key {}: {:?}",
                                    chrome_credential.origin_url, key_idx, e
                                );
                            }
                        }
                    }
                    
                    if !decrypted {
                        debug!("Failed to decrypt password for {} with any key", chrome_credential.origin_url);
                    }
                }
                Err(e) => {
                    debug!("Failed to read credential row: {:?}", e);
                }
            }
        }

        info!(
            "Extracted {} credentials from {}",
            credentials.len(),
            self.browser_name
        );
        Ok(credentials)
    }
}

impl BrowserExtractor for LinuxChromeExtractor {
    fn name(&self) -> &str {
        &self.browser_name
    }

    #[instrument(skip(self))]
    fn extract(&mut self) -> BrowserVoyageResult<ExtractedData> {
        info!("Starting {} extraction on Linux", self.browser_name);

        // Check if browser is installed
        if !self.user_data_path.exists() {
            return Err(BrowserVoyageError::NoDataFound);
        }

        // Detect encryption mode
        let encryption_mode = self.detect_encryption_mode();
        debug!("Using encryption mode: {:?}", encryption_mode);

        // Get possible passwords to try
        let mut passwords = Vec::new();
        
        // Try to get password from keyring first
        if let Ok(keyring_password) = self.get_keyring_password(&encryption_mode) {
            debug!("Got keyring password: {}", if keyring_password.is_empty() { "(empty)" } else { "(non-empty)" });
            if !keyring_password.is_empty() && keyring_password != "peanuts" {
                passwords.push(keyring_password);
            }
        }
        
        // Add fallback passwords
        passwords.push("peanuts".to_string());
        passwords.push(String::new()); // empty password
        
        // Derive keys from all passwords
        let mut keys = Vec::new();
        for password in &passwords {
            if let Ok(key) = self.derive_key(password) {
                debug!("Derived key from password: {}", if password.is_empty() { "(empty)" } else if password == "peanuts" { "peanuts" } else { "(keyring)" });
                keys.push(key);
            }
        }
        
        if keys.is_empty() {
            return Err(BrowserVoyageError::DecryptionFailed(
                "Failed to derive any encryption keys".to_string()
            ));
        }

        // Get all profiles
        let profiles = self.get_profiles()?;
        let mut profile_data = Vec::new();

        for (profile_name, profile_path) in profiles {
            debug!("Processing profile: {}", profile_name);

            let cookies = self
                .extract_cookies(&profile_path, &keys)
                .unwrap_or_else(|e| {
                    debug!("Failed to extract cookies from {}: {:?}", profile_name, e);
                    Vec::new()
                });

            let credentials = self
                .extract_credentials(&profile_path, &keys)
                .unwrap_or_else(|e| {
                    debug!(
                        "Failed to extract credentials from {}: {:?}",
                        profile_name, e
                    );
                    Vec::new()
                });

            if !cookies.is_empty() || !credentials.is_empty() {
                profile_data.push(ProfileData {
                    name: profile_name,
                    path: profile_path.to_string_lossy().to_string(),
                    cookies,
                    credentials,
                });
            }
        }

        if profile_data.is_empty() {
            return Err(BrowserVoyageError::NoDataFound);
        }

        Ok(ExtractedData {
            browser: BrowserInfo {
                name: self.browser_name.clone(),
                vendor: match self.browser_name.as_str() {
                    "Chrome" => "Google".to_string(),
                    "Brave" => "Brave Software".to_string(),
                    "Chromium" => "The Chromium Authors".to_string(),
                    _ => "Unknown".to_string(),
                },
                platform: "Linux".to_string(),
            },
            profiles: profile_data,
        })
    }
}
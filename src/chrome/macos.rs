//! Modern macOS Chrome-based browser extractor using common base traits

use crate::browser_extractor::{BrowserExtractor, ExtractedData};
use crate::chrome::common::{ChromeBrowserConfig, ChromeExtractorBase};
use crate::common::BrowserProfile;
use crate::error::{BrowserVoyageError, BrowserVoyageResult};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use directories::UserDirs;
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// macOS Chrome extractor implementing the modern base traits
#[derive(Debug)]
pub struct MacOSChromeExtractor {
    config: ChromeBrowserConfig,
    user_data_path: PathBuf,
}

impl MacOSChromeExtractor {
    /// Create a new Chrome extractor
    pub fn chrome() -> Self {
        Self::new(ChromeBrowserConfig::chrome())
    }

    /// Create a new Edge extractor
    pub fn edge() -> Self {
        Self::new(ChromeBrowserConfig::edge())
    }

    /// Create a new Brave extractor
    pub fn brave() -> Self {
        Self::new(ChromeBrowserConfig::brave())
    }

    /// Create a new Chromium extractor
    pub fn chromium() -> Self {
        Self::new(ChromeBrowserConfig::chromium())
    }

    /// Create a new extractor with custom config
    fn new(config: ChromeBrowserConfig) -> Self {
        let user_data_path = Self::get_user_data_path_for_config(&config)
            .unwrap_or_else(|| PathBuf::from("/tmp/nonexistent"));

        Self {
            config,
            user_data_path,
        }
    }

    /// Get user data path for a given browser config
    fn get_user_data_path_for_config(config: &ChromeBrowserConfig) -> Option<PathBuf> {
        if let Some(user_dirs) = UserDirs::new() {
            let app_support_dir = user_dirs.home_dir().join("Library/Application Support");
            let browser_dir = app_support_dir.join(&config.data_dir_name);

            if browser_dir.exists() {
                Some(browser_dir)
            } else {
                None
            }
        } else {
            // Fallback to using HOME environment variable
            let home = env::var("HOME").ok()?;
            let browser_dir = PathBuf::from(home)
                .join("Library/Application Support")
                .join(&config.data_dir_name);

            if browser_dir.exists() {
                Some(browser_dir)
            } else {
                None
            }
        }
    }

    /// Get the secret from macOS keychain using security command
    fn get_keychain_secret(&self) -> BrowserVoyageResult<String> {
        debug!(
            "Attempting to retrieve {} from keychain",
            self.config.keychain_service
        );

        // First try: direct keychain access
        let mut cmd = Command::new("security");
        cmd.args([
            "find-generic-password",
            "-w", // output password only
            "-s",
            &self.config.keychain_service,
        ]);

        match cmd.output() {
            Ok(output) if output.status.success() => {
                let secret = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !secret.is_empty() {
                    debug!("Successfully retrieved keychain secret");
                    return Ok(secret);
                }
            }
            Ok(output) => {
                debug!(
                    "Keychain access failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(e) => {
                debug!("Failed to execute security command: {}", e);
            }
        }

        // Second try: with user specification (for cases where multiple users exist)
        let mut cmd_with_user = Command::new("security");
        cmd_with_user.args([
            "find-generic-password",
            "-w",
            "-s",
            &self.config.keychain_service,
            "-a",
            &self.config.name, // account name
        ]);

        match cmd_with_user.output() {
            Ok(output) if output.status.success() => {
                let secret = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !secret.is_empty() {
                    debug!("Successfully retrieved keychain secret with user specification");
                    return Ok(secret);
                }
            }
            Ok(output) => {
                debug!(
                    "Keychain access with user failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(e) => {
                debug!("Failed to execute security command with user: {}", e);
            }
        }

        Err(BrowserVoyageError::AccessDenied(format!(
            "Could not access keychain for {}. You may need to grant keychain access.",
            self.config.name
        )))
    }

    /// Derive the master key from keychain secret
    fn derive_master_key(&self, secret: &str) -> BrowserVoyageResult<Vec<u8>> {
        const SALT: &[u8] = b"saltysalt";
        const ITERATIONS: u32 = 1003;
        let mut output = [0u8; 16];

        pbkdf2_hmac::<Sha1>(secret.as_bytes(), SALT, ITERATIONS, &mut output);

        debug!("Successfully derived master key for {}", self.config.name);
        Ok(output.to_vec())
    }

    /// Decrypt Chrome data on macOS using AES-128-CBC
    fn decrypt_macos_chrome_data(
        &self,
        encrypted_data: &[u8],
        master_key: &[u8],
        host_key: Option<&str>,
    ) -> BrowserVoyageResult<Vec<u8>> {
        // Validate key length (AES-128 requires a 16-byte key)
        if master_key.len() != 16 {
            return Err(BrowserVoyageError::InvalidKeyLength(format!(
                "Expected 16 bytes, got {}",
                master_key.len()
            )));
        }

        // Ensure there's enough data to decrypt (prefix + minimum content)
        if encrypted_data.len() < 3 + 16 {
            return Err(BrowserVoyageError::DecryptionFailed(format!(
                "Encrypted value too short: {} bytes",
                encrypted_data.len()
            )));
        }

        // Check for valid encryption prefix (v10, v11, v20)
        let prefix = &encrypted_data[0..3];
        if prefix != b"v10" && prefix != b"v11" && prefix != b"v20" {
            return Err(BrowserVoyageError::DecryptionFailed(format!(
                "Invalid encryption prefix: {:?}",
                String::from_utf8_lossy(prefix)
            )));
        }

        // Use fixed IV of 16 space characters (0x20) as used by Chromium on macOS
        let iv = [0x20; 16];

        // Get encrypted content (everything after the prefix)
        let ciphertext = &encrypted_data[3..];

        // Check ciphertext length (must be multiple of block size for AES-CBC)
        if !ciphertext.len().is_multiple_of(16) {
            return Err(BrowserVoyageError::DecryptionFailed(format!(
                "Invalid ciphertext length: {}. Must be a multiple of 16 bytes",
                ciphertext.len()
            )));
        }

        // Prepare the key for AES-128
        let mut key_array = [0u8; 16];
        key_array.copy_from_slice(&master_key[..16]);

        // Initialize the AES-128-CBC cipher with key and IV
        let cipher = Aes128CbcDec::new(&key_array.into(), &iv.into());

        // Decrypt the content with PKCS#7 padding
        let mut dec = ciphertext.to_vec();
        match cipher.decrypt_padded_mut::<Pkcs7>(&mut dec) {
            Ok(plaintext) => {
                // Special handling for cookies: validate the domain hash
                if let Some(host) = host_key {
                    // Calculate SHA-256 hash of the domain
                    let mut hasher = Sha256::new();
                    hasher.update(host.as_bytes());
                    let computed_hash = hasher.finalize();

                    // If the first 32 bytes match the domain hash, extract the actual cookie value
                    if plaintext.len() >= 32 && computed_hash.as_slice() == &plaintext[..32] {
                        return Ok(plaintext[32..].to_vec());
                    } else if plaintext.len() >= 32 {
                        // Domain hash verification failed
                        debug!("Cookie domain verification failed for host: {}", host);
                        return Err(BrowserVoyageError::DecryptionFailed(format!(
                            "Cookie domain hash verification failed for: {host}"
                        )));
                    }
                }

                // Return the decrypted binary data
                Ok(plaintext.to_vec())
            }
            Err(e) => {
                debug!("Failed to decrypt with AES-CBC: {:?}", e);
                Err(BrowserVoyageError::DecryptionFailed(format!(
                    "AES-CBC decryption failed: {e:?}"
                )))
            }
        }
    }
}

impl BrowserExtractor for MacOSChromeExtractor {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn extract(&mut self) -> BrowserVoyageResult<ExtractedData> {
        if !self.user_data_path.exists() {
            return Err(BrowserVoyageError::NoDataFound);
        }

        info!(
            "Extracting data from {} at {:?}",
            self.config.name, self.user_data_path
        );
        self.extract_with_common_logic()
    }
}

impl ChromeExtractorBase for MacOSChromeExtractor {
    fn get_config(&self) -> &ChromeBrowserConfig {
        &self.config
    }

    fn get_user_data_path(&self) -> &Path {
        &self.user_data_path
    }

    fn decrypt_chrome_data(&self, encrypted_data: &[u8]) -> BrowserVoyageResult<Vec<u8>> {
        // For macOS, we need the master key first
        let master_key = self.get_master_key()?;
        self.decrypt_macos_chrome_data(encrypted_data, &master_key, None)
    }

    fn get_master_key(&self) -> BrowserVoyageResult<Vec<u8>> {
        let secret = self.get_keychain_secret()?;
        self.derive_master_key(&secret)
    }

    fn find_profiles(&self) -> BrowserVoyageResult<Vec<BrowserProfile>> {
        let mut profiles = Vec::new();

        // Check for Default profile
        let default_path = self.user_data_path.join("Default");
        if default_path.exists() && default_path.is_dir() {
            profiles.push(BrowserProfile::new(
                "Default".to_string(),
                default_path,
                true,
            ));
        }

        // Check for numbered profiles (Profile 1, Profile 2, etc.)
        if let Ok(entries) = std::fs::read_dir(&self.user_data_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with("Profile ") && name != "Default" {
                            profiles.push(BrowserProfile::new(name.to_string(), path, false));
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

    /// Override the base extract_cookies to handle macOS-specific domain validation
    fn extract_cookies(
        &self,
        profile_path: &Path,
    ) -> BrowserVoyageResult<Vec<crate::browser_extractor::Cookie>> {
        use crate::browser_extractor::Cookie;
        use crate::common::DatabaseOperations;
        use crate::common::DefaultDatabaseOps;

        let cookies_db = profile_path.join("Cookies");
        if !cookies_db.exists() {
            debug!("Cookies database not found at: {:?}", cookies_db);
            return Ok(Vec::new());
        }

        let db_ops = DefaultDatabaseOps;
        let conn = db_ops.open_database(&cookies_db)?;
        let master_key = self.get_master_key()?;

        let mut stmt = conn.prepare(
            "SELECT host_key, name, value, encrypted_value, path, expires_utc, is_secure
             FROM cookies",
        )?;

        let cookie_iter = stmt.query_map([], |row| {
            let encrypted_value: Vec<u8> = row.get(3).unwrap_or_default();
            let value: Option<String> = row.get(2)?;

            let final_value = if !encrypted_value.is_empty() {
                match self.decrypt_macos_chrome_data(
                    &encrypted_value,
                    &master_key,
                    Some(&row.get::<_, String>(0)?),
                ) {
                    Ok(decrypted) => String::from_utf8_lossy(&decrypted).to_string(),
                    Err(e) => {
                        warn!(
                            "Failed to decrypt cookie {}: {}",
                            row.get::<_, String>(1)?,
                            e
                        );
                        "".to_string()
                    }
                }
            } else {
                value.unwrap_or_default()
            };

            Ok(Cookie {
                host: row.get(0)?,
                name: row.get(1)?,
                value: final_value,
                path: row.get(4)?,
                expiry: row.get(5)?,
                is_secure: row.get(6)?,
            })
        })?;

        let cookies: Vec<Cookie> = cookie_iter.filter_map(Result::ok).collect();

        info!(
            "Extracted {} cookies from {}",
            cookies.len(),
            self.config.name
        );
        Ok(cookies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let chrome = MacOSChromeExtractor::chrome();
        assert_eq!(chrome.config.name, "Chrome");

        let brave = MacOSChromeExtractor::brave();
        assert_eq!(brave.config.name, "Brave");
    }

    #[test]
    fn test_path_generation() {
        let config = ChromeBrowserConfig::chrome();
        let path = MacOSChromeExtractor::get_user_data_path_for_config(&config);
        // This will vary based on the system, but should not panic
        println!("Chrome path: {path:?}");
    }
}

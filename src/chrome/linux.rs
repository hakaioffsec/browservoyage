//! Modern Linux Chrome-based browser extractor using common base traits

use crate::browser_extractor::{BrowserExtractor, ExtractedData};
use crate::chrome::common::{ChromeBrowserConfig, ChromeExtractorBase};
use crate::common::PlatformUtils;
use crate::error::{BrowserVoyageError, BrowserVoyageResult};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// Linux Chrome extractor implementing the modern base traits
#[derive(Debug)]
pub struct LinuxChromeExtractor {
    config: ChromeBrowserConfig,
    user_data_path: PathBuf,
}

/// Encryption modes available on Linux systems
#[derive(Debug, Clone, PartialEq)]
enum EncryptionMode {
    Gnome,   // GNOME Keyring / libsecret
    Kwallet, // KDE Wallet
    Basic,   // Fallback (plain password)
}

impl LinuxChromeExtractor {
    /// Create a new Chrome extractor
    pub fn chrome() -> Self {
        Self::new(ChromeBrowserConfig::chrome())
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
        let home_dir = PlatformUtils::get_home_dir()?;
        let path_str = match config.name.as_str() {
            "Chrome" => ".config/google-chrome",
            "Brave" => ".config/BraveSoftware/Brave-Browser",
            "Chromium" => ".config/chromium",
            _ => return None,
        };
        let config_dir = home_dir.join(path_str);

        if config_dir.exists() {
            Some(config_dir)
        } else {
            None
        }
    }

    /// Detect the encryption mode available on the system
    fn detect_encryption_mode(&self) -> EncryptionMode {
        // Check for GNOME Keyring
        if env::var("GNOME_KEYRING_CONTROL").is_ok()
            || Command::new("gnome-keyring")
                .arg("--version")
                .output()
                .is_ok()
        {
            return EncryptionMode::Gnome;
        }

        // Check for KDE Wallet
        if Command::new("kwalletd5").arg("--version").output().is_ok()
            || Command::new("kwallet-query").arg("--help").output().is_ok()
        {
            return EncryptionMode::Kwallet;
        }

        // Fallback to basic mode
        EncryptionMode::Basic
    }

    /// Get password from GNOME Keyring (libsecret)
    fn get_gnome_keyring_password(&self) -> BrowserVoyageResult<String> {
        let crypt_name = match self.config.name.as_str() {
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
                .args(["lookup", "xdg:schema", schema, "application", crypt_name])
                .output();

            match output_result {
                Ok(output) if output.status.success() => {
                    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !password.is_empty() {
                        debug!(
                            "Retrieved password from GNOME Keyring using schema {}",
                            schema
                        );
                        return Ok(password);
                    }
                }
                Ok(output) => {
                    debug!(
                        "secret-tool failed with schema {}: {}",
                        schema,
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                Err(e) => {
                    debug!("Failed to execute secret-tool for schema {}: {}", schema, e);
                }
            }
        }

        warn!("Could not retrieve password from GNOME Keyring, using default");
        Ok("peanuts".to_string())
    }

    /// Get password from KDE Wallet
    fn get_kwallet_password(&self) -> BrowserVoyageResult<String> {
        let wallet_name = "kdewallet";
        let key_name = format!("{} Safe Storage", self.config.name);

        let output = Command::new("kwallet-query")
            .args([
                "-r",
                &key_name,
                "-f",
                &format!("{} Keys", self.config.name),
                wallet_name,
            ])
            .output()
            .map_err(|e| {
                BrowserVoyageError::Io(format!("Failed to execute kwallet-query: {}", e))
            })?;

        if output.status.success() {
            let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !password.is_empty() {
                debug!("Retrieved password from KDE Wallet");
                return Ok(password);
            }
        }

        warn!("Could not retrieve password from KDE Wallet, using default");
        Ok("peanuts".to_string())
    }

    /// Get the master password from the keyring
    fn get_keyring_password(&self, mode: &EncryptionMode) -> BrowserVoyageResult<String> {
        match mode {
            EncryptionMode::Gnome => self.get_gnome_keyring_password(),
            EncryptionMode::Kwallet => self.get_kwallet_password(),
            EncryptionMode::Basic => Ok("peanuts".to_string()),
        }
    }

    /// Derive AES key from password using PBKDF2
    fn derive_key_from_password(&self, password: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
        let mut key = [0u8; 16]; // AES-128 key
        pbkdf2_hmac::<Sha1>(password.as_bytes(), salt, iterations, &mut key);
        key.to_vec()
    }

    /// Decrypt Chrome data on Linux
    fn decrypt_linux_chrome_data(&self, encrypted_data: &[u8]) -> BrowserVoyageResult<Vec<u8>> {
        // Handle v10 encryption (prefix "v10")
        if encrypted_data.starts_with(b"v10") {
            let encrypted_data = &encrypted_data[3..]; // Remove "v10" prefix

            let mode = self.detect_encryption_mode();
            let password = self.get_keyring_password(&mode)?;

            // Chrome uses "saltysalt" as salt and 1 iteration for key derivation
            let salt = b"saltysalt";
            let key = self.derive_key_from_password(&password, salt, 1);

            // Chrome uses a 16-byte IV of spaces
            let iv = vec![b' '; 16];

            // Decrypt using AES-128-CBC
            let cipher = Aes128CbcDec::new_from_slices(&key, &iv).map_err(|e| {
                BrowserVoyageError::DecryptionFailed(format!("AES init failed: {}", e))
            })?;

            let mut buf = encrypted_data.to_vec();
            let decrypted = cipher.decrypt_padded_mut::<Pkcs7>(&mut buf).map_err(|e| {
                BrowserVoyageError::DecryptionFailed(format!("Decryption failed: {}", e))
            })?;

            Ok(decrypted.to_vec())
        } else {
            // Assume it's plain text or old format
            Ok(encrypted_data.to_vec())
        }
    }
}

impl BrowserExtractor for LinuxChromeExtractor {
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

impl ChromeExtractorBase for LinuxChromeExtractor {
    fn get_config(&self) -> &ChromeBrowserConfig {
        &self.config
    }

    fn get_user_data_path(&self) -> &Path {
        &self.user_data_path
    }

    fn decrypt_chrome_data(&self, encrypted_data: &[u8]) -> BrowserVoyageResult<Vec<u8>> {
        self.decrypt_linux_chrome_data(encrypted_data)
    }

    fn get_master_key(&self) -> BrowserVoyageResult<Vec<u8>> {
        let mode = self.detect_encryption_mode();
        let password = self.get_keyring_password(&mode)?;

        let salt = b"saltysalt";
        Ok(self.derive_key_from_password(&password, salt, 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let chrome = LinuxChromeExtractor::chrome();
        assert_eq!(chrome.config.name, "Chrome");

        let brave = LinuxChromeExtractor::brave();
        assert_eq!(brave.config.name, "Brave");
    }

    #[test]
    fn test_encryption_mode_detection() {
        let extractor = LinuxChromeExtractor::chrome();
        let mode = extractor.detect_encryption_mode();
        // This will vary based on the system, but should not panic
        println!("Detected encryption mode: {:?}", mode);
    }
}

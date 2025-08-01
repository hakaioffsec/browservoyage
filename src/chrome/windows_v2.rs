//! Modern Windows Chrome-based browser extractor using common base traits

use crate::browser_extractor::{BrowserExtractor, ExtractedData};
use crate::chrome::common::{ChromeBrowserConfig, ChromeExtractorBase};

use crate::error::{convert_windows_error, BrowserVoyageError, BrowserVoyageResult};
use crate::windows::ImpersonationGuard;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::ChaCha20Poly1305;
use hex;
use serde_json;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, instrument};
use windows::core::w;
use windows::Win32::Security::Cryptography::{
    CryptUnprotectData, NCryptDecrypt, NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider,
    CERT_KEY_SPEC, CRYPT_INTEGER_BLOB, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
};

/// Windows Chrome extractor implementing the modern base traits
#[derive(Debug)]
pub struct ModernWindowsChromeExtractor {
    config: ChromeBrowserConfig,
    user_data_path: PathBuf,
}

#[derive(Debug)]
struct ParsedKeyBlob {
    _header: Vec<u8>,
    flag: u8,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
    encrypted_aes_key: Option<Vec<u8>>,
}

impl ModernWindowsChromeExtractor {
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

    /// Create a new extractor with custom config
    fn new(config: ChromeBrowserConfig) -> Self {
        let user_data_path = Self::get_user_data_path_for_config(&config)
            .unwrap_or_else(|| PathBuf::from("C:\\temp\\nonexistent"));

        Self {
            config,
            user_data_path,
        }
    }

    /// Get user data path for a given browser config
    fn get_user_data_path_for_config(config: &ChromeBrowserConfig) -> Option<PathBuf> {
        let user_profile = env::var("USERPROFILE").ok()?;
        let base_path = PathBuf::from(&user_profile);

        let browser_path = match config.name.as_str() {
            "Chrome" => base_path.join("AppData/Local/Google/Chrome/User Data"),
            "Edge" => base_path.join("AppData/Local/Microsoft/Edge/User Data"),
            "Brave" => base_path.join("AppData/Local/BraveSoftware/Brave-Browser/User Data"),
            _ => base_path.join(format!("AppData/Local/{}/User Data", config.data_dir_name)),
        };

        if browser_path.exists() {
            Some(browser_path)
        } else {
            None
        }
    }

    /// Parse the Chrome key blob structure
    fn parse_key_blob(&self, blob_data: &[u8]) -> BrowserVoyageResult<ParsedKeyBlob> {
        if blob_data.len() < 5 {
            return Err(BrowserVoyageError::ParseError("Key blob too short".into()));
        }

        let mut parsed = ParsedKeyBlob {
            _header: blob_data[0..4].to_vec(),
            flag: blob_data[4],
            iv: Vec::new(),
            ciphertext: Vec::new(),
            tag: Vec::new(),
            encrypted_aes_key: None,
        };

        let mut cursor = 5;
        let flag = parsed.flag;

        match flag {
            1 => {
                if cursor + 12 + 32 + 16 > blob_data.len() {
                    return Err(BrowserVoyageError::ParseError(
                        "Invalid data for flag 1".into(),
                    ));
                }
                parsed.iv = blob_data[cursor..cursor + 12].to_vec();
                cursor += 12;
                parsed.ciphertext = blob_data[cursor..cursor + 32].to_vec();
                cursor += 32;
                parsed.tag = blob_data[cursor..cursor + 16].to_vec();
            }
            2 => {
                if cursor + 12 + 32 + 16 > blob_data.len() {
                    return Err(BrowserVoyageError::ParseError(
                        "Invalid data for flag 2".into(),
                    ));
                }
                parsed.iv = blob_data[cursor..cursor + 12].to_vec();
                cursor += 12;
                parsed.ciphertext = blob_data[cursor..cursor + 32].to_vec();
                cursor += 32;
                parsed.tag = blob_data[cursor..cursor + 16].to_vec();
            }
            3 => {
                if cursor + 32 + 12 + 32 + 16 > blob_data.len() {
                    return Err(BrowserVoyageError::ParseError(
                        "Invalid data for flag 3".into(),
                    ));
                }
                parsed.encrypted_aes_key = Some(blob_data[cursor..cursor + 32].to_vec());
                cursor += 32;
                parsed.iv = blob_data[cursor..cursor + 12].to_vec();
                cursor += 12;
                parsed.ciphertext = blob_data[cursor..cursor + 32].to_vec();
                cursor += 32;
                parsed.tag = blob_data[cursor..cursor + 16].to_vec();
            }
            _ => {
                return Err(BrowserVoyageError::ParseError(format!(
                    "Unsupported flag: {flag}"
                )))
            }
        }

        Ok(parsed)
    }

    /// Decrypt using Windows CNG
    #[instrument(skip(input_data))]
    fn decrypt_with_cng(&self, input_data: &[u8]) -> BrowserVoyageResult<Vec<u8>> {
        unsafe {
            let mut h_provider = NCRYPT_PROV_HANDLE::default();
            let provider_name = w!("Microsoft Software Key Storage Provider");

            NCryptOpenStorageProvider(&mut h_provider, provider_name, 0)
                .map_err(convert_windows_error)?;

            let mut h_key = NCRYPT_KEY_HANDLE::default();
            let key_name = w!("Google Chromekey1");

            NCryptOpenKey(
                h_provider,
                &mut h_key,
                key_name,
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
            .map_err(convert_windows_error)?;

            let mut pcb_result = 0u32;
            NCryptDecrypt(
                h_key,
                Some(input_data),
                None,
                None,
                &mut pcb_result,
                NCRYPT_FLAGS(0x40), // NCRYPT_SILENT_FLAG
            )
            .map_err(convert_windows_error)?;

            let mut output = vec![0u8; pcb_result as usize];
            NCryptDecrypt(
                h_key,
                Some(input_data),
                None,
                Some(&mut output),
                &mut pcb_result,
                NCRYPT_FLAGS(0x40), // NCRYPT_SILENT_FLAG
            )
            .map_err(convert_windows_error)?;

            NCryptFreeObject(windows::Win32::Security::Cryptography::NCRYPT_HANDLE(
                h_key.0,
            ))
            .ok();
            NCryptFreeObject(windows::Win32::Security::Cryptography::NCRYPT_HANDLE(
                h_provider.0,
            ))
            .ok();

            output.truncate(pcb_result as usize);
            debug!("Successfully decrypted {} bytes with CNG", output.len());
            Ok(output)
        }
    }

    /// DPAPI decrypt
    fn dpapi_unprotect(&self, data: &[u8]) -> BrowserVoyageResult<Vec<u8>> {
        unsafe {
            let data_in = CRYPT_INTEGER_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut u8,
            };

            let mut data_out = CRYPT_INTEGER_BLOB::default();

            CryptUnprotectData(&data_in, None, None, None, None, 0, &mut data_out)
                .map_err(convert_windows_error)?;

            let result =
                std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize).to_vec();

            #[link(name = "kernel32")]
            extern "system" {
                fn LocalFree(hMem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
            }

            LocalFree(data_out.pbData as *mut std::ffi::c_void);

            debug!("DPAPI decrypted {} bytes", result.len());
            Ok(result)
        }
    }

    /// Derive master key based on the flag
    fn derive_master_key(&self, parsed_data: &ParsedKeyBlob) -> BrowserVoyageResult<Vec<u8>> {
        match parsed_data.flag {
            1 => {
                info!("Using AES-256-GCM decryption (flag 1)");
                let aes_key = hex::decode(
                    "B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787",
                )?;
                let cipher = Aes256Gcm::new_from_slice(&aes_key)
                    .map_err(|e| BrowserVoyageError::InvalidKeyLength(format!("{e:?}")))?;
                let nonce = Nonce::from_slice(&parsed_data.iv);

                let mut ciphertext_with_tag = parsed_data.ciphertext.clone();
                ciphertext_with_tag.extend_from_slice(&parsed_data.tag);

                cipher
                    .decrypt(nonce, ciphertext_with_tag.as_ref())
                    .map_err(|e| BrowserVoyageError::DecryptionFailed(format!("{e:?}")))
            }
            2 => {
                info!("Using ChaCha20-Poly1305 decryption (flag 2)");
                let chacha_key = hex::decode(
                    "B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787",
                )?;
                let cipher = ChaCha20Poly1305::new_from_slice(&chacha_key)
                    .map_err(|e| BrowserVoyageError::InvalidKeyLength(format!("{e:?}")))?;
                let nonce = chacha20poly1305::Nonce::from_slice(&parsed_data.iv);

                let mut ciphertext_with_tag = parsed_data.ciphertext.clone();
                ciphertext_with_tag.extend_from_slice(&parsed_data.tag);

                cipher
                    .decrypt(nonce, ciphertext_with_tag.as_ref())
                    .map_err(|e| BrowserVoyageError::DecryptionFailed(format!("{e:?}")))
            }
            3 => {
                info!("Using AES-256-GCM with CNG decryption (flag 3)");
                let encrypted_aes_key = parsed_data
                    .encrypted_aes_key
                    .as_ref()
                    .ok_or_else(|| BrowserVoyageError::ParseError("Missing AES key".into()))?;

                let decrypted_key = self.decrypt_with_cng(encrypted_aes_key)?;
                let hardcoded_key = hex::decode(
                    "B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787",
                )?;

                let final_key: Vec<u8> = decrypted_key
                    .iter()
                    .zip(hardcoded_key.iter())
                    .map(|(a, b)| a ^ b)
                    .collect();

                let cipher = Aes256Gcm::new_from_slice(&final_key)
                    .map_err(|e| BrowserVoyageError::InvalidKeyLength(format!("{e:?}")))?;
                let nonce = Nonce::from_slice(&parsed_data.iv);

                let mut ciphertext_with_tag = parsed_data.ciphertext.clone();
                ciphertext_with_tag.extend_from_slice(&parsed_data.tag);

                cipher
                    .decrypt(nonce, ciphertext_with_tag.as_ref())
                    .map_err(|e| BrowserVoyageError::DecryptionFailed(format!("{e:?}")))
            }
            _ => Err(BrowserVoyageError::ParseError(format!(
                "Unsupported flag: {}",
                parsed_data.flag
            ))),
        }
    }

    /// Get the app-bound key for v20 decryption
    fn get_app_bound_key_for_v20(&self) -> BrowserVoyageResult<Vec<u8>> {
        let local_state_path = self.user_data_path.join("Local State");
        let local_state_content = fs::read_to_string(&local_state_path)
            .map_err(|e| BrowserVoyageError::Io(format!("Failed to read Local State: {e}")))?;

        let local_state: serde_json::Value = serde_json::from_str(&local_state_content)?;

        let app_bound_key = local_state
            .get("os_crypt")
            .and_then(|os_crypt| os_crypt.get("app_bound_encrypted_key"))
            .and_then(|key| key.as_str())
            .ok_or_else(|| {
                BrowserVoyageError::ParseError("Missing app_bound_encrypted_key".into())
            })?;

        let encrypted_key = BASE64
            .decode(app_bound_key)
            .map_err(|_| BrowserVoyageError::Base64Error)?;

        if encrypted_key.len() < 4 || &encrypted_key[0..4] != b"APPB" {
            return Err(BrowserVoyageError::ParseError(
                "Invalid app-bound key format".into(),
            ));
        }

        let encrypted_key = &encrypted_key[4..];

        let _guard = ImpersonationGuard::new()?;
        let system_decrypted = self.dpapi_unprotect(encrypted_key)?;
        drop(_guard);

        let user_decrypted = self.dpapi_unprotect(&system_decrypted)?;
        let parsed_blob = self.parse_key_blob(&user_decrypted)?;
        let master_key = self.derive_master_key(&parsed_blob)?;

        Ok(master_key)
    }

    /// Decrypt Chrome data on Windows
    fn decrypt_windows_chrome_data(&self, encrypted_data: &[u8]) -> BrowserVoyageResult<Vec<u8>> {
        if encrypted_data.len() < 3 {
            return Err(BrowserVoyageError::DecryptionFailed(
                "Encrypted data too short".into(),
            ));
        }

        // Handle v20 encryption
        if encrypted_data.starts_with(b"v20") {
            debug!("Decrypting v20 encrypted data");

            let encrypted_data = &encrypted_data[3..];
            if encrypted_data.len() < 12 {
                return Err(BrowserVoyageError::DecryptionFailed(
                    "v20 data too short".into(),
                ));
            }

            let nonce = &encrypted_data[0..12];
            let ciphertext = &encrypted_data[12..];

            // Try with the app-bound key
            let master_key = self.get_app_bound_key_for_v20()?;
            let cipher = Aes256Gcm::new_from_slice(&master_key)
                .map_err(|e| BrowserVoyageError::InvalidKeyLength(format!("{e:?}")))?;
            let nonce = Nonce::from_slice(nonce);

            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|e| BrowserVoyageError::DecryptionFailed(format!("{e:?}")))
        } else {
            // Handle older encryption (v10, v11, DPAPI)
            self.dpapi_unprotect(encrypted_data)
        }
    }
}

impl BrowserExtractor for ModernWindowsChromeExtractor {
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

impl ChromeExtractorBase for ModernWindowsChromeExtractor {
    fn get_config(&self) -> &ChromeBrowserConfig {
        &self.config
    }

    fn get_user_data_path(&self) -> &Path {
        &self.user_data_path
    }

    fn decrypt_chrome_data(&self, encrypted_data: &[u8]) -> BrowserVoyageResult<Vec<u8>> {
        self.decrypt_windows_chrome_data(encrypted_data)
    }

    fn get_master_key(&self) -> BrowserVoyageResult<Vec<u8>> {
        // For Windows, we try to get the app-bound key
        self.get_app_bound_key_for_v20()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let chrome = ModernWindowsChromeExtractor::chrome();
        assert_eq!(chrome.config.name, "Chrome");

        let brave = ModernWindowsChromeExtractor::brave();
        assert_eq!(brave.config.name, "Brave");
    }

    #[test]
    fn test_path_generation() {
        let config = ChromeBrowserConfig::chrome();
        let path = ModernWindowsChromeExtractor::get_user_data_path_for_config(&config);
        // This will vary based on the system, but should not panic
        println!("Chrome path: {:?}", path);
    }
}

//! Optimized Windows Chrome-based browser extractor with extraction-level impersonation

use crate::browser_extractor::{
    BrowserExtractor, BrowserInfo, Cookie, Credential, ExtractedData, ProfileData,
};
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
use rusqlite::Connection;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use windows::core::w;
use windows::Win32::Security::Cryptography::{
    CryptUnprotectData, NCryptDecrypt, NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider,
    CERT_KEY_SPEC, CRYPT_INTEGER_BLOB, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
};

/// Optimized Windows Chrome extractor with extraction-level impersonation
#[derive(Debug)]
pub struct WindowsChromeExtractor {
    config: ChromeBrowserConfig,
    user_data_path: PathBuf,
    cached_master_key: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
struct LocalState {
    os_crypt: OsCrypt,
}

#[derive(Debug, Deserialize)]
struct OsCrypt {
    app_bound_encrypted_key: Option<String>,
    encrypted_key: Option<String>,
}

#[derive(Debug)]
pub struct ParsedKeyBlob {
    _header: Vec<u8>,
    flag: u8,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
    encrypted_aes_key: Option<Vec<u8>>,
}

impl WindowsChromeExtractor {
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
            .unwrap_or_else(|| PathBuf::from("C:\\temp\\nonexistent"));

        Self {
            config,
            user_data_path,
            cached_master_key: None,
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

    /// Initialize master key with impersonation (called once per extraction)
    fn initialize_master_key_with_impersonation(&mut self) -> BrowserVoyageResult<()> {
        if self.cached_master_key.is_some() {
            return Ok(()); // Already initialized
        }

        info!(
            "Initializing master key for {} with impersonation",
            self.config.name
        );

        // Let inner routines manage impersonation only where required (e.g., SYSTEM DPAPI decrypt)
        let master_key = self.extract_master_key_with_active_impersonation()?;
        self.cached_master_key = Some(master_key);

        Ok(())
    }

    fn extract_master_key_with_active_impersonation(&self) -> BrowserVoyageResult<Vec<u8>> {
        let local_state_path = self.user_data_path.join("Local State");

        info!("Reading {} Local State file", self.config.name);
        let local_state_content = fs::read_to_string(&local_state_path)
            .map_err(|e| BrowserVoyageError::Io(format!("Failed to read Local State: {e}")))?;
        let local_state: LocalState = serde_json::from_str(&local_state_content)?;

        match self.config.name.as_str() {
            "Chrome" => self.extract_chrome_master_key(&local_state.os_crypt),
            "Edge" | "Brave" => self.extract_simple_master_key(&local_state.os_crypt),
            _ => Err(BrowserVoyageError::ParseError(format!(
                "Unsupported browser: {}",
                self.config.name
            ))),
        }
    }

    fn extract_chrome_master_key(&self, os_crypt: &OsCrypt) -> BrowserVoyageResult<Vec<u8>> {
        let app_bound_encrypted_key =
            os_crypt.app_bound_encrypted_key.as_ref().ok_or_else(|| {
                BrowserVoyageError::ParseError("Missing app_bound_encrypted_key for Chrome".into())
            })?;

        let key_blob_encrypted_with_prefix = BASE64
            .decode(app_bound_encrypted_key)
            .map_err(|_| BrowserVoyageError::Base64Error)?;

        if key_blob_encrypted_with_prefix.len() < 4
            || &key_blob_encrypted_with_prefix[..4] != b"APPB"
        {
            return Err(BrowserVoyageError::ParseError(
                "Invalid app_bound_encrypted_key prefix".into(),
            ));
        }

        let key_blob_encrypted = &key_blob_encrypted_with_prefix[4..];
        // Perform first decrypt under SYSTEM impersonation, then drop it for user decrypt
        let key_blob_system_decrypted = {
            let _guard = ImpersonationGuard::new()?;
            let result = self.dpapi_unprotect(key_blob_encrypted)?;
            // Drop guard to revert to the original user before the second DPAPI call
            drop(_guard);
            result
        };

        let key_blob_user_decrypted = self.dpapi_unprotect(&key_blob_system_decrypted)?;

        let parsed_data = self.parse_key_blob(&key_blob_user_decrypted);
        match parsed_data.and_then(|pd| self.derive_v20_master_key(&pd)) {
            Ok(master_key) => Ok(master_key),
            Err(e) => {
                debug!(
                    "Chrome key derivation failed ({}). Falling back to last-32-bytes method",
                    e
                );
                if key_blob_user_decrypted.len() >= 32 {
                    let state_key =
                        key_blob_user_decrypted[key_blob_user_decrypted.len() - 32..].to_vec();
                    Ok(state_key)
                } else {
                    Err(e)
                }
            }
        }
    }

    fn extract_simple_master_key(&self, os_crypt: &OsCrypt) -> BrowserVoyageResult<Vec<u8>> {
        // First try the standard Edge/Brave approach
        if let Some(encrypted_key) = &os_crypt.encrypted_key {
            if let Ok(key) = self.try_standard_dpapi_approach(encrypted_key) {
                return Ok(key);
            }
            debug!(
                "Standard DPAPI approach failed for {}, trying Chrome's complex key derivation",
                self.config.name
            );
        }

        // Fallback: Try Chrome's complex key derivation method
        if let Some(app_bound_encrypted_key) = &os_crypt.app_bound_encrypted_key {
            if let Ok(key) = self.extract_chrome_style_key(app_bound_encrypted_key) {
                return Ok(key);
            }
        }

        Err(BrowserVoyageError::ParseError(format!(
            "Failed to extract master key for {} using any available method",
            self.config.name
        )))
    }

    fn try_standard_dpapi_approach(&self, encrypted_key: &str) -> BrowserVoyageResult<Vec<u8>> {
        let key_with_prefix = BASE64
            .decode(encrypted_key)
            .map_err(|_| BrowserVoyageError::Base64Error)?;

        if key_with_prefix.len() < 5 || &key_with_prefix[..5] != b"DPAPI" {
            return Err(BrowserVoyageError::ParseError(
                "Invalid encrypted_key prefix".into(),
            ));
        }

        let encrypted_key_data = &key_with_prefix[5..];

        let decrypted_content = self.dpapi_unprotect(encrypted_key_data)?;

        if decrypted_content.len() < 32 {
            return Err(BrowserVoyageError::ParseError(format!(
                "DPAPI decrypted content too short for {}: expected at least 32 bytes, got {}",
                self.config.name,
                decrypted_content.len()
            )));
        }

        let state_key = decrypted_content[decrypted_content.len() - 32..].to_vec();

        debug!(
            "Successfully extracted {} master key using standard approach (last 32 bytes of {} total)",
            self.config.name,
            decrypted_content.len()
        );
        Ok(state_key)
    }

    /// Get alternative key for v20 cookies using Chrome's complex key derivation method
    fn get_app_bound_key_for_v20(&self) -> BrowserVoyageResult<Vec<u8>> {
        let local_state_path = self.user_data_path.join("Local State");
        let local_state_content = fs::read_to_string(&local_state_path)
            .map_err(|e| BrowserVoyageError::Io(format!("Failed to read Local State: {e}")))?;

        let local_state: LocalState = serde_json::from_str(&local_state_content).map_err(|e| {
            BrowserVoyageError::ParseError(format!("Failed to parse Local State: {e}"))
        })?;

        match &local_state.os_crypt.app_bound_encrypted_key {
            Some(app_bound_encrypted_key) => {
                // Use Chrome's complex key derivation method (system-user DPAPI + blob parsing)
                self.extract_chrome_style_key(app_bound_encrypted_key)
            }
            None => Err(BrowserVoyageError::ParseError(
                "No app_bound_encrypted_key found for v20 fallback".into(),
            )),
        }
    }

    /// Extract master key using Chrome's complex derivation method
    ///
    /// This method uses system-user DPAPI decryption followed by blob parsing,
    /// then extracts the last 32 bytes as the master key. Originally designed for Chrome,
    /// but also used as a fallback for v20 cookies in Edge/Brave.
    fn extract_chrome_style_key(
        &self,
        app_bound_encrypted_key: &str,
    ) -> BrowserVoyageResult<Vec<u8>> {
        debug!(
            "Using Chrome's complex key derivation for {} (system-user DPAPI + last 32 bytes)",
            self.config.name
        );

        let key_blob_encrypted_with_prefix = BASE64
            .decode(app_bound_encrypted_key)
            .map_err(|_| BrowserVoyageError::Base64Error)?;

        if key_blob_encrypted_with_prefix.len() < 4
            || &key_blob_encrypted_with_prefix[..4] != b"APPB"
        {
            return Err(BrowserVoyageError::ParseError(
                "Invalid app_bound_encrypted_key prefix".into(),
            ));
        }

        let key_blob_encrypted = &key_blob_encrypted_with_prefix[4..];

        // Try system-user DPAPI approach like Chrome but take last 32 bytes
        let _guard = ImpersonationGuard::new()?;
        let key_blob_system_decrypted = self.dpapi_unprotect(key_blob_encrypted)?;
        drop(_guard);

        let key_blob_user_decrypted = self.dpapi_unprotect(&key_blob_system_decrypted)?;

        // Use the last 32 bytes of decrypted key directly (Edge/Brave style)
        if key_blob_user_decrypted.len() >= 32 {
            let state_key = key_blob_user_decrypted[key_blob_user_decrypted.len() - 32..].to_vec();
            debug!(
                "Successfully extracted {} master key using Chrome's complex derivation (last 32 bytes of {} total)",
                self.config.name,
                key_blob_user_decrypted.len()
            );
            Ok(state_key)
        } else {
            Err(BrowserVoyageError::ParseError(format!(
                "System-user DPAPI decrypted content too short for Edge approach: expected at least 32 bytes, got {}",
                key_blob_user_decrypted.len()
            )))
        }
    }

    /// Helper function to handle binary data in cookies by encoding as base64 when UTF-8 conversion fails
    fn handle_binary_data(&self, data: Vec<u8>) -> BrowserVoyageResult<String> {
        match String::from_utf8(data.clone()) {
            Ok(s) => Ok(s),
            Err(_) => {
                debug!("Cookie contains binary data, encoding as base64");
                Ok(BASE64.encode(&data))
            }
        }
    }

    /// Try v20 cookie decryption using Chrome's complex key derivation (app_bound_encrypted_key)
    fn try_v20_fallback_decryption(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> BrowserVoyageResult<Option<String>> {
        debug!(
            "Trying v20 decryption with Chrome's complex key derivation for {}",
            self.config.name
        );

        let alt_key = self.get_app_bound_key_for_v20()?;
        debug!(
            "Attempting v20 decryption with app_bound key ({} bytes)",
            alt_key.len()
        );

        if alt_key.len() == 32 {
            let alt_cipher = Aes256Gcm::new_from_slice(&alt_key)
                .map_err(|e| BrowserVoyageError::InvalidKeyLength(format!("{e:?}")))?;
            let nonce = Nonce::from_slice(nonce);

            if let Ok(result) = alt_cipher.decrypt(nonce, ciphertext) {
                debug!("v20 decryption successful with app_bound key");
                return Ok(Some(self.handle_binary_data(result)?));
            } else {
                debug!("v20 decryption failed with app_bound key");
            }
        }

        Ok(None)
    }

    /// Decrypt Chromium encrypted values (cookies and passwords)
    ///
    /// Handles different encryption versions (v10, v11, v20) and browser-specific logic:
    /// - Edge/Brave: Uses simple AES-GCM decryption, with fallback to Chrome's complex key derivation for v20 cookies
    /// - Chrome: Uses AES-GCM with domain hash validation for cookies
    ///
    /// Gracefully handles binary cookie data by encoding as base64 when UTF-8 conversion fails.
    fn decrypt_chromium_value(
        &self,
        encrypted_value: &[u8],
        master_key: &[u8],
        host_key: Option<&str>,
    ) -> BrowserVoyageResult<String> {
        // Validate encrypted value format and length
        if encrypted_value.len() < 3 + 12 + 16 {
            return Err(BrowserVoyageError::ParseError(
                "Invalid encrypted value length".into(),
            ));
        }

        // Check for supported encryption prefixes (v10, v11, v20)
        if !matches!(&encrypted_value[..3], b"v10" | b"v11" | b"v20") {
            return Err(BrowserVoyageError::ParseError(format!(
                "Unknown encryption prefix: {:?}",
                String::from_utf8_lossy(&encrypted_value[..3])
            )));
        }

        let nonce = &encrypted_value[3..15];
        let ciphertext = &encrypted_value[15..];

        let cipher = Aes256Gcm::new_from_slice(master_key)
            .map_err(|e| BrowserVoyageError::InvalidKeyLength(format!("{e:?}")))?;
        let nonce = Nonce::from_slice(nonce);

        // Attempt standard AES-GCM decryption
        let decrypted = match cipher.decrypt(nonce, ciphertext) {
            Ok(result) => result,
            Err(e) => {
                // For v20 cookies in Edge/Brave, try Chrome's complex key derivation as fallback
                if &encrypted_value[..3] == b"v20"
                    && matches!(self.config.name.as_str(), "Edge" | "Brave")
                {
                    if let Some(result) = self.try_v20_fallback_decryption(nonce, ciphertext)? {
                        return Ok(result);
                    }
                }

                return Err(BrowserVoyageError::DecryptionFailed(format!(
                    "AES-GCM: {e}"
                )));
            }
        };

        // For Edge/Brave, use simple decryption (no domain hash validation)
        if matches!(self.config.name.as_str(), "Edge" | "Brave") {
            return self.handle_binary_data(decrypted);
        }

        // Special handling for Chrome cookies: validate the domain hash
        if let Some(host) = host_key {
            // Calculate SHA-256 hash of the domain
            let computed_hash = Sha256::digest(host.as_bytes());

            // If the first 32 bytes match the domain hash, extract the actual cookie value
            if decrypted.len() >= 32 && computed_hash.as_slice() == &decrypted[..32] {
                return Ok(String::from_utf8(decrypted[32..].to_vec())?);
            }
        }

        // Convert the decrypted binary data to a UTF-8 string (for passwords or cookies without domain hash)
        Ok(String::from_utf8(decrypted)?)
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

    fn parse_key_blob(&self, blob_data: &[u8]) -> BrowserVoyageResult<ParsedKeyBlob> {
        let mut cursor = 0;

        if blob_data.len() < 8 {
            return Err(BrowserVoyageError::ParseError("Blob data too short".into()));
        }

        let header_len =
            u32::from_le_bytes(blob_data[cursor..cursor + 4].try_into().map_err(|_| {
                BrowserVoyageError::ParseError("Failed to parse header length".into())
            })?) as usize;
        cursor += 4;

        if cursor + header_len > blob_data.len() {
            return Err(BrowserVoyageError::ParseError(
                "Invalid header length".into(),
            ));
        }

        let header = blob_data[cursor..cursor + header_len].to_vec();
        cursor += header_len;

        let content_len =
            u32::from_le_bytes(blob_data[cursor..cursor + 4].try_into().map_err(|_| {
                BrowserVoyageError::ParseError("Failed to parse content length".into())
            })?) as usize;
        cursor += 4;

        if header_len + content_len + 8 != blob_data.len() {
            return Err(BrowserVoyageError::ParseError(
                "Invalid blob structure".into(),
            ));
        }

        let flag = blob_data[cursor];
        cursor += 1;

        debug!("Parsing key blob with flag: {}", flag);

        let mut parsed = ParsedKeyBlob {
            _header: header,
            flag,
            iv: Vec::new(),
            ciphertext: Vec::new(),
            tag: Vec::new(),
            encrypted_aes_key: None,
        };

        match flag {
            1 | 2 => {
                if cursor + 12 + 32 + 16 > blob_data.len() {
                    return Err(BrowserVoyageError::ParseError(format!(
                        "Invalid data for flag {flag}"
                    )));
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

    fn byte_xor(&self, ba1: &[u8], ba2: &[u8]) -> Vec<u8> {
        ba1.iter().zip(ba2.iter()).map(|(a, b)| a ^ b).collect()
    }

    fn derive_v20_master_key(&self, parsed_data: &ParsedKeyBlob) -> BrowserVoyageResult<Vec<u8>> {
        match parsed_data.flag {
            1 => {
                debug!("Using AES-256-GCM decryption (flag 1)");
                let aes_key = hex::decode(
                    "B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787",
                )?;
                let cipher = Aes256Gcm::new_from_slice(&aes_key)
                    .map_err(|e| BrowserVoyageError::InvalidKeyLength(format!("{e:?}")))?;
                let nonce = Nonce::from_slice(&parsed_data.iv);

                let mut combined = parsed_data.ciphertext.clone();
                combined.extend_from_slice(&parsed_data.tag);

                cipher
                    .decrypt(nonce, combined.as_ref())
                    .map_err(|e| BrowserVoyageError::DecryptionFailed(format!("AES: {e}")))
            }
            2 => {
                debug!("Using ChaCha20-Poly1305 decryption (flag 2)");
                let chacha20_key = hex::decode(
                    "E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660",
                )?;
                let cipher = ChaCha20Poly1305::new_from_slice(&chacha20_key)
                    .map_err(|e| BrowserVoyageError::InvalidKeyLength(format!("{e:?}")))?;
                let nonce = chacha20poly1305::Nonce::from_slice(&parsed_data.iv);

                let mut combined = parsed_data.ciphertext.clone();
                combined.extend_from_slice(&parsed_data.tag);

                cipher
                    .decrypt(nonce, combined.as_ref())
                    .map_err(|e| BrowserVoyageError::DecryptionFailed(format!("ChaCha20: {e}")))
            }
            3 => {
                debug!("Using AES-256-GCM with CNG decryption (flag 3)");
                let xor_key = hex::decode(
                    "CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390",
                )?;

                let encrypted_aes_key =
                    parsed_data.encrypted_aes_key.as_ref().ok_or_else(|| {
                        BrowserVoyageError::ParseError(
                            "Missing encrypted AES key for flag 3".into(),
                        )
                    })?;

                debug!("Impersonating SYSTEM to access CNG key");
                let decrypted_aes_key = {
                    let _guard = ImpersonationGuard::new()?;
                    self.decrypt_with_cng(encrypted_aes_key)?
                };

                let xored_aes_key = self.byte_xor(&decrypted_aes_key, &xor_key);
                let cipher = Aes256Gcm::new_from_slice(&xored_aes_key)
                    .map_err(|e| BrowserVoyageError::InvalidKeyLength(format!("{e:?}")))?;
                let nonce = Nonce::from_slice(&parsed_data.iv);

                let mut combined = parsed_data.ciphertext.clone();
                combined.extend_from_slice(&parsed_data.tag);

                cipher
                    .decrypt(nonce, combined.as_ref())
                    .map_err(|e| BrowserVoyageError::DecryptionFailed(format!("AES: {e}")))
            }
            _ => Err(BrowserVoyageError::ParseError(format!(
                "Unsupported flag: {}",
                parsed_data.flag
            ))),
        }
    }

    fn extract_cookies(
        &self,
        master_key: &[u8],
        profile_path: &Path,
    ) -> BrowserVoyageResult<Vec<Cookie>> {
        let cookie_db_path = profile_path.join("Network/Cookies");

        info!("Connecting to {} cookie database", self.config.name);
        let conn = Connection::open_with_flags(
            &cookie_db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;

        let mut stmt =
            conn.prepare("SELECT host_key, name, CAST(encrypted_value AS BLOB), path, expires_utc, is_secure from cookies")?;
        let cookies = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, bool>(5)?,
            ))
        })?;

        let mut extracted_cookies = Vec::new();
        let mut total_cookies = 0;
        let mut encrypted_cookies = 0;
        let mut non_prefixed_cookies = 0;

        for cookie in cookies {
            let (host_key, name, encrypted_value, path, expiry, is_secure) = cookie?;
            total_cookies += 1;

            if encrypted_value.is_empty() {
                debug!(
                    "Skipping cookie {}/{} - empty encrypted_value",
                    host_key, name
                );
                continue;
            }

            debug!(
                "Processing cookie {}/{}: encrypted_value length = {}, first 3 bytes = {:?}",
                host_key,
                name,
                encrypted_value.len(),
                if encrypted_value.len() >= 3 {
                    String::from_utf8_lossy(&encrypted_value[..3])
                } else {
                    "N/A".into()
                }
            );

            if encrypted_value.len() > 3
                && (&encrypted_value[..3] == b"v20"
                    || &encrypted_value[..3] == b"v10"
                    || &encrypted_value[..3] == b"v11")
            {
                encrypted_cookies += 1;

                // Log full encrypted_value for debugging
                debug!(
                    "Cookie {}/{} encrypted_value (full hex): {}",
                    host_key,
                    name,
                    hex::encode(&encrypted_value)
                );

                match self.decrypt_chromium_value(&encrypted_value, master_key, Some(&host_key)) {
                    Ok(decrypted_value) => {
                        debug!("Successfully decrypted cookie {}/{}", host_key, name);
                        extracted_cookies.push(Cookie {
                            host: host_key.clone(),
                            name,
                            value: decrypted_value,
                            path,
                            expiry,
                            is_secure,
                        });
                    }
                    Err(e) => {
                        debug!("Failed to decrypt cookie {}/{}: {}", host_key, name, e);
                    }
                }
            } else {
                non_prefixed_cookies += 1;
                debug!(
                    "Skipping cookie {}/{} - no recognized encryption prefix",
                    host_key, name
                );
            }
        }

        debug!("Cookie processing summary for {}: total={}, encrypted={}, non-prefixed={}, extracted={}", 
               self.config.name, total_cookies, encrypted_cookies, non_prefixed_cookies, extracted_cookies.len());

        info!("Successfully extracted {} cookies", extracted_cookies.len());
        Ok(extracted_cookies)
    }

    fn extract_credentials(
        &self,
        master_key: &[u8],
        profile_path: &Path,
    ) -> BrowserVoyageResult<Vec<Credential>> {
        let login_db_path = profile_path.join("Login Data");

        if !login_db_path.exists() {
            debug!("Login Data database not found at: {:?}", login_db_path);
            return Ok(Vec::new());
        }

        info!("Connecting to {} Login Data database", self.config.name);

        // Try to copy the database file if it's locked
        let profile_name = profile_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        let temp_path = std::env::temp_dir().join(format!(
            "{}_{}_login_data_temp.db",
            self.config.name.to_lowercase(),
            profile_name
        ));
        let db_path = if Connection::open_with_flags(
            &login_db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .is_err()
        {
            // Database is locked, copy it
            std::fs::copy(&login_db_path, &temp_path)
                .map_err(|e| BrowserVoyageError::Io(format!("Failed to copy Login Data: {e}")))?;
            &temp_path
        } else {
            &login_db_path
        };

        let conn =
            Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;

        let mut stmt =
            conn.prepare("SELECT origin_url, username_value, password_value FROM logins")?;
        let credentials = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;

        let mut extracted_credentials = Vec::new();

        for credential in credentials {
            let (origin_url, username, encrypted_password) = credential?;

            if !encrypted_password.is_empty()
                && !origin_url.is_empty()
                && encrypted_password.len() > 3
                && (&encrypted_password[..3] == b"v20"
                    || &encrypted_password[..3] == b"v10"
                    || &encrypted_password[..3] == b"v11")
            {
                // Log full encrypted_password for debugging
                debug!(
                    "Credential {} encrypted_password (full hex): {}",
                    origin_url,
                    hex::encode(&encrypted_password)
                );

                match self.decrypt_chromium_value(&encrypted_password, master_key, None) {
                    Ok(decrypted_password) => {
                        extracted_credentials.push(Credential {
                            url: origin_url,
                            username,
                            password: decrypted_password,
                        });
                    }
                    Err(e) => {
                        debug!("Failed to decrypt password for {}: {}", origin_url, e);
                    }
                }
            }
        }

        // Clean up temp file if we used it
        if db_path == &temp_path {
            let _ = std::fs::remove_file(&temp_path);
        }

        info!(
            "Successfully extracted {} credentials",
            extracted_credentials.len()
        );
        Ok(extracted_credentials)
    }

    /// Finds all browser profiles for this browser type
    fn find_profiles(&self) -> BrowserVoyageResult<Vec<crate::common::BrowserProfile>> {
        let user_data_path = &self.user_data_path;
        let mut profiles = Vec::new();

        // Check for Default profile first to preserve its priority
        let default_path = user_data_path.join("Default");
        if default_path.exists() {
            profiles.push(crate::common::BrowserProfile::new(
                "Default".to_string(),
                default_path,
                true,
            ));
        }

        // Scan for other profile directories (e.g., "Profile 1", "Profile 2")
        if let Ok(entries) = fs::read_dir(user_data_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with("Profile ") {
                            profiles.push(crate::common::BrowserProfile::new(
                                name.to_string(),
                                path,
                                false,
                            ));
                        }
                    }
                }
            }
        }

        Ok(profiles)
    }

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

            // Use cached master key (no impersonation needed)
            let master_key = self.cached_master_key.as_ref()
                .ok_or_else(|| BrowserVoyageError::DecryptionFailed(
                    "Master key not initialized. Call initialize_master_key_with_impersonation first.".into()
                ))?;

            let cipher = Aes256Gcm::new_from_slice(master_key)
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

impl BrowserExtractor for WindowsChromeExtractor {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn extract(&mut self) -> BrowserVoyageResult<ExtractedData> {
        info!(
            "User data path for {}: {:?}",
            self.config.name, self.user_data_path
        );
        self.initialize_master_key_with_impersonation()?;
        let master_key = self.get_master_key()?;

        let profiles = self.find_profiles()?;
        let mut all_profile_data = Vec::new();

        if profiles.is_empty() {
            warn!("No profiles found for {}", self.config.name);
        }

        for profile in profiles {
            debug!("Extracting data from profile: {}", profile.name);
            // Using unwrap_or_default to continue even if one db fails, e.g. profile is not in use
            let cookies = self
                .extract_cookies(&master_key, &profile.path)
                .unwrap_or_default();
            let credentials = self
                .extract_credentials(&master_key, &profile.path)
                .unwrap_or_default();

            if cookies.is_empty() && credentials.is_empty() {
                debug!("No data extracted from profile: {}", profile.name);
                continue;
            }

            all_profile_data.push(ProfileData {
                name: profile.name,
                path: profile.path.display().to_string(),
                cookies,
                credentials,
            });
        }

        Ok(ExtractedData {
            browser: BrowserInfo {
                name: self.config.name.clone(),
                vendor: self.config.vendor.clone(),
                platform: "Windows".to_string(),
            },
            profiles: all_profile_data,
        })
    }
}

impl ChromeExtractorBase for WindowsChromeExtractor {
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
        // Return cached key (should already be initialized by extract())
        self.cached_master_key.clone().ok_or_else(|| {
            BrowserVoyageError::DecryptionFailed(
                "Master key not initialized. This is a programming error.".into(),
            )
        })
    }
}

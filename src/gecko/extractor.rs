use super::data::*;
use crate::browser_extractor::{
    BrowserExtractor, BrowserInfo, Cookie, Credential, ExtractedData, ProfileData,
};
use crate::error::{BrowserVoyageError, BrowserVoyageResult};
use base64::{engine::general_purpose, Engine};
use rusqlite::{Connection, OpenFlags};
use std::{
    fs::{self, File},
    io::{BufReader, Read},
    path::{Path, PathBuf},
};
use tracing::{debug, info, warn};

use super::asn1pbe::ASN1PBE;

static SQLITE_FLAGS: OpenFlags = {
    let read_only = OpenFlags::SQLITE_OPEN_READ_ONLY;
    let no_mutex = OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let shared_cache = OpenFlags::SQLITE_OPEN_SHARED_CACHE;
    let uri = OpenFlags::SQLITE_OPEN_URI;
    read_only.union(no_mutex).union(shared_cache).union(uri)
};

#[derive(Debug)]
pub struct GeckoExtractor {
    browser_name: String,
    browser_path: PathBuf,
}

impl GeckoExtractor {
    pub fn new(browser_name: String, browser_path: PathBuf) -> Self {
        Self {
            browser_name,
            browser_path,
        }
    }

    pub fn find_firefox_installations() -> Vec<(String, PathBuf)> {
        let mut installations = Vec::new();

        #[cfg(target_os = "windows")]
        {
            let user_profile = match std::env::var("USERPROFILE") {
                Ok(p) => p,
                Err(_) => return installations,
            };

            let base_path = PathBuf::from(&user_profile).join("AppData/Roaming/Mozilla/Firefox");
            if base_path.exists() {
                installations.push(("Firefox".to_string(), base_path.clone()));
            }

            let dev_path = PathBuf::from(&user_profile)
                .join("AppData/Roaming/Mozilla/Firefox Developer Edition");
            if dev_path.exists() {
                installations.push(("Firefox Developer Edition".to_string(), dev_path));
            }

            let nightly_path =
                PathBuf::from(&user_profile).join("AppData/Roaming/Mozilla/Firefox Nightly");
            if nightly_path.exists() {
                installations.push(("Firefox Nightly".to_string(), nightly_path));
            }
        }

        #[cfg(target_os = "linux")]
        {
            use directories::UserDirs;
            if let Some(user_dirs) = UserDirs::new() {
                let home = user_dirs.home_dir();
                
                // Standard Firefox profiles location on Linux
                let firefox_dir = home.join(".mozilla/firefox");
                if firefox_dir.exists() {
                    installations.push(("Firefox".to_string(), firefox_dir.clone()));
                }

                // Firefox Developer Edition
                let dev_dir = home.join(".mozilla/firefox-dev");
                if dev_dir.exists() {
                    installations.push(("Firefox Developer Edition".to_string(), dev_dir));
                }

                // Firefox Nightly
                let nightly_dir = home.join(".mozilla/firefox-nightly");
                if nightly_dir.exists() {
                    installations.push(("Firefox Nightly".to_string(), nightly_dir));
                }

                // Firefox ESR
                let esr_dir = home.join(".mozilla/firefox-esr");
                if esr_dir.exists() {
                    installations.push(("Firefox ESR".to_string(), esr_dir));
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            use directories::UserDirs;
            if let Some(user_dirs) = UserDirs::new() {
                let home = user_dirs.home_dir();
                
                // Standard Firefox on macOS
                let firefox_dir = home.join("Library/Application Support/Firefox");
                if firefox_dir.exists() {
                    installations.push(("Firefox".to_string(), firefox_dir.clone()));
                }

                // Firefox Developer Edition on macOS
                let dev_dir = home.join("Library/Application Support/Firefox Developer Edition");
                if dev_dir.exists() {
                    installations.push(("Firefox Developer Edition".to_string(), dev_dir));
                }

                // Firefox Nightly on macOS
                let nightly_dir = home.join("Library/Application Support/Firefox Nightly");
                if nightly_dir.exists() {
                    installations.push(("Firefox Nightly".to_string(), nightly_dir));
                }
            }
        }

        installations
    }

    fn get_profiles(&self) -> BrowserVoyageResult<Vec<PathBuf>> {
        // On Windows, Firefox profiles are in a "Profiles" subdirectory
        // On Linux/macOS, profiles are directly in the Firefox directory
        #[cfg(target_os = "windows")]
        let profile_folder = self.browser_path.join("Profiles");
        
        #[cfg(not(target_os = "windows"))]
        let profile_folder = self.browser_path.clone();

        if !profile_folder.exists() {
            return Err(BrowserVoyageError::Io(format!(
                "Profile folder not found: {profile_folder:?}"
            )));
        }

        // Try to parse profiles.ini if it exists (standard Firefox behavior)
        let profiles_ini = profile_folder.join("profiles.ini");
        if profiles_ini.exists() {
            if let Ok(profiles) = self.parse_profiles_ini(&profiles_ini) {
                if !profiles.is_empty() {
                    debug!("Found {} profiles from profiles.ini", profiles.len());
                    return Ok(profiles);
                }
            }
        }

        // Fallback: scan for profile directories manually
        let profiles: Vec<_> = fs::read_dir(&profile_folder)
            .map_err(|e| {
                BrowserVoyageError::Io(format!("Failed to read profiles directory: {e}"))
                    .with_info(format!("Profile folder: {profile_folder:?}"))
            })?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_dir() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        // Look for profile directories (contain dots and end with profile names)
                        if name.contains('.') && (
                            name.contains("default") || 
                            name.contains("release") ||
                            name.len() > 8  // Profile hash is usually longer
                        ) {
                            return Some(entry.path());
                        }
                    }
                }
                None
            })
            .collect();

        if profiles.is_empty() {
            return Err(BrowserVoyageError::NoDataFound
                .with_info(format!("No profiles found in {profile_folder:?}")));
        }
        
        debug!("Found {} profiles by directory scanning", profiles.len());
        Ok(profiles)
    }

    fn parse_profiles_ini(&self, profiles_ini_path: &PathBuf) -> BrowserVoyageResult<Vec<PathBuf>> {
        let content = fs::read_to_string(profiles_ini_path)
            .map_err(|e| BrowserVoyageError::Io(format!("Failed to read profiles.ini: {e}")))?;

        let mut profiles = Vec::new();
        let mut current_section = String::new();
        let mut is_default = false;
        let mut path: Option<PathBuf> = None;

        for line in content.lines() {
            let line = line.trim();
            
            if line.starts_with('[') && line.ends_with(']') {
                // Process previous profile if any
                if current_section.starts_with("Profile") {
                    if let Some(profile_path) = path.take() {
                        let full_path = if profile_path.is_absolute() {
                            profile_path
                        } else {
                            self.browser_path.join(profile_path)
                        };
                        
                        if full_path.exists() {
                            if is_default {
                                // Insert default profile at the beginning
                                profiles.insert(0, full_path);
                            } else {
                                profiles.push(full_path);
                            }
                        }
                    }
                }
                
                // Start new section
                current_section = line[1..line.len()-1].to_string();
                is_default = false;
                path = None;
                continue;
            }

            if current_section.starts_with("Profile") {
                if let Some((key, value)) = line.split_once('=') {
                    match key.trim() {
                        "Path" => path = Some(PathBuf::from(value.trim())),
                        "IsRelative" => {
                            // Handle relative vs absolute paths
                            if value.trim() == "0" && path.is_some() {
                                // Absolute path, use as is
                            }
                        },
                        "Default" => is_default = value.trim() == "1",
                        _ => {}
                    }
                }
            }
        }

        // Process the last profile
        if current_section.starts_with("Profile") {
            if let Some(profile_path) = path {
                let full_path = if profile_path.is_absolute() {
                    profile_path
                } else {
                    self.browser_path.join(profile_path)
                };
                
                if full_path.exists() {
                    if is_default {
                        profiles.insert(0, full_path);
                    } else {
                        profiles.push(full_path);
                    }
                }
            }
        }

        Ok(profiles)
    }

    fn get_database_path(&self, profile: &PathBuf, filename: &str) -> Option<PathBuf> {
        let path = profile.join(filename);
        if path.exists() {
            Some(path)
        } else {
            warn!("{} not found in profile directory: {:?}", filename, profile);
            None
        }
    }

    fn establish_connection(&self, path: &PathBuf) -> BrowserVoyageResult<Connection> {
        let try_connect = |p: &PathBuf| -> BrowserVoyageResult<Connection> {
            let uri = format!("file:{}?mode=ro&immutable=1", p.display());
            Connection::open_with_flags(&uri, SQLITE_FLAGS).map_err(|e| {
                BrowserVoyageError::DatabaseError(e).with_info(format!("Database: {p:?}"))
            })
        };

        match try_connect(path) {
            Ok(conn) => Ok(conn),
            Err(_) => {
                let temp_dir = std::env::temp_dir();
                let temp_file = temp_dir.join(format!(
                    "temp_{}",
                    path.file_name().unwrap().to_string_lossy()
                ));
                fs::copy(path, &temp_file).map_err(|e| {
                    BrowserVoyageError::Io(format!("Failed to copy database: {e}"))
                        .with_info(format!("Source: {path:?}"))
                })?;

                match Connection::open_with_flags(&temp_file, SQLITE_FLAGS) {
                    Ok(conn) => Ok(conn),
                    Err(e) => {
                        let _ = fs::remove_file(temp_file);
                        Err(BrowserVoyageError::DatabaseError(e)
                            .with_info("Failed to open temp database".to_string()))
                    }
                }
            }
        }
    }

    fn query_key4_metadata(&self, profile: &PathBuf) -> BrowserVoyageResult<Option<Key4MetaData>> {
        let key4_path = match self.get_database_path(profile, "key4.db") {
            Some(path) => path,
            None => return Ok(None),
        };

        let conn = self.establish_connection(&key4_path)?;
        let mut stmt = conn.prepare("SELECT item1, item2 FROM metaData WHERE id = 'password'")?;

        let metadata = stmt
            .query_map([], |row| Ok(Key4MetaData::new(row.get(0)?, row.get(1)?)))
            .map_err(|e| {
                BrowserVoyageError::DatabaseError(e)
                    .with_info(format!("Failed to query metadata from {key4_path:?}"))
            })?
            .next()
            .transpose()?;

        Ok(metadata)
    }

    fn query_nss_private(&self, profile: &PathBuf) -> BrowserVoyageResult<Option<Key4NssPrivate>> {
        let key4_path = match self.get_database_path(profile, "key4.db") {
            Some(path) => path,
            None => return Ok(None),
        };

        let conn = self.establish_connection(&key4_path)?;
        let mut stmt = conn.prepare("SELECT a11, a102 from nssPrivate")?;

        let nss_private = stmt
            .query_map([], |row| Ok(Key4NssPrivate::new(row.get(0)?, row.get(1)?)))
            .map_err(|e| {
                BrowserVoyageError::DatabaseError(e)
                    .with_info(format!("Failed to query nssPrivate from {key4_path:?}"))
            })?
            .next()
            .transpose()?;

        Ok(nss_private)
    }

    fn query_cookies(&self, profile: &PathBuf) -> BrowserVoyageResult<Vec<Cookie>> {
        let cookies_path = match self.get_database_path(profile, "cookies.sqlite") {
            Some(path) => path,
            None => return Ok(Vec::new()),
        };

        const MAX_RETRIES: u32 = 5;
        const INITIAL_WAIT_MS: u64 = 100;
        let mut last_error = None;

        for attempt in 0..MAX_RETRIES {
            match (|| -> BrowserVoyageResult<Vec<Cookie>> {
                let mut conn = self.establish_connection(&cookies_path)?;

                let count: i32 = conn
                    .query_row("SELECT COUNT(*) FROM moz_cookies", [], |row| row.get(0))
                    .map_err(|e| {
                        BrowserVoyageError::DatabaseError(e).with_info("Failed to count cookies")
                    })?;

                if count == 0 {
                    return Ok(Vec::new());
                }

                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let mut stmt = tx.prepare_cached(
                    "SELECT host, name, value, path, expiry, isSecure
                     FROM moz_cookies
                     WHERE host NOT LIKE 'chrome:%'
                     AND host NOT LIKE 'about:%'",
                )?;

                let cookies = stmt
                    .query_map([], |row| {
                        Ok(Cookie {
                            host: row.get(0)?,
                            name: row.get(1)?,
                            value: row.get(2)?,
                            path: row.get(3)?,
                            expiry: row.get(4)?,
                            is_secure: row.get(5)?,
                        })
                    })?
                    .filter_map(Result::ok)
                    .collect();

                Ok(cookies)
            })() {
                Ok(cookies) => return Ok(cookies),
                Err(e) => {
                    last_error = Some(e);
                    if attempt < MAX_RETRIES - 1 {
                        std::thread::sleep(std::time::Duration::from_millis(
                            INITIAL_WAIT_MS * (2_u64.pow(attempt)),
                        ));
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            BrowserVoyageError::NoDataFound
                .with_info(format!("Failed to read cookies from {cookies_path:?}"))
        }))
    }

    fn query_accounts(
        &self,
        profile: &Path,
        master_key: &[u8],
    ) -> BrowserVoyageResult<Vec<Credential>> {
        let logins_path = profile.join("logins.json");
        if !logins_path.exists() {
            return Ok(Vec::new());
        }

        let mut reader = BufReader::new(File::open(&logins_path).map_err(|e| {
            BrowserVoyageError::Io(format!("Failed to open logins.json: {e}"))
                .with_info(format!("Path: {logins_path:?}"))
        })?);
        let mut buffer = String::new();
        reader.read_to_string(&mut buffer)?;

        let json: GeckoAccount = serde_json::from_str(&buffer)?;
        let mut credentials = Vec::new();

        for login in json.logins {
            let result = (|| -> BrowserVoyageResult<Credential> {
                let decoded_username = general_purpose::STANDARD
                    .decode(&login.encrypted_username)
                    .map_err(|_| BrowserVoyageError::Base64Error)?;
                let decoded_password = general_purpose::STANDARD
                    .decode(&login.encrypted_password)
                    .map_err(|_| BrowserVoyageError::Base64Error)?;

                let user_pbe = ASN1PBE::new(&decoded_username)?;
                let password_pbe = ASN1PBE::new(&decoded_password)?;

                Ok(Credential {
                    url: login.hostname,
                    username: String::from_utf8(user_pbe.decrypt(master_key)?)?,
                    password: String::from_utf8(password_pbe.decrypt(master_key)?)?,
                })
            })();

            if let Ok(cred) = result {
                credentials.push(cred);
            }
        }

        Ok(credentials)
    }

    fn process_master_key(
        &self,
        metadata: &Key4MetaData,
        nss: &Key4NssPrivate,
    ) -> BrowserVoyageResult<Vec<u8>> {
        const PASSWORD_CHECK: &[u8] = b"password-check";
        const KEY_LIN: &[u8] = &[248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        let meta_pbe = ASN1PBE::new(&metadata.item2)?;
        let flag = meta_pbe.decrypt(&metadata.item1)?;

        if !flag
            .windows(PASSWORD_CHECK.len())
            .any(|window| window == PASSWORD_CHECK)
        {
            return Err(BrowserVoyageError::DecryptionFailed(
                "password-check validation failed".into(),
            ));
        }

        if nss.nss_a102 != KEY_LIN {
            return Err(BrowserVoyageError::DecryptionFailed(
                "nssA102 validation failed".into(),
            ));
        }

        let nss_a11_pbe = ASN1PBE::new(&nss.nss_a11)?;
        let final_key = nss_a11_pbe.decrypt(&metadata.item1)?;

        if final_key.len() < 24 {
            return Err(BrowserVoyageError::DecryptionFailed(
                "final key length validation failed".into(),
            ));
        }

        Ok(final_key[..24].to_vec())
    }
}

impl BrowserExtractor for GeckoExtractor {
    fn name(&self) -> &str {
        &self.browser_name
    }

    fn extract(&mut self) -> BrowserVoyageResult<ExtractedData> {
        info!("Starting {} extraction", self.browser_name);
        let mut profile_data_vec = Vec::new();

        for profile_path in self.get_profiles()? {
            let profile_name = profile_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown")
                .to_string();

            info!("Processing profile: {}", profile_name);

            let result = (|| -> BrowserVoyageResult<Option<ProfileData>> {
                let metadata = match self.query_key4_metadata(&profile_path)? {
                    Some(data) => data,
                    None => {
                        debug!("No metadata found for profile: {:?}", profile_path);
                        return Ok(None);
                    }
                };

                let nss_private = match self.query_nss_private(&profile_path)? {
                    Some(data) => data,
                    None => {
                        debug!("No NSS private data found for profile: {:?}", profile_path);
                        return Ok(None);
                    }
                };

                let final_key = self.process_master_key(&metadata, &nss_private)?;
                let cookies = self.query_cookies(&profile_path)?;
                let credentials = self.query_accounts(&profile_path, &final_key)?;

                if !cookies.is_empty() || !credentials.is_empty() {
                    info!(
                        "Found {} cookies and {} credentials in profile {}",
                        cookies.len(),
                        credentials.len(),
                        profile_name
                    );

                    let profile_data = ProfileData {
                        name: profile_name,
                        path: profile_path.to_string_lossy().to_string(),
                        cookies,
                        credentials,
                    };

                    return Ok(Some(profile_data));
                }

                Ok(None)
            })();

            match result {
                Ok(Some(profile_data)) => {
                    profile_data_vec.push(profile_data);
                }
                Ok(None) => {
                    debug!("No data extracted from profile: {:?}", profile_path);
                }
                Err(e) => {
                    warn!("Failed to process profile {:?}: {}", profile_path, e);
                }
            }
        }

        if profile_data_vec.is_empty() {
            return Err(BrowserVoyageError::NoDataFound
                .with_info(format!("No valid profiles found for {}", self.browser_name)));
        }

        Ok(ExtractedData {
            browser: BrowserInfo {
                name: self.browser_name.clone(),
                vendor: "Mozilla".to_string(),
                platform: std::env::consts::OS.to_string(),
            },
            profiles: profile_data_vec,
        })
    }
}

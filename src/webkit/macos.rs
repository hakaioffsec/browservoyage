use crate::browser_extractor::{BrowserExtractor, BrowserInfo, Cookie, ExtractedData, ProfileData};
use crate::error::{BrowserVoyageError, BrowserVoyageResult};
use binary_cookies::BinaryCookiesReader;
use std::{fs::File, io::Read, path::PathBuf};
use tracing::{debug, warn};

pub struct SafariExtractor {
    name: String,
    vendor: String,
    platform: String,
}

impl SafariExtractor {
    pub fn new() -> Self {
        SafariExtractor {
            name: "Safari".to_string(),
            vendor: "Apple".to_string(),
            platform: "macOS".to_string(),
        }
    }

    pub fn find_safari_installations() -> Vec<(String, PathBuf)> {
        let mut installations = Vec::new();

        // Safari uses a sandboxed container location on modern macOS
        let home = match std::env::var("HOME") {
            Ok(h) => h,
            Err(e) => {
                warn!("Could not get HOME environment variable: {}", e);
                return installations;
            }
        };

        // Modern Safari container path
        let safari_container_path = PathBuf::from(&home)
            .join("Library")
            .join("Containers")
            .join("com.apple.Safari")
            .join("Data")
            .join("Library");

        debug!(
            "Looking for Safari container at: {:?}",
            safari_container_path
        );

        if safari_container_path.exists() {
            debug!(
                "Safari container directory exists at: {:?}",
                safari_container_path
            );
            installations.push(("Safari".to_string(), safari_container_path));
        } else {
            // Try legacy Safari path as fallback
            let legacy_safari_path = PathBuf::from(&home).join("Library").join("Safari");
            debug!(
                "Safari container not found, trying legacy path: {:?}",
                legacy_safari_path
            );

            if legacy_safari_path.exists() {
                debug!(
                    "Legacy Safari directory exists at: {:?}",
                    legacy_safari_path
                );
                installations.push(("Safari".to_string(), legacy_safari_path));
            } else {
                warn!("Safari not found at container or legacy paths");
            }
        }

        installations
    }

    fn get_cookies_path(&self, safari_base: &PathBuf) -> BrowserVoyageResult<PathBuf> {
        let cookies_path = safari_base.join("Cookies").join("Cookies.binarycookies");

        debug!("Checking cookies path: {:?}", cookies_path);

        // First check if we can access the Safari directory itself
        if let Err(e) = std::fs::read_dir(safari_base) {
            warn!("Cannot access Safari directory {:?}: {}", safari_base, e);
            let is_container_path = safari_base
                .to_string_lossy()
                .contains("Containers/com.apple.Safari");
            return Err(BrowserVoyageError::AccessDenied(format!(
                "Cannot access Safari {} directory at {}. Grant Full Disk Access to your terminal or IDE in System Settings > Privacy & Security > Full Disk Access",
                if is_container_path { "container" } else { "" },
                safari_base.display()
            )));
        }

        // Then check if the Cookies subdirectory exists and is accessible
        let cookies_dir = safari_base.join("Cookies");
        if let Err(e) = std::fs::read_dir(&cookies_dir) {
            warn!(
                "Cannot access Safari Cookies directory {:?}: {}",
                cookies_dir, e
            );
            return Err(BrowserVoyageError::AccessDenied(
                "Cannot access Safari Cookies directory. Grant Full Disk Access to your terminal or IDE in System Settings > Privacy & Security > Full Disk Access".to_string()
            ));
        }

        if !cookies_path.exists() {
            debug!("Cookies file does not exist at {:?}", cookies_path);
            return Err(BrowserVoyageError::NoDataFound);
        }

        Ok(cookies_path)
    }

    fn clean_cookie_value(value: &str) -> String {
        // Safari binary cookies sometimes include binary plist metadata at the end
        // Look for the "bplist" marker and truncate before it
        if let Some(pos) = value.find("bplist") {
            value[..pos].to_string()
        } else {
            // Also check for other common binary markers
            let cleaned = value
                .trim_end_matches(|c: char| c.is_control() || c == '\0')
                .trim();
            cleaned.to_string()
        }
    }

    fn query_cookies(&self, cookies_path: &PathBuf) -> BrowserVoyageResult<Vec<Cookie>> {
        let mut file = File::open(cookies_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                BrowserVoyageError::AccessDenied(
                    "Cannot read Safari cookies file. Grant Full Disk Access to your terminal or IDE in System Settings > Privacy & Security > Full Disk Access".to_string()
                )
            } else {
                BrowserVoyageError::Io(format!("Failed to open cookies file: {}", e))
            }
        })?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| BrowserVoyageError::Io(format!("Failed to read cookies file: {}", e)))?;

        let mut reader = BinaryCookiesReader::from_vec(&data);
        reader.decode().map_err(|e| {
            BrowserVoyageError::ParseError(format!("Failed to decode binary cookies: {}", e))
        })?;

        let cookies = reader
            .origin_pages()
            .iter()
            .flat_map(|page| page.cookies())
            .map(|cookie| {
                // Clean up cookie values that may contain binary plist metadata
                let clean_value = Self::clean_cookie_value(&cookie.value_str());

                Cookie {
                    host: cookie.domain_str().to_string(),
                    name: cookie.name_str().to_string(),
                    value: clean_value,
                    path: cookie.path_str().to_string(),
                    is_secure: cookie.secure,
                    expiry: cookie.expires as i64,
                }
            })
            .collect();

        Ok(cookies)
    }
}

impl BrowserExtractor for SafariExtractor {
    fn name(&self) -> &str {
        &self.name
    }

    fn extract(&mut self) -> BrowserVoyageResult<ExtractedData> {
        let mut profiles = Vec::new();

        let installations = Self::find_safari_installations();
        debug!("Found {} Safari installations", installations.len());

        for (name, path) in installations {
            debug!("Processing Safari profile '{}' at: {:?}", name, path);

            match self.get_cookies_path(&path) {
                Ok(cookies_path) => {
                    debug!("Found cookies file at: {:?}", cookies_path);
                    match self.query_cookies(&cookies_path) {
                        Ok(cookies) => {
                            debug!("Successfully extracted {} cookies", cookies.len());
                            if !cookies.is_empty() {
                                let profile = ProfileData {
                                    name: name.clone(),
                                    path: path.to_string_lossy().to_string(),
                                    cookies,
                                    credentials: Vec::new(), // Safari doesn't store credentials in a way we can extract
                                };
                                profiles.push(profile);
                            } else {
                                warn!("No cookies found in cookies file");
                            }
                        }
                        Err(e) => {
                            warn!("Failed to process cookies: {}", e);
                        }
                    }
                }
                Err(e) => {
                    // If it's an AccessDenied error, propagate it immediately
                    if matches!(e, BrowserVoyageError::AccessDenied(_)) {
                        return Err(e);
                    }
                    warn!("Failed to get cookies path for profile {}: {}", name, e);
                }
            }
        }

        if profiles.is_empty() {
            debug!("No Safari profiles found with data");
            return Err(BrowserVoyageError::NoDataFound);
        }

        Ok(ExtractedData {
            browser: BrowserInfo {
                name: self.name.clone(),
                vendor: self.vendor.clone(),
                platform: self.platform.clone(),
            },
            profiles,
        })
    }
}

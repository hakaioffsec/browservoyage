//! Modern Safari (WebKit) browser extractor using common abstractions

use crate::browser_extractor::{BrowserExtractor, BrowserInfo, Cookie, ExtractedData, ProfileData};
use crate::common::PlatformUtils;
use crate::error::{BrowserVoyageError, BrowserVoyageResult};
use binary_cookies::BinaryCookiesReader;
use std::{fs::File, io::Read, path::PathBuf};
use tracing::{debug, info};

/// Safari browser configuration
#[derive(Debug, Clone)]
pub struct SafariBrowserConfig {
    pub name: String,
    pub vendor: String,
    pub platform: String,
    pub container_id: String,
}

impl SafariBrowserConfig {
    pub fn safari() -> Self {
        Self {
            name: "Safari".to_string(),
            vendor: "Apple".to_string(),
            platform: "macOS".to_string(),
            container_id: "com.apple.Safari".to_string(),
        }
    }
}

/// Modern Safari extractor with improved organization
#[derive(Debug)]
pub struct SafariExtractor {
    config: SafariBrowserConfig,
    container_path: Option<PathBuf>,
}

impl SafariExtractor {
    /// Create a new Safari extractor
    pub fn new() -> Self {
        let config = SafariBrowserConfig::safari();
        let container_path = Self::find_safari_container();

        Self {
            config,
            container_path,
        }
    }

    /// Find Safari container path on modern macOS
    fn find_safari_container() -> Option<PathBuf> {
        let home_dir = PlatformUtils::get_home_dir()?;

        // Modern Safari container path
        let safari_container_path = home_dir
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
                "Safari container directory found at: {:?}",
                safari_container_path
            );
            Some(safari_container_path)
        } else {
            debug!("Safari container not found, checking legacy location");
            // Try legacy location
            let legacy_path = home_dir.join("Library").join("Safari");
            if legacy_path.exists() {
                debug!("Legacy Safari directory found at: {:?}", legacy_path);
                Some(legacy_path)
            } else {
                debug!("No Safari installation found");
                None
            }
        }
    }

    /// Get the path to Safari's binary cookies file
    fn get_cookies_file_path(&self) -> Option<PathBuf> {
        let container_path = self.container_path.as_ref()?;

        // Try different possible cookie file locations
        let possible_paths = [
            container_path.join("Cookies").join("Cookies.binarycookies"),
            container_path.join("Safari").join("Cookies.binarycookies"),
        ];

        for path in &possible_paths {
            debug!("Checking for cookies file at: {:?}", path);
            if path.exists() {
                debug!("Found cookies file at: {:?}", path);
                return Some(path.clone());
            }
        }

        debug!("No cookies file found in any expected location");
        None
    }

    /// Clean cookie values by removing binary plist data and null terminators
    fn clean_cookie_value(value: &str) -> String {
        let without_bplist = if let Some(pos) = value.find("bplist") {
            &value[..pos]
        } else {
            value
        };

        without_bplist.trim_end_matches('\0').to_string()
    }

    /// Extract cookies from Safari's binary cookies format
    fn extract_safari_cookies(&self) -> BrowserVoyageResult<Vec<Cookie>> {
        let cookies_file_path = self
            .get_cookies_file_path()
            .ok_or_else(|| BrowserVoyageError::NoDataFound)?;

        debug!("Reading cookies from: {:?}", cookies_file_path);

        let mut file = File::open(&cookies_file_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    BrowserVoyageError::AccessDenied(format!(
                        "Permission denied accessing Safari cookies. Full Disk Access may be required. Path: {}",
                        cookies_file_path.display()
                    ))
                } else {
                    BrowserVoyageError::Io(format!("Failed to open cookies file: {}", e))
                }
            })?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| BrowserVoyageError::Io(format!("Failed to read cookies file: {}", e)))?;

        debug!("Read {} bytes from cookies file", buffer.len());

        let mut reader = BinaryCookiesReader::from_vec(&buffer);
        reader.decode().map_err(|e| {
            BrowserVoyageError::ParseError(format!("Failed to decode binary cookies: {}", e))
        })?;

        let mut cookies = Vec::new();
        for page in reader.origin_pages() {
            for binary_cookie in page.cookies() {
                // Convert binary cookie to our Cookie struct
                let cookie = Cookie {
                    host: binary_cookie.domain_str().to_string(),
                    name: binary_cookie.name_str().to_string(),
                    value: Self::clean_cookie_value(&binary_cookie.value_str()),
                    path: binary_cookie.path_str().to_string(),
                    expiry: binary_cookie.expires as i64,
                    is_secure: binary_cookie.secure,
                };
                cookies.push(cookie);
            }
        }

        info!("Extracted {} cookies from Safari", cookies.len());
        Ok(cookies)
    }

    /// Check if Safari is available and accessible
    pub fn is_available(&self) -> bool {
        self.container_path.is_some() && self.get_cookies_file_path().is_some()
    }
}

impl Default for SafariExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl BrowserExtractor for SafariExtractor {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn extract(&mut self) -> BrowserVoyageResult<ExtractedData> {
        info!("Starting Safari extraction on macOS");

        if !self.is_available() {
            return Err(BrowserVoyageError::NoDataFound);
        }

        // Extract cookies (Safari doesn't store passwords in an easily accessible format)
        let cookies = self.extract_safari_cookies()?;

        // Safari typically has a single "profile" (the default)
        let profile_data = ProfileData {
            name: "Default".to_string(),
            path: self
                .container_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
            cookies,
            credentials: Vec::new(), // Safari passwords are in Keychain, not easily accessible
        };

        Ok(ExtractedData {
            browser: BrowserInfo {
                name: self.config.name.clone(),
                vendor: self.config.vendor.clone(),
                platform: self.config.platform.clone(),
            },
            profiles: vec![profile_data],
        })
    }
}

/// Legacy compatibility - creates the modern extractor
pub fn create_safari_extractor() -> SafariExtractor {
    SafariExtractor::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safari_config() {
        let config = SafariBrowserConfig::safari();
        assert_eq!(config.name, "Safari");
        assert_eq!(config.vendor, "Apple");
        assert_eq!(config.platform, "macOS");
    }

    #[test]
    fn test_safari_extractor_creation() {
        let extractor = SafariExtractor::new();
        assert_eq!(extractor.name(), "Safari");
    }

    #[test]
    fn test_container_path_discovery() {
        let path = SafariExtractor::find_safari_container();
        // This will vary based on the system, but should not panic
        println!("Safari container path: {:?}", path);
    }
}

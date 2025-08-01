//! Modern Safari (WebKit) browser extractor using common abstractions

use crate::browser_extractor::{BrowserExtractor, BrowserInfo, Cookie, ExtractedData, ProfileData};
use crate::common::PlatformUtils;
use crate::error::{BrowserVoyageError, BrowserVoyageResult};
use binary_cookies::BinaryCookiesReader;
use std::{fs::File, io::Read, path::PathBuf};
use tracing::{debug, info, warn};

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
pub struct ModernSafariExtractor {
    config: SafariBrowserConfig,
    container_path: Option<PathBuf>,
}

impl ModernSafariExtractor {
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

        let reader = BinaryCookiesReader::new(&buffer).map_err(|e| {
            BrowserVoyageError::ParseError(format!("Failed to parse binary cookies: {}", e))
        })?;

        let mut cookies = Vec::new();
        for page in reader.pages() {
            for binary_cookie in page.cookies() {
                // Convert binary cookie to our Cookie struct
                let cookie = Cookie {
                    host: binary_cookie.domain().to_string(),
                    name: binary_cookie.name().to_string(),
                    value: binary_cookie.value().to_string(),
                    path: binary_cookie.path().to_string(),
                    expiry: binary_cookie
                        .expiry_date()
                        .map(|d| d.timestamp())
                        .unwrap_or(0),
                    is_secure: binary_cookie.is_secure(),
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

impl Default for ModernSafariExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl BrowserExtractor for ModernSafariExtractor {
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
pub fn create_safari_extractor() -> ModernSafariExtractor {
    ModernSafariExtractor::new()
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
        let extractor = ModernSafariExtractor::new();
        assert_eq!(extractor.name(), "Safari");
    }

    #[test]
    fn test_container_path_discovery() {
        let path = ModernSafariExtractor::find_safari_container();
        // This will vary based on the system, but should not panic
        println!("Safari container path: {:?}", path);
    }
}

//! Common traits, abstractions, and utilities shared across browser extractors

use crate::error::BrowserVoyageResult;
use std::path::PathBuf;

/// Trait for database operations common across browsers
pub trait DatabaseOperations {
    /// Opens a database connection with appropriate flags
    fn open_database(&self, path: &std::path::Path) -> BrowserVoyageResult<rusqlite::Connection>;

    /// Checks if a database file exists and is accessible
    fn is_database_accessible(&self, path: &std::path::Path) -> bool {
        path.exists() && path.is_file()
    }
}

/// Trait for encryption/decryption operations
pub trait CryptographyOperations {
    /// Decrypts data using browser-specific methods
    fn decrypt_data(&self, encrypted_data: &[u8]) -> BrowserVoyageResult<Vec<u8>>;

    /// Gets the encryption key for the browser
    fn get_encryption_key(&self) -> BrowserVoyageResult<Vec<u8>>;
}

/// Trait for profile discovery and management
pub trait ProfileDiscovery {
    /// Finds all browser profiles for this browser type
    fn find_profiles(&self) -> BrowserVoyageResult<Vec<BrowserProfile>>;

    /// Gets the default profile path
    fn get_default_profile_path(&self) -> BrowserVoyageResult<PathBuf>;

    /// Validates that a profile directory is valid
    fn is_valid_profile(&self, path: &std::path::Path) -> bool;
}

/// Common browser profile information
#[derive(Debug, Clone)]
pub struct BrowserProfile {
    pub name: String,
    pub path: PathBuf,
    pub is_default: bool,
}

impl BrowserProfile {
    pub fn new(name: String, path: PathBuf, is_default: bool) -> Self {
        Self {
            name,
            path,
            is_default,
        }
    }
}

/// Common database paths and file names used across browsers
pub struct DatabasePaths;

impl DatabasePaths {
    pub const COOKIES_DB: &'static str = "Cookies";
    pub const LOGIN_DATA_DB: &'static str = "Login Data";
    pub const WEB_DATA_DB: &'static str = "Web Data";
    pub const HISTORY_DB: &'static str = "History";
    pub const PREFERENCES_FILE: &'static str = "Preferences";
    pub const LOCAL_STATE_FILE: &'static str = "Local State";
}

/// Common SQL queries used across Chromium-based browsers
pub struct ChromiumQueries;

impl ChromiumQueries {
    pub const COOKIES: &'static str = r#"
        SELECT host_key, name, value, path, expires_utc, is_secure, is_httponly, encrypted_value
        FROM cookies
        WHERE length(encrypted_value) > 0
    "#;

    pub const LOGINS: &'static str = r#"
        SELECT origin_url, username_value, password_value
        FROM logins
        WHERE length(password_value) > 0
    "#;

    pub const HISTORY: &'static str = r#"
        SELECT url, title, visit_count, last_visit_time
        FROM urls
        ORDER BY last_visit_time DESC
    "#;
}

/// Common SQL queries used across Firefox/Gecko browsers
pub struct GeckoQueries;

impl GeckoQueries {
    pub const COOKIES: &'static str = r#"
        SELECT host, name, value, path, expiry, isSecure
        FROM moz_cookies
    "#;

    pub const LOGINS: &'static str = r#"
        SELECT hostname, encryptedUsername, encryptedPassword
        FROM moz_logins
    "#;

    pub const HISTORY: &'static str = r#"
        SELECT p.url, p.title, p.visit_count, h.visit_date
        FROM moz_places p
        JOIN moz_historyvisits h ON p.id = h.place_id
        ORDER BY h.visit_date DESC
    "#;
}

/// Platform-specific utilities
pub struct PlatformUtils;

impl PlatformUtils {
    /// Gets the user's home directory
    pub fn get_home_dir() -> Option<PathBuf> {
        directories::UserDirs::new().map(|dirs| dirs.home_dir().to_path_buf())
    }

    /// Gets the user's local app data directory
    pub fn get_local_app_data_dir() -> Option<PathBuf> {
        directories::BaseDirs::new().map(|dirs| dirs.data_local_dir().to_path_buf())
    }

    /// Gets the user's application support directory (macOS) or app data (Windows/Linux)
    pub fn get_app_data_dir() -> Option<PathBuf> {
        directories::BaseDirs::new().map(|dirs| dirs.data_dir().to_path_buf())
    }
}

/// Utility functions for data processing
pub struct DataUtils;

impl DataUtils {
    /// Converts Windows FILETIME to Unix timestamp
    pub fn filetime_to_unix_timestamp(filetime: i64) -> i64 {
        // Windows FILETIME is 100-nanosecond intervals since January 1, 1601
        // Unix timestamp is seconds since January 1, 1970
        const EPOCH_DIFF: i64 = 11644473600; // Seconds between 1601 and 1970
        (filetime / 10_000_000) - EPOCH_DIFF
    }

    /// Converts Chrome's timestamp format to Unix timestamp
    pub fn chrome_timestamp_to_unix(chrome_time: i64) -> i64 {
        // Chrome timestamps are microseconds since January 1, 1601
        const EPOCH_DIFF_MICROSECONDS: i64 = 11644473600_000_000;
        (chrome_time - EPOCH_DIFF_MICROSECONDS) / 1_000_000
    }

    /// Converts Firefox's timestamp format to Unix timestamp
    pub fn firefox_timestamp_to_unix(firefox_time: i64) -> i64 {
        // Firefox timestamps are microseconds since Unix epoch
        firefox_time / 1_000_000
    }
}

/// Default implementation for database operations
pub struct DefaultDatabaseOps;

impl DatabaseOperations for DefaultDatabaseOps {
    fn open_database(&self, path: &std::path::Path) -> BrowserVoyageResult<rusqlite::Connection> {
        use rusqlite::OpenFlags;

        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_SHARED_CACHE;

        rusqlite::Connection::open_with_flags(path, flags)
            .map_err(|e| crate::error::BrowserVoyageError::DatabaseError(e))
    }
}

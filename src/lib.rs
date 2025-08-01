//! # BrowserVoyage
//!
//! A comprehensive browser data extraction library.
//!
//! This library provides functionality to extract cookies, credentials, and other data
//! from popular web browsers across different platforms.
//!
//! ## Example
//!
//! ```no_run
//! use browservoyage::{extract_browser_data, ExtractionConfig};
//!
//! fn main() {
//!     let config = ExtractionConfig::default();
//!     match extract_browser_data(&config) {
//!         Ok(data) => println!("Extracted data: {:?}", data),
//!         Err(e) => eprintln!("Error: {}", e),
//!     }
//! }
//! ```

pub mod browser_extractor;
pub mod browser_factory;
pub mod chrome;
pub mod cli;
pub mod common;
pub mod error;
pub mod gecko;
pub mod output;

#[cfg(target_os = "macos")]
pub mod webkit;

#[cfg(target_os = "windows")]
pub mod windows;

// Re-export commonly used types
pub use browser_extractor::{
    BrowserExtractor, BrowserInfo, Cookie, Credential, ExtractedData, ProfileData,
};
pub use error::{BrowserVoyageError, BrowserVoyageResult};

/// Content types that can be extracted from browsers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentType {
    /// Website cookies.
    Cookies,
    /// Saved login credentials.
    Credentials,
    /// Browsing history.
    History,
    /// All available content types.
    All,
}

impl ContentType {
    /// Returns a vector of all individual content types.
    pub fn all_types() -> Vec<ContentType> {
        vec![
            ContentType::Cookies,
            ContentType::Credentials,
            ContentType::History,
        ]
    }
}

/// Supported browser types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserType {
    /// Google Chrome.
    Chrome,
    /// Mozilla Firefox.
    Firefox,
    /// Microsoft Edge.
    Edge,
    /// Apple Safari.
    Safari,
    /// Brave Browser.
    Brave,
    /// The open-source Chromium browser.
    Chromium,
    /// All supported browsers.
    All,
}

impl BrowserType {
    /// Returns a vector of all Chromium-based browser types.
    pub fn chromium_based() -> Vec<BrowserType> {
        vec![
            BrowserType::Chrome,
            BrowserType::Edge,
            BrowserType::Brave,
            BrowserType::Chromium,
        ]
    }

    /// Returns a vector of all individual browser types.
    pub fn all_types() -> Vec<BrowserType> {
        vec![
            BrowserType::Chrome,
            BrowserType::Firefox,
            BrowserType::Edge,
            BrowserType::Safari,
            BrowserType::Brave,
            BrowserType::Chromium,
        ]
    }
}

/// Output formats supported by the library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputFormat {
    /// JSON format.
    Json,
    /// CSV format.
    Csv,
    /// XML format.
    Xml,
}

/// Configuration for browser data extraction.
#[derive(Debug, Clone)]
pub struct ExtractionConfig {
    /// The types of content to extract.
    pub content_types: Vec<ContentType>,
    /// The browsers to extract from.
    pub browser_types: Vec<BrowserType>,
    /// The format for the output.
    pub output_format: OutputFormat,
    /// The path to the output file. If `None`, output is written to stdout.
    pub output_path: Option<std::path::PathBuf>,
    /// Whether to enable verbose logging.
    pub verbose: bool,
}

impl Default for ExtractionConfig {
    /// Creates a default `ExtractionConfig`.
    ///
    /// By default, all content types are extracted from all browsers,
    /// and the output is formatted as JSON.
    fn default() -> Self {
        Self {
            content_types: vec![ContentType::All],
            browser_types: vec![BrowserType::All],
            output_format: OutputFormat::Json,
            output_path: None,
            verbose: false,
        }
    }
}

/// Extracts browser data based on the provided configuration.
///
/// This is the main entry point for the library. It takes an `ExtractionConfig`
/// and returns a vector of `ExtractedData` structs, one for each browser
/// that was successfully extracted.
///
/// # Arguments
///
/// * `config` - A reference to an `ExtractionConfig` that specifies what to extract.
///
/// # Returns
///
/// A `BrowserVoyageResult` containing either a vector of `ExtractedData` or a `BrowserVoyageError`.
pub fn extract_browser_data(config: &ExtractionConfig) -> BrowserVoyageResult<Vec<ExtractedData>> {
    if config.verbose {
        tracing::info!("Starting browser data extraction with config: {:?}", config);
    }

    // Get all available extractors
    let mut available_extractors = crate::browser_factory::get_extractors().unwrap_or_default();

    // Filter extractors based on browser types if not "All"
    if !config.browser_types.contains(&BrowserType::All) {
        available_extractors.retain(|extractor| {
            config
                .browser_types
                .iter()
                .any(|browser_type| matches_browser_type(extractor.name(), browser_type))
        });
    }

    let mut all_results = Vec::new();
    for mut extractor in available_extractors {
        if config.verbose {
            tracing::info!("Extracting from {}", extractor.name());
        }

        match extractor.extract() {
            Ok(mut data) => {
                // Filter content based on content types
                filter_extracted_data(&mut data, &config.content_types);

                if config.verbose {
                    tracing::info!("Successfully extracted data from {}", extractor.name());
                }
                all_results.push(data);
            }
            Err(e) => {
                tracing::warn!("Failed to extract from {}: {}", extractor.name(), e);
            }
        }
    }

    Ok(all_results)
}

/// Check if an extractor name matches a browser type
fn matches_browser_type(extractor_name: &str, browser_type: &BrowserType) -> bool {
    match browser_type {
        BrowserType::Chrome => extractor_name.eq_ignore_ascii_case("chrome"),
        BrowserType::Firefox => {
            extractor_name.eq_ignore_ascii_case("firefox") || extractor_name.contains("Firefox")
        }
        BrowserType::Edge => extractor_name.eq_ignore_ascii_case("edge"),
        BrowserType::Safari => extractor_name.eq_ignore_ascii_case("safari"),
        BrowserType::Brave => extractor_name.eq_ignore_ascii_case("brave"),
        BrowserType::Chromium => extractor_name.eq_ignore_ascii_case("chromium"),
        BrowserType::All => true,
    }
}

/// Filter extracted data based on content types
fn filter_extracted_data(data: &mut ExtractedData, content_types: &[ContentType]) {
    if content_types.contains(&ContentType::All) {
        return; // No filtering needed
    }

    for profile in &mut data.profiles {
        if !content_types.contains(&ContentType::Cookies) {
            profile.cookies.clear();
        }
        if !content_types.contains(&ContentType::Credentials) {
            profile.credentials.clear();
        }
        // TODO: Add history filtering when history extraction is implemented
    }
}

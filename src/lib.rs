//! BrowserVoyage - A comprehensive browser data extraction library
//!
//! This library provides functionality to extract cookies, credentials, and other data
//! from popular web browsers across different platforms.

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
pub use browser_factory::BrowserFactory;
pub use error::{BrowserVoyageError, BrowserVoyageResult};

/// Content types that can be extracted from browsers
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentType {
    Cookies,
    Credentials,
    History,
    All,
}

impl ContentType {
    pub fn all_types() -> Vec<ContentType> {
        vec![
            ContentType::Cookies,
            ContentType::Credentials,
            ContentType::History,
        ]
    }
}

/// Supported browser types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserType {
    Chrome,
    Firefox,
    Edge,
    Safari,
    Brave,
    Chromium,
    All,
}

impl BrowserType {
    pub fn chromium_based() -> Vec<BrowserType> {
        vec![
            BrowserType::Chrome,
            BrowserType::Edge,
            BrowserType::Brave,
            BrowserType::Chromium,
        ]
    }

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

/// Output formats supported by the library
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Csv,
    Xml,
}

/// Configuration for browser data extraction
#[derive(Debug, Clone)]
pub struct ExtractionConfig {
    pub content_types: Vec<ContentType>,
    pub browser_types: Vec<BrowserType>,
    pub output_format: OutputFormat,
    pub output_path: Option<std::path::PathBuf>,
    pub verbose: bool,
}

impl Default for ExtractionConfig {
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

/// Main extraction function that respects the configuration
pub fn extract_browser_data(config: &ExtractionConfig) -> BrowserVoyageResult<Vec<ExtractedData>> {
    if config.verbose {
        tracing::info!("Starting browser data extraction with config: {:?}", config);
    }

    // Get all available extractors
    let mut available_extractors = BrowserFactory::get_available_extractors();

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

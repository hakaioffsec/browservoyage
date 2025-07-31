use crate::browser_extractor::{BrowserExtractor, ExtractedData};
use crate::error::BrowserVoyageResult;
use tracing::info;

#[cfg(target_os = "windows")]
use crate::chrome::WindowsChromeExtractor;
use crate::gecko::GeckoExtractor;

pub struct BrowserFactory;

impl BrowserFactory {
    pub fn get_available_extractors() -> Vec<Box<dyn BrowserExtractor>> {
        let mut extractors: Vec<Box<dyn BrowserExtractor>> = Vec::new();

        // Chrome extractors
        #[cfg(target_os = "windows")]
        {
            extractors.push(Box::new(WindowsChromeExtractor::new()));
        }

        // Firefox extractors - cross-platform
        for (name, path) in GeckoExtractor::find_firefox_installations() {
            info!("Found {}: {:?}", name, path);
            extractors.push(Box::new(GeckoExtractor::new(name, path)));
        }

        extractors
    }

    pub fn extract_all() -> BrowserVoyageResult<Vec<ExtractedData>> {
        let mut all_results = Vec::new();
        let mut extractors = Self::get_available_extractors();

        for extractor in extractors.iter_mut() {
            info!("Extracting from {}", extractor.name());
            match extractor.extract() {
                Ok(data) => {
                    info!("Successfully extracted data from {}", extractor.name());
                    all_results.push(data);
                }
                Err(e) => {
                    tracing::warn!("Failed to extract from {}: {}", extractor.name(), e);
                }
            }
        }

        Ok(all_results)
    }
}

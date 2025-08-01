use crate::browser_extractor::{BrowserExtractor, ExtractedData};
use crate::error::BrowserVoyageResult;
use tracing::info;

#[cfg(target_os = "linux")]
use crate::chrome::LinuxChromeExtractor;
#[cfg(target_os = "macos")]
use crate::chrome::MacOSChromeExtractor;
#[cfg(target_os = "windows")]
use crate::chrome::WindowsChromeExtractor;
use crate::gecko::GeckoExtractor;
#[cfg(target_os = "macos")]
use crate::webkit::SafariExtractor;

/// A factory for creating browser-specific data extractors.
pub struct BrowserFactory;

impl BrowserFactory {
    /// Returns a vector of all available browser extractors for the current platform.
    ///
    /// This function checks for the presence of supported browsers and returns a
    /// vector of `Box<dyn BrowserExtractor>` for each one that is found.
    pub fn get_available_extractors() -> Vec<Box<dyn BrowserExtractor>> {
        let mut extractors: Vec<Box<dyn BrowserExtractor>> = Vec::new();

        // Chrome extractors
        #[cfg(target_os = "windows")]
        {
            extractors.push(Box::new(WindowsChromeExtractor::chrome()));
            extractors.push(Box::new(WindowsChromeExtractor::edge()));
            extractors.push(Box::new(WindowsChromeExtractor::brave()));
        }

        #[cfg(target_os = "macos")]
        {
            // Try to add Chrome
            extractors.push(Box::new(MacOSChromeExtractor::chrome()));

            // Try to add Edge
            extractors.push(Box::new(MacOSChromeExtractor::edge()));

            // Try to add Brave
            extractors.push(Box::new(MacOSChromeExtractor::brave()));

            // Try to add Chromium
            extractors.push(Box::new(MacOSChromeExtractor::chromium()));
        }

        #[cfg(target_os = "linux")]
        {
            // Try to add Chrome
            extractors.push(Box::new(LinuxChromeExtractor::chrome()));

            // Try to add Brave
            extractors.push(Box::new(LinuxChromeExtractor::brave()));

            // Try to add Chromium
            extractors.push(Box::new(LinuxChromeExtractor::chromium()));
        }

        // Firefox extractors - cross-platform
        for (name, path) in GeckoExtractor::find_firefox_installations() {
            info!("Found {}: {:?}", name, path);
            extractors.push(Box::new(GeckoExtractor::new(name, path)));
        }

        // Safari extractor - macOS only
        #[cfg(target_os = "macos")]
        {
            extractors.push(Box::new(SafariExtractor::new()));
        }

        extractors
    }

    /// Extracts data from all available browsers.
    ///
    /// This function gets all available browser extractors and calls the `extract`
    /// method on each one. It returns a vector of `ExtractedData` structs, one
    /// for each browser that was successfully extracted.
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
                    // Special handling for Safari access denied errors
                    if extractor.name() == "Safari"
                        && matches!(e, crate::error::BrowserVoyageError::AccessDenied(_))
                    {
                        tracing::error!("\n⚠️  Safari Full Disk Access Required\n");
                        tracing::error!("Failed to extract from Safari: {}", e);
                        tracing::error!("\nTo extract Safari data on macOS:");
                        tracing::error!(
                            "1. Open System Settings > Privacy & Security > Full Disk Access"
                        );
                        tracing::error!(
                            "2. Click the '+' button and add your terminal application:"
                        );
                        tracing::error!("   - Terminal.app (if using the default terminal)");
                        tracing::error!("   - iTerm2.app (if using iTerm2)");
                        tracing::error!("   - Your IDE (if running from VS Code, IntelliJ, etc.)");
                        tracing::error!("3. Restart your terminal/IDE and try again\n");
                    } else if (extractor.name() == "Chrome"
                        || extractor.name() == "Edge"
                        || extractor.name() == "Brave"
                        || extractor.name() == "Chromium")
                        && matches!(e, crate::error::BrowserVoyageError::AccessDenied(_))
                    {
                        tracing::error!("\n⚠️  {} Keychain Access Required\n", extractor.name());
                        tracing::error!("Failed to extract from {}: {}", extractor.name(), e);
                        tracing::error!("\nTo extract {} data on macOS:", extractor.name());
                        tracing::error!("You may need to grant keychain access when prompted.");
                        tracing::error!("If the prompt doesn't appear:");
                        tracing::error!("1. Open Keychain Access app");
                        tracing::error!("2. Search for '{} Safe Storage'", extractor.name());
                        tracing::error!("3. Double-click the entry and check 'Show password'");
                        tracing::error!("4. You may need to enter your macOS password\n");
                    } else {
                        tracing::warn!("Failed to extract from {}: {}", extractor.name(), e);
                    }
                }
            }
        }

        Ok(all_results)
    }
}

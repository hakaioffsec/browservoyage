use crate::browser_extractor::BrowserExtractor;
#[cfg(target_os = "linux")]
use crate::chrome::linux::LinuxChromeExtractor;
#[cfg(target_os = "macos")]
use crate::chrome::macos::MacOSChromeExtractor;
#[cfg(target_os = "windows")]
use crate::chrome::windows::WindowsChromeExtractor;
use crate::error::BrowserVoyageResult;
use crate::gecko::GeckoExtractor;
#[cfg(target_os = "macos")]
use crate::webkit::macos::SafariExtractor;

pub fn get_extractors() -> BrowserVoyageResult<Vec<Box<dyn BrowserExtractor>>> {
    let mut extractors: Vec<Box<dyn BrowserExtractor>> = Vec::new();

    // #[cfg(target_os = "windows")]
    // {
    //     extractors.push(Box::new(WindowsChromeExtractor::chrome()));
    //     extractors.push(Box::new(WindowsChromeExtractor::edge()));
    //     extractors.push(Box::new(WindowsChromeExtractor::brave()));
    //     extractors.push(Box::new(WindowsChromeExtractor::chromium()));
    // }

    #[cfg(target_os = "macos")]
    {
        extractors.push(Box::new(MacOSChromeExtractor::chrome()));
        extractors.push(Box::new(MacOSChromeExtractor::edge()));
        extractors.push(Box::new(MacOSChromeExtractor::brave()));
        extractors.push(Box::new(MacOSChromeExtractor::chromium()));
        extractors.push(Box::new(SafariExtractor::new()));
        
        // Add Firefox extractors for macOS
        for (name, path) in GeckoExtractor::find_firefox_installations() {
            extractors.push(Box::new(GeckoExtractor::new(name, path)));
        }
    }

    // #[cfg(target_os = "linux")]
    // {
    //     extractors.push(Box::new(LinuxChromeExtractor::chrome()));
    //     extractors.push(Box::new(LinuxChromeExtractor::edge()));
    //     extractors.push(Box::new(LinuxChromeExtractor::brave()));
    //     extractors.push(Box::new(LinuxChromeExtractor::chromium()));
    // }

    Ok(extractors)
}

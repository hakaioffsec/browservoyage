mod browser_extractor;
mod browser_factory;
mod chrome;
mod error;
mod gecko;

#[cfg(target_os = "macos")]
mod webkit;

#[cfg(target_os = "windows")]
mod windows;

use color_eyre::eyre::Result;
use tracing::{error, info};

#[cfg(target_os = "windows")]
use ::windows::Win32::UI::Shell::IsUserAnAdmin;

use crate::browser_factory::BrowserFactory;
use std::fs;
use std::path::Path;

#[cfg(target_os = "windows")]
fn is_admin() -> bool {
    #[cfg(target_os = "windows")]
    {
        unsafe { IsUserAnAdmin().as_bool() }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // On non-Windows platforms, we don't require admin for Firefox
        false
    }
}

fn main() -> Result<()> {
    // Initialize color-eyre and tracing
    color_eyre::install()?;

    // Use trace-level logging for debug builds, info-level for release builds
    let default_level = if cfg!(debug_assertions) {
        tracing::Level::TRACE
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive(default_level.into()),
        )
        .init();

    info!("BrowserVoyage - Browser Data Extractor");

    // Only check for admin on Windows when Chrome extraction is possible
    #[cfg(target_os = "windows")]
    if !is_admin() {
        error!("This script needs to run as administrator on Windows.");
        return Err(crate::error::BrowserVoyageError::AccessDenied(
            "Administrator privileges required on Windows".into(),
        )
        .into());
    }

    // Create output directory
    let output_dir = Path::new("browser_data_export");
    fs::create_dir_all(output_dir)?;

    // Extract from all available browsers
    match BrowserFactory::extract_all() {
        Ok(results) => {
            for result in results {
                info!("Extracted from {}", result.browser.name);

                // Save to JSON file
                let filename = format!("{}_export.json", result.browser.name.to_lowercase());
                let filepath = output_dir.join(&filename);
                let json = serde_json::to_string_pretty(&result)?;
                fs::write(&filepath, json)?;
                info!("  Saved full data to: {}", filepath.display());

                // Print summary and samples
                for profile in result.profiles {
                    info!("  Profile: {}", profile.name);
                    info!("    Cookies: {}", profile.cookies.len());
                    info!("    Credentials: {}", profile.credentials.len());

                    // Print sample cookies (first 5)
                    if !profile.cookies.is_empty() {
                        info!(
                            "\n  Sample cookies (showing 5 of {}):",
                            profile.cookies.len()
                        );
                        for cookie in profile.cookies.iter().take(5) {
                            info!("    {} | {} = {}", cookie.host, cookie.name, cookie.value);
                        }
                    }

                    // Print all credentials (usually fewer)
                    if !profile.credentials.is_empty() {
                        info!("\n  Credentials found:");
                        for cred in &profile.credentials {
                            info!("    {} | {} | {}", cred.url, cred.username, cred.password);
                        }
                    }
                }
            }

            info!("\nAll data exported to: {}", output_dir.display());
        }
        Err(e) => {
            error!("Extraction failed: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}

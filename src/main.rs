use browservoyage::{cli::Cli, extract_browser_data, output::get_formatter};
use clap::Parser;
use color_eyre::eyre::Result;
use std::fs;
use std::path::Path;
use tracing::{error, info};

#[cfg(target_os = "windows")]
use ::windows::Win32::UI::Shell::IsUserAnAdmin;

#[cfg(target_os = "windows")]
fn is_admin() -> bool {
    #[cfg(target_os = "windows")]
    {
        unsafe { IsUserAnAdmin().as_bool() }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // On non-Windows platforms, we don't require admin
        false
    }
}

fn main() -> Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();

    // Initialize color-eyre and tracing
    color_eyre::install()?;

    // Set up logging based on CLI flags
    let log_level = cli.get_log_level();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive(log_level.into()),
        )
        .init();

    if cli.verbose || cli.debug || cli.trace {
        info!("Running with configuration: {:?}", cli);
    }

    // Only check for admin on Windows when Chrome extraction is possible
    #[cfg(target_os = "windows")]
    if !is_admin() {
        error!("This script needs to run as administrator on Windows.");
        return Err(browservoyage::BrowserVoyageError::AccessDenied(
            "Administrator privileges required on Windows".into(),
        )
        .into());
    }

    // Convert CLI to extraction config
    let config = cli.to_extraction_config();

    // Determine output directory
    let output_dir = config
        .output_path
        .clone()
        .unwrap_or_else(|| Path::new("browser_data_export").to_path_buf());

    // Create output directory if it doesn't exist
    if output_dir.is_dir() || output_dir.extension().is_none() {
        fs::create_dir_all(&output_dir)?;
    } else {
        // If it's a file path, create parent directory
        if let Some(parent) = output_dir.parent() {
            fs::create_dir_all(parent)?;
        }
    }

    // Extract browser data
    match extract_browser_data(&config) {
        Ok(results) => {
            for result in &results {
                info!("Extracted from {}", result.browser.name);

                // Determine output file path
                let output_path = if output_dir.is_dir() {
                    let formatter = get_formatter(&config.output_format);
                    let filename = format!(
                        "{}_export.{}",
                        result.browser.name.to_lowercase(),
                        formatter.file_extension()
                    );
                    output_dir.join(filename)
                } else {
                    output_dir.clone()
                };

                // Format and save data
                let formatter = get_formatter(&config.output_format);
                let formatted_data = formatter.format(std::slice::from_ref(result))?;
                fs::write(&output_path, formatted_data)?;

                info!("  Saved data to: {}", output_path.display());

                // Print summary and samples if verbose
                if config.verbose {
                    for profile in &result.profiles {
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
            }

            if results.is_empty() {
                info!("No browser data found or extracted.");
            } else {
                info!(
                    "Extraction completed. {} browser(s) processed.",
                    results.len()
                );
                if output_dir.is_dir() {
                    info!("Data exported to directory: {}", output_dir.display());
                } else {
                    info!("Data exported to file: {}", output_dir.display());
                }
            }
        }
        Err(e) => {
            error!("Extraction failed: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}

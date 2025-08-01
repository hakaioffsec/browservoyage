use clap::{Parser, ValueEnum};
use std::path::PathBuf;

/// Browser data extraction tool
#[derive(Parser, Debug)]
#[command(name = "browservoyage")]
#[command(about = "Extract cookies, credentials, and other data from web browsers")]
#[command(version)]
pub struct Cli {
    /// Browsers to extract data from
    #[arg(short, long, value_enum, value_delimiter = ',', default_values = ["all"])]
    pub browsers: Vec<BrowserArg>,

    /// Content types to extract
    #[arg(short, long, value_enum, value_delimiter = ',', default_values = ["all"])]
    pub content: Vec<ContentArg>,

    /// Output format
    #[arg(short = 'f', long, value_enum, default_value = "json")]
    pub format: FormatArg,

    /// Output directory or file path
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Enable verbose logging
    #[arg(short, long)]
    pub verbose: bool,

    /// Enable debug logging (overrides verbose)
    #[arg(short, long)]
    pub debug: bool,

    /// Trace logging (overrides debug and verbose)
    #[arg(short, long)]
    pub trace: bool,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum BrowserArg {
    Chrome,
    Firefox,
    Edge,
    Safari,
    Brave,
    Chromium,
    All,
}

impl From<BrowserArg> for crate::BrowserType {
    fn from(arg: BrowserArg) -> Self {
        match arg {
            BrowserArg::Chrome => crate::BrowserType::Chrome,
            BrowserArg::Firefox => crate::BrowserType::Firefox,
            BrowserArg::Edge => crate::BrowserType::Edge,
            BrowserArg::Safari => crate::BrowserType::Safari,
            BrowserArg::Brave => crate::BrowserType::Brave,
            BrowserArg::Chromium => crate::BrowserType::Chromium,
            BrowserArg::All => crate::BrowserType::All,
        }
    }
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum ContentArg {
    Cookies,
    Credentials,
    History,
    All,
}

impl From<ContentArg> for crate::ContentType {
    fn from(arg: ContentArg) -> Self {
        match arg {
            ContentArg::Cookies => crate::ContentType::Cookies,
            ContentArg::Credentials => crate::ContentType::Credentials,
            ContentArg::History => crate::ContentType::History,
            ContentArg::All => crate::ContentType::All,
        }
    }
}

#[derive(ValueEnum, Clone, Debug)]
pub enum FormatArg {
    Json,
    Csv,
    Xml,
}

impl From<FormatArg> for crate::OutputFormat {
    fn from(arg: FormatArg) -> Self {
        match arg {
            FormatArg::Json => crate::OutputFormat::Json,
            FormatArg::Csv => crate::OutputFormat::Csv,
            FormatArg::Xml => crate::OutputFormat::Xml,
        }
    }
}

impl Cli {
    pub fn to_extraction_config(&self) -> crate::ExtractionConfig {
        let browser_types = if self.browsers.contains(&BrowserArg::All) {
            vec![crate::BrowserType::All]
        } else {
            self.browsers.iter().map(|b| b.clone().into()).collect()
        };

        let content_types = if self.content.contains(&ContentArg::All) {
            vec![crate::ContentType::All]
        } else {
            self.content.iter().map(|c| c.clone().into()).collect()
        };

        crate::ExtractionConfig {
            browser_types,
            content_types,
            output_format: self.format.clone().into(),
            output_path: self.output.clone(),
            verbose: self.verbose || self.debug || self.trace,
        }
    }

    pub fn get_log_level(&self) -> tracing::Level {
        if self.trace {
            tracing::Level::TRACE
        } else if self.debug {
            tracing::Level::DEBUG
        } else if self.verbose {
            tracing::Level::INFO
        } else if cfg!(debug_assertions) {
            tracing::Level::TRACE
        } else {
            tracing::Level::INFO
        }
    }
}

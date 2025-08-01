//! Output formatting functionality for different export formats

use crate::browser_extractor::ExtractedData;
#[cfg(test)]
use crate::browser_extractor::{Cookie, Credential};
use crate::error::{BrowserVoyageError, BrowserVoyageResult};
use crate::OutputFormat;
use serde::Serialize;
use std::io::Write;

/// Trait for output formatting
pub trait OutputFormatter {
    /// Format the extracted data into the target format
    fn format(&self, data: &[ExtractedData]) -> BrowserVoyageResult<String>;

    /// Get the file extension for this format
    fn file_extension(&self) -> &'static str;
}

/// JSON output formatter
pub struct JsonFormatter;

impl OutputFormatter for JsonFormatter {
    fn format(&self, data: &[ExtractedData]) -> BrowserVoyageResult<String> {
        serde_json::to_string_pretty(data).map_err(|e| BrowserVoyageError::JsonError(e))
    }

    fn file_extension(&self) -> &'static str {
        "json"
    }
}

/// CSV output formatter
pub struct CsvFormatter;

/// Flattened cookie record for CSV export
#[derive(Debug, Serialize)]
struct CookieRecord {
    browser_name: String,
    browser_vendor: String,
    profile_name: String,
    host: String,
    name: String,
    value: String,
    path: String,
    expiry: i64,
    is_secure: bool,
}

/// Flattened credential record for CSV export
#[derive(Debug, Serialize)]
struct CredentialRecord {
    browser_name: String,
    browser_vendor: String,
    profile_name: String,
    url: String,
    username: String,
    password: String,
}

impl OutputFormatter for CsvFormatter {
    fn format(&self, data: &[ExtractedData]) -> BrowserVoyageResult<String> {
        let mut output = Vec::new();

        // Write cookies CSV
        writeln!(output, "=== COOKIES ===").map_err(|e| BrowserVoyageError::Io(e.to_string()))?;
        let mut cookies_output = Vec::new();
        {
            let mut writer = csv::Writer::from_writer(&mut cookies_output);

            for browser_data in data {
                for profile in &browser_data.profiles {
                    for cookie in &profile.cookies {
                        let record = CookieRecord {
                            browser_name: browser_data.browser.name.clone(),
                            browser_vendor: browser_data.browser.vendor.clone(),
                            profile_name: profile.name.clone(),
                            host: cookie.host.clone(),
                            name: cookie.name.clone(),
                            value: cookie.value.clone(),
                            path: cookie.path.clone(),
                            expiry: cookie.expiry,
                            is_secure: cookie.is_secure,
                        };
                        writer
                            .serialize(record)
                            .map_err(|e| BrowserVoyageError::CsvError(e.to_string()))?;
                    }
                }
            }
            writer
                .flush()
                .map_err(|e| BrowserVoyageError::CsvError(e.to_string()))?;
        }
        output.extend_from_slice(&cookies_output);

        writeln!(output, "\n=== CREDENTIALS ===")
            .map_err(|e| BrowserVoyageError::Io(e.to_string()))?;
        let mut credentials_output = Vec::new();
        {
            let mut writer = csv::Writer::from_writer(&mut credentials_output);

            for browser_data in data {
                for profile in &browser_data.profiles {
                    for credential in &profile.credentials {
                        let record = CredentialRecord {
                            browser_name: browser_data.browser.name.clone(),
                            browser_vendor: browser_data.browser.vendor.clone(),
                            profile_name: profile.name.clone(),
                            url: credential.url.clone(),
                            username: credential.username.clone(),
                            password: credential.password.clone(),
                        };
                        writer
                            .serialize(record)
                            .map_err(|e| BrowserVoyageError::CsvError(e.to_string()))?;
                    }
                }
            }
            writer
                .flush()
                .map_err(|e| BrowserVoyageError::CsvError(e.to_string()))?;
        }
        output.extend_from_slice(&credentials_output);

        String::from_utf8(output).map_err(|e| BrowserVoyageError::Utf8Error(e))
    }

    fn file_extension(&self) -> &'static str {
        "csv"
    }
}

/// XML output formatter
pub struct XmlFormatter;

impl OutputFormatter for XmlFormatter {
    fn format(&self, data: &[ExtractedData]) -> BrowserVoyageResult<String> {
        let mut output = String::new();
        output.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        output.push_str("<browser_data>\n");

        for browser_data in data {
            output.push_str(&format!(
                "  <browser name=\"{}\" vendor=\"{}\" platform=\"{}\">\n",
                xml_escape(&browser_data.browser.name),
                xml_escape(&browser_data.browser.vendor),
                xml_escape(&browser_data.browser.platform)
            ));

            for profile in &browser_data.profiles {
                output.push_str(&format!(
                    "    <profile name=\"{}\" path=\"{}\">\n",
                    xml_escape(&profile.name),
                    xml_escape(&profile.path)
                ));

                // Cookies
                output.push_str("      <cookies>\n");
                for cookie in &profile.cookies {
                    output.push_str(&format!(
                        "        <cookie host=\"{}\" name=\"{}\" path=\"{}\" expiry=\"{}\" secure=\"{}\">{}</cookie>\n",
                        xml_escape(&cookie.host),
                        xml_escape(&cookie.name),
                        xml_escape(&cookie.path),
                        cookie.expiry,
                        cookie.is_secure,
                        xml_escape(&cookie.value)
                    ));
                }
                output.push_str("      </cookies>\n");

                // Credentials
                output.push_str("      <credentials>\n");
                for credential in &profile.credentials {
                    output.push_str(&format!(
                        "        <credential url=\"{}\" username=\"{}\">{}</credential>\n",
                        xml_escape(&credential.url),
                        xml_escape(&credential.username),
                        xml_escape(&credential.password)
                    ));
                }
                output.push_str("      </credentials>\n");

                output.push_str("    </profile>\n");
            }

            output.push_str("  </browser>\n");
        }

        output.push_str("</browser_data>\n");
        Ok(output)
    }

    fn file_extension(&self) -> &'static str {
        "xml"
    }
}

/// Get the appropriate formatter for the given output format
pub fn get_formatter(format: &OutputFormat) -> Box<dyn OutputFormatter> {
    match format {
        OutputFormat::Json => Box::new(JsonFormatter),
        OutputFormat::Csv => Box::new(CsvFormatter),
        OutputFormat::Xml => Box::new(XmlFormatter),
    }
}

/// Escape XML special characters
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser_extractor::{BrowserInfo, ProfileData};

    fn create_test_data() -> Vec<ExtractedData> {
        vec![ExtractedData {
            browser: BrowserInfo {
                name: "Test Browser".to_string(),
                vendor: "Test Vendor".to_string(),
                platform: "Test Platform".to_string(),
            },
            profiles: vec![ProfileData {
                name: "Default".to_string(),
                path: "/test/path".to_string(),
                cookies: vec![Cookie {
                    host: "example.com".to_string(),
                    name: "test_cookie".to_string(),
                    value: "test_value".to_string(),
                    path: "/".to_string(),
                    expiry: 1234567890,
                    is_secure: true,
                }],
                credentials: vec![Credential {
                    url: "https://example.com".to_string(),
                    username: "testuser".to_string(),
                    password: "testpass".to_string(),
                }],
            }],
        }]
    }

    #[test]
    fn test_json_formatter() {
        let formatter = JsonFormatter;
        let data = create_test_data();
        let result = formatter.format(&data);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("Test Browser"));
    }

    #[test]
    fn test_csv_formatter() {
        let formatter = CsvFormatter;
        let data = create_test_data();
        let result = formatter.format(&data);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("COOKIES"));
        assert!(output.contains("CREDENTIALS"));
    }

    #[test]
    fn test_xml_formatter() {
        let formatter = XmlFormatter;
        let data = create_test_data();
        let result = formatter.format(&data);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("<?xml"));
        assert!(output.contains("<browser_data>"));
        assert!(output.contains("Test Browser"));
    }

    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("test & <data>"), "test &amp; &lt;data&gt;");
        assert_eq!(xml_escape("\"quoted\""), "&quot;quoted&quot;");
    }
}

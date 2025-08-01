# BrowserVoyage

Your friendly tool to extract cookies and passwords from major web browsers.

BrowserVoyage is a simple command-line tool and Rust library for extracting browsing data. It's designed to be easy to use, cross-platform, and modular.

## Supported Browsers

- Google Chrome
- Mozilla Firefox
- Microsoft Edge
- Safari (macOS only)
- Brave
- Chromium

Works on **Windows**, **macOS**, and **Linux**.

## Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/browservoyage
    cd browservoyage
    ```

2.  **Build the project:**
    ```bash
    cargo build --release
    ```
    The executable will be in `./target/release/browservoyage`.

## Quick Start

Here are a few examples to get you started:

```bash
# Extract all data from all browsers (outputs to `browser_data_export/`)
./target/release/browservoyage

# Extract only passwords from Chrome and Firefox into a CSV file
./target/release/browservoyage --browsers chrome,firefox --content credentials --format csv --output passwords.csv

# Get help and see all available options
./target/release/browservoyage --help
```

## Using as a Library

You can also add BrowserVoyage as a dependency to your Rust project.

**Cargo.toml:**

```toml
[dependencies]
browservoyage = { git = "https://github.com/your-username/browservoyage" }
```

**Example:**

```rust
use browservoyage::{extract_browser_data, ExtractionConfig, BrowserType, ContentType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ExtractionConfig::default(); // Extracts all content from all browsers
    let results = extract_browser_data(&config)?;

    for result in results {
        println!("Extracted data from {} for {} profiles.", result.browser.name, result.profiles.len());
    }

    Ok(())
}
```

## Contributing

Contributions are welcome! If you'd like to help, please feel free to fork the repository and submit a pull request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the GNU GPLv3 License.

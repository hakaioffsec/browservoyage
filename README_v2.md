# BrowserVoyage - Modern Browser Data Extraction Library & CLI

A comprehensive, modular browser data extraction tool and library that can decrypt and extract cookies and saved passwords from multiple browsers across different platforms. Features a modern CLI interface with flexible filtering options and multiple output formats.

## 🚀 Features

### **Modern CLI Interface**
- **Selective Extraction**: Choose specific browsers and content types
- **Multiple Output Formats**: JSON, CSV, XML export options
- **Flexible Logging**: Configurable verbosity levels (info, debug, trace)
- **Custom Output Paths**: Specify exact output location
- **Cross-Platform**: Works on Windows, macOS, and Linux

### **Browser Support**

#### **Chrome-based Browsers** 🌐
- **Chrome, Edge, Brave, Chromium** across all platforms
- Modern encryption support (v10, v11, v20)
- Advanced Windows encryption (AES-256-GCM, ChaCha20-Poly1305, CNG)
- macOS Keychain integration
- Linux keyring support (GNOME Keyring, KDE Wallet)

#### **Firefox/Gecko** 🦊
- **Firefox, Firefox Developer Edition, Firefox Nightly, Firefox ESR**
- Cross-platform support (Windows, macOS, Linux)
- ASN.1 PBE decryption for master key extraction
- Multiple profile support
- 3DES and AES-256-CBC decryption algorithms

#### **Safari (macOS)** 🧭
- Binary cookies format extraction
- Sandboxed container support
- Full Disk Access integration

## 📦 Installation & Building

### **Requirements**

#### **Windows**
- Administrator privileges (for Chrome/Edge data access)
- Windows 10/11

#### **macOS** 
- Full Disk Access (for Safari data extraction)
- macOS 10.15+ recommended

#### **Linux**
- GNOME Keyring or KDE Wallet (for Chrome data decryption)
- Standard user permissions

### **Building**
```bash
git clone https://github.com/your-username/browservoyage
cd browservoyage
cargo build --release
```

## 🖥️ CLI Usage

### **Basic Commands**

```bash
# Extract all data from all browsers (default)
browservoyage

# Extract only cookies from Chrome and Firefox
browservoyage --browsers chrome,firefox --content cookies

# Export to CSV format with verbose logging
browservoyage --format csv --verbose

# Extract credentials to specific directory
browservoyage --content credentials --output ./passwords

# Debug logging for troubleshooting
browservoyage --debug
```

### **CLI Options**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--browsers` | `-b` | Browsers to extract from | `all` |
| `--content` | `-c` | Content types to extract | `all` |
| `--format` | `-f` | Output format | `json` |
| `--output` | `-o` | Output path/directory | `browser_data_export/` |
| `--verbose` | `-v` | Enable verbose logging | `false` |
| `--debug` | `-d` | Enable debug logging | `false` |
| `--trace` | `-t` | Enable trace logging | `false` |

### **Browser Options**
- `chrome` - Google Chrome
- `firefox` - Mozilla Firefox (all variants)
- `edge` - Microsoft Edge  
- `safari` - Safari (macOS only)
- `brave` - Brave Browser
- `chromium` - Chromium
- `all` - All available browsers

### **Content Options**
- `cookies` - HTTP cookies
- `credentials` - Saved passwords
- `history` - Browsing history (planned)
- `all` - All available content types

### **Format Options**
- `json` - Pretty-printed JSON (default)
- `csv` - Comma-separated values
- `xml` - Structured XML

### **Advanced Examples**

```bash
# Security audit: Extract all credentials in CSV format
browservoyage --content credentials --format csv --output ./audit/passwords.csv

# Cookie analysis: Chrome and Edge cookies only
browservoyage --browsers chrome,edge --content cookies --verbose

# Cross-browser comparison: JSON output with debug info
browservoyage --format json --debug --output ./analysis/

# Minimal extraction: Just Firefox data
browservoyage --browsers firefox --trace
```

## 📚 Library Usage

BrowserVoyage can also be used as a library in your Rust projects:

```toml
[dependencies]
browservoyage = "0.1.0"
```

### **Basic Library Usage**

```rust
use browservoyage::{
    extract_browser_data, ExtractionConfig, 
    BrowserType, ContentType, OutputFormat
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure extraction
    let config = ExtractionConfig {
        browser_types: vec![BrowserType::Chrome, BrowserType::Firefox],
        content_types: vec![ContentType::Cookies],
        output_format: OutputFormat::Json,
        output_path: Some("./output".into()),
        verbose: true,
    };

    // Extract data
    let results = extract_browser_data(&config)?;
    
    // Process results
    for result in results {
        println!("Extracted from {}: {} profiles", 
                 result.browser.name, result.profiles.len());
    }

    Ok(())
}
```

### **Advanced Library Usage**

```rust
use browservoyage::{BrowserFactory, BrowserExtractor};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get available extractors
    let mut extractors = BrowserFactory::get_available_extractors();
    
    // Extract from each browser
    for mut extractor in extractors {
        match extractor.extract() {
            Ok(data) => {
                println!("Successfully extracted from {}", extractor.name());
                // Process data...
            }
            Err(e) => {
                eprintln!("Failed to extract from {}: {}", extractor.name(), e);
            }
        }
    }

    Ok(())
}
```

## 🏗️ Architecture

### **Modern Library Structure**

```
src/
├── lib.rs                 # Library entry point & public API
├── main.rs                # CLI application
├── cli.rs                 # Command-line interface (clap)
├── common.rs              # Shared traits & utilities
├── output.rs              # Output formatting (JSON/CSV/XML)
├── error.rs               # Error types & handling
├── browser_extractor.rs   # Core browser extraction trait
├── browser_factory.rs     # Browser extractor factory
├── chrome/                # Chrome-based browser support
│   ├── common.rs          # Shared Chrome abstractions
│   ├── windows.rs         # Windows Chrome implementation
│   ├── macos.rs           # macOS Chrome implementation
│   └── linux.rs           # Linux Chrome implementation
├── gecko/                 # Firefox/Gecko support
│   ├── extractor.rs       # Main Gecko extractor
│   ├── data.rs            # Gecko data structures
│   └── asn1pbe.rs         # ASN.1 PBE decryption
├── webkit/                # Safari/WebKit support
│   └── macos.rs           # Safari implementation
└── windows/               # Windows-specific utilities
    └── impersonation.rs   # Privilege escalation
```

### **Key Design Principles**

- **🧩 Modular**: Each browser type is a separate module
- **🔄 Reusable**: Common functionality shared via traits  
- **🎯 Extensible**: Easy to add new browsers/platforms
- **⚡ Efficient**: Selective extraction reduces overhead
- **🛡️ Safe**: Comprehensive error handling
- **📊 Flexible**: Multiple output formats

## 🔧 Technical Details

### **Chrome Technical Details**

#### **Encryption Versions**
- **v10**: Legacy DPAPI encryption
- **v11**: Enhanced DPAPI encryption  
- **v20**: Modern AES-256-GCM with app-bound keys

#### **Platform-Specific Decryption**
- **Windows**: DPAPI + CNG for v20, supports flags 1-3
- **macOS**: Keychain integration with PBKDF2 key derivation
- **Linux**: GNOME Keyring/KDE Wallet with AES-128-CBC

### **Firefox Technical Details**

#### **Master Key Extraction**
1. Query `key4.db` for metadata and NSS private key data
2. Validate password-check and key integrity
3. Use ASN.1 PBE decryption with appropriate algorithm
4. Extract and decrypt saved passwords from `logins.json`

### **Safari Technical Details**

#### **Binary Cookies Format**
- Proprietary binary format used by Safari
- Requires Full Disk Access on modern macOS
- Supports both legacy and sandboxed container locations

## 🔒 Security & Permissions

### **Windows Requirements**
- **Administrator privileges** required for Chrome-based browsers
- Uses Windows DPAPI and CNG for decryption
- Supports LSASS impersonation for system-level access

### **macOS Requirements**  
- **Full Disk Access** required for Safari
- Keychain access prompts for Chrome-based browsers
- Terminal/IDE must be authorized for disk access

### **Linux Requirements**
- User-level permissions sufficient
- Supports GNOME Keyring and KDE Wallet integration
- Fallback to basic decryption if keyrings unavailable

## 🐛 Troubleshooting

### **Common Issues**

#### **Permission Denied Errors**
```bash
# Windows: Run as Administrator
# macOS: Grant Full Disk Access to terminal
# Linux: Check keyring service status
```

#### **No Data Found**
```bash
# Check if browsers are installed
browservoyage --debug

# Try specific browser
browservoyage --browsers chrome --verbose
```

#### **Decryption Failures**
```bash
# Enable trace logging for detailed info
browservoyage --trace

# Check platform-specific requirements
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

### **Adding New Browser Support**

1. Create a new module in the appropriate directory
2. Implement the `BrowserExtractor` trait
3. Add platform-specific decryption logic
4. Update the `BrowserFactory` to include the new extractor
5. Add tests and documentation

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for legitimate security research, system administration, and personal data recovery purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse of this software.

## 🙏 Acknowledgments

- Chrome encryption research community
- Firefox/Gecko cryptography documentation  
- macOS security research contributors
- Open source cryptography libraries

---

**BrowserVoyage** - Making browser data extraction simple, secure, and reliable across all platforms! 🚀
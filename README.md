# BrowserVoyage - Browser Data Extractor (Rust)

A comprehensive, modular browser data extraction tool that can decrypt and extract cookies and saved passwords from multiple browsers across different platforms. Currently supports Chrome on Windows, Firefox across all platforms, and Safari on macOS.

## Features

### Chrome Support

- Decrypts Chrome cookies and saved passwords on Windows
- Supports encryption versions v10, v11, and v20
- Supports Chrome 127+ (flag 1: AES-256-GCM), 133+ (flag 2: ChaCha20-Poly1305), and 137+ (flag 3: AES-256-GCM with CNG)
- Parses Chrome's Local State file to extract the app-bound encryption key
- Automatically handles SHA-256 domain hashing for cookies
- Extracts credentials from Login Data database

### Firefox Support

- Extracts and decrypts saved passwords from logins.json
- Extracts cookies from cookies.sqlite
- Supports multiple Firefox profiles
- Handles Firefox, Firefox Developer Edition, and Firefox Nightly
- Uses ASN.1 PBE decryption for master key extraction
- Supports 3DES and AES-256-CBC decryption algorithms

### Safari Support

- Extracts cookies from Safari's binary cookies format on macOS
- Reads from `~/Library/Safari/Cookies/Cookies.binarycookies`
- **Important**: Requires Full Disk Access permissions (see Requirements)

### General Features

- Robust LSASS/winlogon impersonation for SYSTEM-level DPAPI access
- Comprehensive error handling with detailed error types
- Structured logging with tracing
- Colored error output with color-eyre

## Requirements

### Windows

- **Administrator privileges** - The tool must be run as administrator
- Chrome browser installed with v20 cookies

### macOS

- **Full Disk Access** - Required for Safari data extraction
  - Grant access to your terminal application (Terminal.app, iTerm2, or your IDE)
  - Go to System Settings > Privacy & Security > Full Disk Access
  - Add your terminal application to the list and enable it

### All Platforms

- Firefox installations are supported without special permissions

## Building

```bash
cargo build --release
```

## Usage

Run the executable as administrator:

```bash
# In an elevated command prompt or PowerShell
.\target\release\browservoyage.exe
```

### Verbose Logging

To enable debug logging, set the `RUST_LOG` environment variable:

```bash
# PowerShell
$env:RUST_LOG="browservoyage=debug"
.\target\release\browservoyage.exe

# Command Prompt
set RUST_LOG=browservoyage=debug
.\target\release\browservoyage.exe
```

The tool will:

1. Check for administrator privileges
2. Read Chrome's Local State file to get the encrypted key
3. Decrypt the key using SYSTEM and user DPAPI
4. Parse the key blob to determine the encryption method
5. Derive the master key based on the flag (1, 2, or 3)
6. Connect to Chrome's cookie database
7. Decrypt and display all v20 cookies

## Output

The tool outputs decrypted cookies in the format:

```
<host_key> <cookie_name> <cookie_value>
```

## Technical Details

### Chrome Technical Details

#### Encryption Flags

- **Flag 1** (Chrome 127+): Uses AES-256-GCM with a hardcoded key
- **Flag 2** (Chrome 133+): Uses ChaCha20-Poly1305 with a hardcoded key
- **Flag 3** (Chrome 137+): Uses AES-256-GCM with a key decrypted via CNG and XORed with a hardcoded key

#### Key Derivation Process

1. Extract `app_bound_encrypted_key` from Local State
2. Remove "APPB" prefix
3. Decrypt with SYSTEM DPAPI (requires LSASS impersonation)
4. Decrypt with user DPAPI
5. Parse the resulting blob to extract encryption parameters
6. Derive the master key based on the flag

### Firefox Technical Details

#### Master Key Extraction

1. Query `key4.db` for metadata and NSS private key data
2. Validate password-check and key integrity
3. Use ASN.1 PBE decryption with the appropriate algorithm:
   - NssPBE: 3DES-CBC with HMAC-SHA1 key derivation
   - MetaPBE: AES-256-CBC with PBKDF2-SHA256
   - LoginPBE: 3DES-CBC with direct key usage

#### Data Extraction

- **Cookies**: Read from `cookies.sqlite` database
- **Passwords**: Read from `logins.json` and decrypt using the master key

## Architecture

The project follows a modular architecture designed for easy extension:

### Module Structure

```
src/
├── browser_extractor.rs   # Core trait definitions
├── browser_factory.rs     # Factory for creating browser extractors
├── chrome/                # Chrome-specific implementations
│   ├── mod.rs            # Module exports
│   └── windows.rs        # Windows-specific Chrome implementation
├── gecko/                 # Firefox/Gecko implementations (cross-platform)
│   ├── mod.rs            # Module exports
│   ├── data.rs           # Gecko data structures
│   ├── extractor.rs      # Main Gecko extractor
│   └── asn1pbe.rs        # ASN.1 PBE decryption
├── windows/               # Windows-specific utilities
│   ├── mod.rs            # Module exports
│   └── impersonation.rs  # Windows privilege escalation
├── error.rs              # Error types
└── main.rs               # Application entry point
```

### Adding New Browser Support

To add support for a new browser or platform:

1. **For a new platform of an existing browser** (e.g., Chrome on Linux):

   - Add a new file in the browser's module (e.g., `chrome/linux.rs`)
   - Implement the `BrowserExtractor` trait
   - Update the module's `mod.rs` to conditionally export based on platform

2. **For a new browser** (e.g., Safari/WebKit):
   - Create a new module directory (e.g., `webkit/`)
   - Implement the `BrowserExtractor` trait
   - Add to `BrowserFactory::get_available_extractors()`

### Platform Support Matrix

| Browser | Windows | Linux | macOS |
| ------- | ------- | ----- | ----- |
| Chrome  | ✅      | 🔲    | 🔲    |
| Firefox | ✅      | ✅    | ✅    |
| Safari  | N/A     | N/A   | ✅    |

✅ = Implemented, 🔲 = Planned

### Security Notes

- This tool requires administrator privileges to impersonate LSASS
- The tool uses hardcoded keys that are part of Chrome's implementation
- This is for educational/research purposes only

## Dependencies

- `windows` - Windows API bindings with comprehensive Win32 support
- `aes` & `aes-gcm` - AES encryption (GCM and CBC modes)
- `des` & `cbc` - 3DES encryption for Firefox
- `chacha20poly1305` - ChaCha20-Poly1305 encryption
- `rusqlite` - SQLite database access for Firefox cookies
- `serde` & `serde_json` - JSON parsing
- `base64` - Base64 decoding
- `hex` - Hex decoding
- `asn1-rs` - ASN.1 parsing for Firefox key extraction
- `pbkdf2`, `hmac`, `sha1`, `sha2` - Cryptographic primitives for key derivation
- `binary-cookies` - Safari binary cookies format parser
- `thiserror` - Derive macro for custom error types
- `tracing` & `tracing-subscriber` - Structured logging
- `color-eyre` - Beautiful error reporting

## License

This is a port of a proof-of-concept script. Use responsibly and in accordance with applicable laws and regulations.

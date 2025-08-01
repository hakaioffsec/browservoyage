#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "macos")]
pub mod macos_v2;

#[cfg(target_os = "macos")]
pub use macos::SafariExtractor;

#[cfg(target_os = "macos")]
pub use macos_v2::ModernSafariExtractor;

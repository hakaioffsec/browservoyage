pub mod common;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "macos")]
pub mod macos_v2;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub mod linux_v2;

#[cfg(target_os = "windows")]
pub use windows::WindowsChromeExtractor;

#[cfg(target_os = "macos")]
pub use macos::MacOSChromeExtractor;

#[cfg(target_os = "linux")]
pub use linux::LinuxChromeExtractor;

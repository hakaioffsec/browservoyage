pub mod common;
pub mod linux;
pub mod macos;
pub mod windows;
// #[cfg(target_os = "linux")]
// pub use self::linux_v2::ModernLinuxChromeExtractor as ChromeExtractor;

#[cfg(target_os = "linux")]
pub use self::linux::LinuxChromeExtractor as ChromeExtractor;

// #[cfg(target_os = "macos")]
// pub use self::macos_v2::MacosChromeExtractor as ChromeExtractor;

#[cfg(target_os = "macos")]
pub use self::macos::MacOSChromeExtractor;

#[cfg(target_os = "windows")]
pub use self::windows::WindowsChromeExtractor as ChromeExtractor;

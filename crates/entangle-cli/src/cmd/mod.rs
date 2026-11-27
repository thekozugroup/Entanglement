//! Command handlers for the `entangle` CLI.

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod backup;
pub mod catalog;
pub mod compute;
pub mod distribution;
pub mod doctor;
pub mod init;
pub mod keyring;
pub mod mesh;
pub mod package;
pub mod pair;
pub mod plugins;
pub mod quickstart;
pub mod release;
pub mod scaffold;
pub mod version;
pub mod wrapper;

pub mod tier;

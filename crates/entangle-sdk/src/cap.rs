//! Capability handle helpers — RAII wrapper over `entangle:plugin/capability`.
//!
//! On `wasm32-wasip2` this calls through to the host capability broker via the
//! component-model import defined in `entangle:plugin/capability@0.1.0`.
//! On native targets this module compiles but the types are stubs only.

// Only meaningful types exist on wasm; native target needs at least the module
// to satisfy `pub mod cap` in lib.rs.

#[cfg(target_arch = "wasm32")]
mod inner {
    use crate::capability::{fetch, release, FetchError, Handle, Kind};

    /// RAII guard around a capability handle.
    ///
    /// The handle is released automatically when the `Cap` is dropped,
    /// preventing leaks even on early return or panic unwind.
    pub struct Cap {
        handle: Handle,
    }

    impl Cap {
        /// Fetch a capability by kind and optional name.
        ///
        /// Returns `Err(FetchError)` if the capability was not granted or is
        /// not recognised by the host.
        pub fn fetch(kind: Kind, name: Option<&str>) -> Result<Self, FetchError> {
            let h = fetch(kind, name)?;
            Ok(Self { handle: h })
        }

        /// Return the raw opaque handle value.
        ///
        /// Callers may pass this to other host functions that accept a `handle`.
        pub fn handle(&self) -> Handle {
            self.handle
        }
    }

    impl Drop for Cap {
        fn drop(&mut self) {
            release(self.handle);
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use inner::Cap;

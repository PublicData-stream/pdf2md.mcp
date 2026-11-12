pub mod auth;
pub mod browser;
pub mod config;
pub mod conversion;
pub mod direct;
pub mod error;
pub mod http;
pub mod jobs;
pub mod manual;
pub mod mcp;
pub mod model;
pub mod policy;
pub mod runtime;
pub mod service;
pub mod storage;
pub mod workspace;

#[cfg(test)]
mod browser_tests;

// reqwest's provider-free Rustls backend requires explicit initialization.
// Respect a provider already installed by an embedding application.
fn configure_tls() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

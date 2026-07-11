//! MindChain Wallet desktop entry point.
#![forbid(unsafe_code)]
#![cfg_attr(
    all(not(debug_assertions), feature = "gui"),
    windows_subsystem = "windows"
)]

#[cfg(feature = "gui")]
fn main() {
    noos_wallet_app::run();
}

#[cfg(not(feature = "gui"))]
fn main() {
    eprintln!("noos-wallet-app was built without the `gui` feature; rebuild with --features gui");
    std::process::exit(2);
}

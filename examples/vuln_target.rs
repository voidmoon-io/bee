//! The 019-http-intercept fixture target, standalone, for the quickstart's manual smoke.
//!
//! `cargo run --example vuln_target --features intercept` prints its ports and serves until killed.
//! The server itself is `tests/support/vuln_target.rs`, shared with the test suite.

#[path = "../tests/support/vuln_target.rs"]
mod vuln_target;

fn main() {
    let (http, https, _handle) = vuln_target::start();
    println!("vuln_target http  = {http}");
    if let Some(a) = https {
        println!("vuln_target https = {a}  (self-signed: localhost, app.test, 127.0.0.1)");
    }
    loop {
        std::thread::park();
    }
}

//! Generates the Kotlin and Swift bindings.
//!
//!     cargo run --features ffi --bin uniffi-bindgen -- \
//!       generate --library target/debug/liblnurlcash_core.dylib \
//!       --language kotlin --out-dir bindings

fn main() {
    uniffi::uniffi_bindgen_main()
}

// SPDX-License-Identifier: MIT
fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_NDK_ANDROID_PLATFORM");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rustc-link-lib=android");
        // Fail the build rather than ship a cdylib that cannot be loaded.
        println!("cargo:rustc-link-arg=-Wl,--no-undefined");
    }
}

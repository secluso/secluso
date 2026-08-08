fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let android_feature_enabled = std::env::var_os("CARGO_FEATURE_ANDROID").is_some();

    if target_os == "android" && android_feature_enabled {
        println!("cargo:rustc-link-lib=camera2ndk");
        println!("cargo:rustc-link-lib=mediandk");
        println!("cargo:rustc-link-lib=aaudio");
        println!("cargo:rustc-link-lib=android");
    }
}

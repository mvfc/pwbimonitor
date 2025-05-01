fn main() {
    let target_family: String =
        std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or("Unknown".to_string());

    if target_family == "windows" {
        // If building from the crate
        println!("cargo:rustc-link-search=libs/winpcap/lib");
        println!("cargo:rerun-if-changed=libs/winpcap/include");

        // If building from a workspace
        println!("cargo:rustc-link-search=psniff/libs/winpcap/lib");
        println!("cargo:rerun-if-changed=psniff/libs/winpcap/include");
    }
}

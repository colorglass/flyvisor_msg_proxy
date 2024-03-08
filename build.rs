use cmake;
use std::env;
use std::path::Path;
use std::process;

fn main() {
    let outdir = env::var("OUT_DIR").unwrap();
    let gmssl_src_dir = Path::new(&outdir).join("gmssl-src");
    if !gmssl_src_dir.exists() {
        let result = process::Command::new("git")
            .args([
                "clone",
                "https://github.com/guanzhi/GmSSL.git",
                gmssl_src_dir.to_str().unwrap(),
            ])
            .status()
            .expect("failed to execute git clone");

        if !result.success() {
            panic!(
                "git clone failed with exit code: {}",
                result.code().unwrap()
            );
        }

        process::Command::new("git")
            .current_dir(&gmssl_src_dir)
            .args(["checkout", "b0c5208a687daaac25f59c6aeee40945a5f67504"])
            .spawn()
            .expect("failed to execute git checkout");
    }

    let mut dest = cmake::Config::new(&gmssl_src_dir)
        .define("BUILD_SHARED_LIBS", "OFF")
        .build();

    dest.push("lib");

    println!("cargo:rustc-link-lib=static=gmssl");
    println!("cargo:rustc-link-search=native={}", dest.display());
}

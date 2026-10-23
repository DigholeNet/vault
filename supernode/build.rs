// SPDX-License-Identifier: MIT
use std::{env, fs, path::Path, process::Command};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    fs::create_dir_all(&out_dir).unwrap();
    fs::copy("supernode.adoc", Path::new(&out_dir).join("supernode.adoc")).unwrap();
    match Command::new("asciidoctor")
        .args(["-b", "manpage", "supernode.adoc"])
        .current_dir(Path::new(&out_dir))
        .status()
    {
        Ok(s) => {
            if s.success() {
                Command::new("gzip")
                    .args(["supernode.1"])
                    .current_dir(Path::new(&out_dir))
                    .status()
                    .unwrap();
                // Keep the package-local target/ dir that cargo-deb expects
                // (the workspace target/ lives at the repo root).
                fs::create_dir_all("target").unwrap();
                fs::copy(
                    Path::new(&out_dir).join("supernode.1.gz"),
                    "target/supernode.1.gz",
                )
                .unwrap();
            } else {
                println!("cargo:warning=Error building manpage: {:?}", s.code());
            }
        }
        Err(err) => {
            println!("cargo:warning=Error building manpage: {}", err);
            println!("cargo:warning=The manpage will not be build. Do you have 'asciidoctor'?");
        }
    }
}

// SPDX-License-Identifier: MIT
use std::{env, fs, path::Path, process::Command};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    // Process manpage using asciidoctor command

    fs::create_dir_all(&out_dir).unwrap();
    fs::copy("edge.adoc", Path::new(&out_dir).join("edge.adoc")).unwrap();
    match Command::new("asciidoctor")
        .args(["-b", "manpage", "edge.adoc"])
        .current_dir(Path::new(&out_dir))
        .status()
    {
        Ok(_) => {
            Command::new("gzip")
                .args(["edge.1"])
                .current_dir(Path::new(&out_dir))
                .status()
                .unwrap();
            // Keep the package-local target/ dir that cargo-deb expects
            // (the workspace target/ lives at the repo root).
            fs::create_dir_all("target").unwrap();
            fs::copy(Path::new(&out_dir).join("edge.1.gz"), "target/edge.1.gz").unwrap();
        }
        Err(err) => {
            println!("cargo:warning=Error building manpage: {}", err);
            println!("cargo:warning=The manpage will not be build. Do you have 'asciidoctor'?");
        }
    }
}

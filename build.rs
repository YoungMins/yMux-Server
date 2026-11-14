//! Embeds `web/dist` into the binary at compile time.
//!
//! Generates `$OUT_DIR/embedded.rs` with a sorted table of (path, bytes). When
//! `web/dist/index.html` does not exist (no Node toolchain), a small
//! placeholder page is embedded instead so `cargo build` / `cargo test` work.

use std::fs;
use std::path::{Path, PathBuf};

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            walk(root, &path, out);
        } else if ft.is_file() {
            if let Ok(rel) = path.strip_prefix(root) {
                let rel = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push((rel, path.clone()));
            }
        }
    }
}

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let dist = manifest.join("web").join("dist");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=web/dist");

    let mut files: Vec<(String, PathBuf)> = Vec::new();
    if dist.join("index.html").is_file() {
        walk(&dist, &dist, &mut files);
    }
    files.sort();

    let mut code = String::from("pub static EMBEDDED: &[(&str, &[u8])] = &[\n");
    if files.is_empty() {
        code.push_str(concat!(
            "(\"index.html\", b\"<!doctype html><html lang=\\\"en\\\"><head><meta charset=\\\"utf-8\\\">",
            "<title>yMux server</title></head><body><h1>yMux server</h1>",
            "<p>The web app was not built into this binary. Build <code>web/</code> and rebuild the server.</p>",
            "</body></html>\"),\n"
        ));
    } else {
        for (rel, abs) in &files {
            code.push_str(&format!(
                "({:?}, include_bytes!({:?}) as &[u8]),\n",
                rel,
                abs.to_string_lossy()
            ));
        }
    }
    code.push_str("];\n");

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default()).join("embedded.rs");
    if fs::read_to_string(&out).map(|c| c != code).unwrap_or(true) {
        if let Err(e) = fs::write(&out, code) {
            panic!("cannot write {}: {e}", out.display());
        }
    }
}

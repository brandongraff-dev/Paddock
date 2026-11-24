//! Bundles `../resources` (install.ps1, docker-compose.lite.yml, schema/, .env.example, filled
//! in by `scripts/prepare_resources.py`) into the executable, so Paddock Setup is ONE .exe that
//! needs nothing next to it. The list is generated into `$OUT_DIR/embedded.rs`.

use std::path::{Path, PathBuf};
use std::{env, fs};

fn collect(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(root, &p, out);
        } else if let Ok(rel) = p.strip_prefix(root) {
            let parts: Vec<String> = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            out.push(parts.join("/"));
        }
    }
}

fn main() {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../resources");
    println!("cargo:rerun-if-changed={}", root.display());
    let mut files = Vec::new();
    if root.is_dir() {
        collect(&root, &root, &mut files);
    }
    files.sort();
    let mut src = String::from("/// (path relative to the install files folder, contents)\npub static EMBEDDED: &[(&str, &[u8])] = &[\n");
    for rel in &files {
        let abs = root.join(rel);
        println!("cargo:rerun-if-changed={}", abs.display());
        src.push_str(&format!(
            "    ({:?}, include_bytes!({:?}) as &[u8]),\n",
            rel,
            abs.to_string_lossy()
        ));
    }
    src.push_str("];\n");
    fs::write(
        Path::new(&env::var("OUT_DIR").unwrap()).join("embedded.rs"),
        src,
    )
    .unwrap();
    tauri_build::build();
}

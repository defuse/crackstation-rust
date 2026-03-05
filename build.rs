fn main() {
    for pattern in &["templates/**/*", "static/**/*"] {
        for entry in glob::glob(pattern).unwrap() {
            if let Ok(path) = entry {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
}

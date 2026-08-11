fn main() {
    for pattern in &["templates/**/*", "static/**/*"] {
        let paths = glob::glob(pattern).expect("build.rs glob pattern is a valid literal");
        for entry in paths {
            // A GlobError means templates/ or static/ could not be walked (permission
            // denied, unreadable entry, I/O error). Silently skipping it would drop files
            // from the rerun set and still exit 0, so fail the build instead.
            let path = entry.expect("failed to read an entry under templates/ or static/");
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

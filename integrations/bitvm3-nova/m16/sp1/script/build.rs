use std::path::{Path, PathBuf};

use sp1_build::{build_program_with_args, BuildArgs};

/// Absolute source paths reach the guest ELF through panic locations, so the
/// checkout directory, M15's vendored halo2curves and CARGO_HOME are remapped to
/// fixed prefixes.
fn remap(from: &Path, to: &str) -> String {
    let from = from.canonicalize().unwrap_or_else(|_| from.to_path_buf());
    format!("--remap-path-prefix={}={to}", from.display())
}

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_HOME");
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let checkout = manifest.join("..");
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")))
        .expect("CARGO_HOME or HOME");
    for program in ["../program"] {
        build_program_with_args(
            program,
            BuildArgs {
                locked: false,
                rustflags: vec![
                    remap(&cargo_home, "/cargo"),
                    remap(&checkout, "/m16-sp1"),
                    remap(&manifest.join("../../../m15/vendor"), "/m15-vendor"),
                ],
                ..Default::default()
            },
        );
    }
}

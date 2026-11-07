use std::path::{Path, PathBuf};

use sp1_build::{build_program_with_args, BuildArgs};

/// The two M12 guests (architecture A and control C) are built here so their
/// compressed proofs can be produced and then wrapped. Absolute paths reach
/// the ELF through panic locations, so the checkout and CARGO_HOME are
/// remapped to the same fixed prefixes M12 uses; the ELF digests then match
/// M12's (2db52978... for A).
fn remap(from: &Path, to: &str) -> String {
    let from = from.canonicalize().unwrap_or_else(|_| from.to_path_buf());
    format!("--remap-path-prefix={}={to}", from.display())
}

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_HOME");
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let m12_sp1 = manifest.join("../../m12/sp1");
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")))
        .expect("CARGO_HOME or HOME");
    for program in ["program", "program-direct"] {
        build_program_with_args(
            m12_sp1.join(program).to_str().expect("utf-8 path"),
            BuildArgs {
                locked: false,
                rustflags: vec![remap(&cargo_home, "/cargo"), remap(&m12_sp1, "/m12-sp1")],
                ..Default::default()
            },
        );
    }
}

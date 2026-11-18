use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Barrier},
};

use garbled_snark_verifier::{CircuitContext, Gate, WireId};
use m13_statement::FinalStatement;
use m14_claim::{self as claim, CircuitSpec, Manifest};
use tempfile::TempDir;

fn circuit(ctx: &mut impl CircuitContext, w: &Vec<WireId>) -> Vec<WireId> {
    let out = ctx.issue_wire();
    ctx.add_gate(Gate::and(w[0], w[1], out));
    vec![out]
}

fn spec() -> CircuitSpec {
    CircuitSpec {
        id: "test-and-v1".into(),
        source_sha256: [1; 32],
        reference_sha256: [2; 32],
        input_bits: 2,
        ciphertexts: 1,
    }
}

fn statement() -> FinalStatement {
    FinalStatement {
        wrap_vk_sha256: "11".repeat(32),
        program_vk_digest: "01000000".repeat(8),
        recursion_vk_root: "02000000".repeat(8),
        committed_values_sha256: "22".repeat(32),
        exit_code: 0,
        is_complete: 1,
    }
}

#[derive(Debug)]
struct Released {
    path: PathBuf,
    pin: [u8; 32],
}
impl std::ops::Deref for Released {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.path
    }
}

struct Instance {
    temp: TempDir,
    public: PathBuf,
    private: PathBuf,
    manifest: Manifest,
    pin: [u8; 32],
}
impl Instance {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let public = temp.path().join("public");
        let private = temp.path().join("private");
        let manifest = claim::setup(&public, &private, statement(), spec(), 16, circuit).unwrap();
        let pin = manifest.digest().unwrap();
        Self {
            temp,
            public,
            private,
            manifest,
            pin,
        }
    }
    fn release(&self, name: &str, bits: &[bool]) -> anyhow::Result<Released> {
        let path = self.temp.path().join(name);
        let released = claim::release(
            &self.public,
            &self.private,
            &path,
            &self.manifest,
            &spec(),
            self.pin,
            [3; 32],
            bits,
        )?;
        Ok(Released {
            path,
            pin: released.digest()?,
        })
    }
    fn evaluate(&self, released: &Released, bits: &[bool]) -> anyhow::Result<claim::Evaluation> {
        claim::evaluate(
            &self.public,
            released,
            &self.manifest,
            &spec(),
            self.pin,
            released.pin,
            [3; 32],
            bits,
            16,
            circuit,
        )
    }
}

#[test]
fn public_evaluator_runs_in_separate_process_without_private_state() {
    let i = Instance::new();
    let labels = i.release("release", &[true, true]).unwrap();
    // Remove access to private state before starting a fresh evaluator process.
    fs::remove_dir_all(&i.private).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "public_evaluator_child",
            "--ignored",
            "--nocapture",
        ])
        .env("M14_TEST_PUBLIC", &i.public)
        .env("M14_TEST_RELEASE", &labels.path)
        .env("M14_TEST_RELEASE_PIN", hex::encode(labels.pin))
        .env("M14_TEST_PIN", hex::encode(i.pin))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::metadata(i.public.join(claim::INPUT_COMMITMENTS))
            .unwrap()
            .len(),
        128
    );
}

#[test]
#[ignore = "invoked in a fresh process by the role separation test"]
fn public_evaluator_child() {
    let public = PathBuf::from(std::env::var("M14_TEST_PUBLIC").unwrap());
    let release = PathBuf::from(std::env::var("M14_TEST_RELEASE").unwrap());
    let pin = claim::parse_pin(&std::env::var("M14_TEST_PIN").unwrap()).unwrap();
    let release_pin = claim::parse_pin(&std::env::var("M14_TEST_RELEASE_PIN").unwrap()).unwrap();
    let manifest = claim::load_manifest(&public, pin, &spec()).unwrap();
    let out = claim::evaluate(
        &public,
        &release,
        &manifest,
        &spec(),
        pin,
        release_pin,
        [3; 32],
        &[true, true],
        16,
        circuit,
    )
    .unwrap();
    assert_eq!(out.verdict, "accept");
}

#[test]
fn well_formed_false_input_opens_reject() {
    let i = Instance::new();
    let labels = i.release("release", &[false, true]).unwrap();
    assert_eq!(
        i.evaluate(&labels, &[false, true]).unwrap().verdict,
        "reject"
    );
}

#[test]
fn same_input_retry_is_identical_and_other_input_is_refused() {
    let i = Instance::new();
    let first = i.release("first", &[true, true]).unwrap();
    let second = i.release("retry", &[true, true]).unwrap();
    assert_eq!(
        fs::read(first.join(claim::SELECTED_LABELS)).unwrap(),
        fs::read(second.join(claim::SELECTED_LABELS)).unwrap()
    );
    assert!(i
        .release("other", &[false, true])
        .unwrap_err()
        .to_string()
        .contains("different proof"));
    assert!(claim::release(
        &i.public,
        &i.private,
        &i.temp.path().join("other-hash"),
        &i.manifest,
        &spec(),
        i.pin,
        [9; 32],
        &[true, true]
    )
    .is_err());
}

#[test]
fn reservation_survives_failed_publication_and_partial_records_fail_closed() {
    let i = Instance::new();
    fs::create_dir(i.temp.path().join("occupied")).unwrap();
    assert!(i.release("occupied", &[true, true]).is_err());
    assert!(i.release("different", &[false, true]).is_err());
    i.release("retry", &[true, true]).unwrap();
    let j = Instance::new();
    fs::write(j.private.join("release-reservation.json"), b"{").unwrap();
    assert!(j.release("locked", &[true, true]).is_err());
    assert!(!j.temp.path().join("locked").exists());
}

#[test]
fn concurrent_different_releases_have_one_winner() {
    let i = Instance::new();
    let barrier = Arc::new(Barrier::new(2));
    let winners = std::thread::scope(|scope| {
        let tasks: Vec<_> = [false, true]
            .into_iter()
            .map(|bit| {
                let barrier = barrier.clone();
                let instance = &i;
                scope.spawn(move || {
                    barrier.wait();
                    instance
                        .release(if bit { "a" } else { "b" }, &[bit, true])
                        .is_ok()
                })
            })
            .collect();
        tasks
            .into_iter()
            .map(|task| task.join().unwrap())
            .filter(|won| *won)
            .count()
    });
    assert_eq!(winners, 1);
}

#[test]
fn fresh_instances_have_distinct_private_and_public_material() {
    let a = Instance::new();
    let b = Instance::new();
    assert_ne!(a.pin, b.pin);
    assert_ne!(a.manifest.instance_id, b.manifest.instance_id);
    assert_ne!(a.manifest.public_salt, b.manifest.public_salt);
    let release = a.release("release", &[true, true]).unwrap();
    assert!(b.evaluate(&release, &[true, true]).is_err());
}

#[test]
fn pinned_manifest_rejects_mutations_and_unsupported_circuit() {
    let i = Instance::new();
    claim::load_manifest(&i.public, i.pin, &spec()).unwrap();
    let original: serde_json::Value = serde_json::to_value(&i.manifest).unwrap();
    for field in [
        "instance_id",
        "public_salt",
        "true_label",
        "false_label",
        "accept_label_sha256",
        "reject_label_sha256",
    ] {
        let mut changed = original.clone();
        let value = changed[field][0].as_u64().unwrap();
        changed[field][0] = serde_json::json!((value + 1) % 256);
        fs::write(
            i.public.join(claim::MANIFEST),
            serde_json::to_vec(&changed).unwrap(),
        )
        .unwrap();
        assert!(
            claim::load_manifest(&i.public, i.pin, &spec()).is_err(),
            "{field}"
        );
    }
    fs::write(
        i.public.join(claim::MANIFEST),
        serde_json::to_vec(&original).unwrap(),
    )
    .unwrap();
    let mut unsupported = spec();
    unsupported.source_sha256[0] ^= 1;
    assert!(claim::load_manifest(&i.public, i.pin, &unsupported).is_err());
    assert!(claim::load_manifest(&i.public, [0; 32], &spec()).is_err());
}

#[test]
fn corrupt_missing_truncated_and_extra_artifacts_fail_before_output() {
    for name in [
        claim::CIPHERTEXTS,
        claim::INPUT_COMMITMENTS,
        claim::SELECTED_LABELS,
    ] {
        for mutation in ["flip", "truncate", "append", "missing"] {
            let i = Instance::new();
            let release = i.release("release", &[true, true]).unwrap();
            let dir: &Path = if name == claim::SELECTED_LABELS {
                &release
            } else {
                &i.public
            };
            let path = dir.join(name);
            let mut bytes = fs::read(&path).unwrap();
            match mutation {
                "flip" => {
                    bytes[0] ^= 1;
                    fs::write(&path, bytes).unwrap();
                }
                "truncate" => {
                    bytes.pop();
                    fs::write(&path, bytes).unwrap();
                }
                "append" => {
                    bytes.push(0);
                    fs::write(&path, bytes).unwrap();
                }
                "missing" => fs::remove_file(&path).unwrap(),
                _ => unreachable!(),
            }
            assert!(
                i.evaluate(&release, &[true, true]).is_err(),
                "{name}/{mutation}"
            );
        }
    }
}

#[test]
fn wrong_proof_and_rewritten_release_header_cannot_relabel_input() {
    let i = Instance::new();
    let mut release = i.release("release", &[true, true]).unwrap();
    assert!(i.evaluate(&release, &[false, true]).is_err());
    // Even with a newly agreed release header, the setup commitments reject a modified label.
    let path = release.join(claim::SELECTED_LABELS);
    let mut bytes = fs::read(&path).unwrap();
    bytes[0] ^= 1;
    fs::write(&path, &bytes).unwrap();
    let mut header: serde_json::Value =
        serde_json::from_slice(&fs::read(release.join(claim::RELEASE)).unwrap()).unwrap();
    header["labels"]["sha256"] = serde_json::json!(claim::sha256(&bytes));
    fs::write(
        release.join(claim::RELEASE),
        serde_json::to_vec(&header).unwrap(),
    )
    .unwrap();
    let modified: claim::Release = serde_json::from_value(header).unwrap();
    release.pin = modified.digest().unwrap();
    assert!(i.evaluate(&release, &[true, true]).is_err());
}

#[test]
fn proof_file_hash_cannot_be_rewritten_for_unchanged_inputs() {
    let i = Instance::new();
    let release = i.release("release", &[true, true]).unwrap();
    let mut header: serde_json::Value =
        serde_json::from_slice(&fs::read(release.join(claim::RELEASE)).unwrap()).unwrap();
    header["binding"]["proof_sha256"] = serde_json::to_value([7u8; 32]).unwrap();
    fs::write(
        release.join(claim::RELEASE),
        serde_json::to_vec(&header).unwrap(),
    )
    .unwrap();
    let error = claim::evaluate(
        &i.public,
        &release,
        &i.manifest,
        &spec(),
        i.pin,
        release.pin,
        [7; 32],
        &[true, true],
        16,
        circuit,
    )
    .unwrap_err();
    assert!(error.to_string().contains("release pin"));
}

#[test]
fn reader_detects_mutation_after_preflight_and_never_reopens_path() {
    let i = Instance::new();
    let path = i.public.join(claim::CIPHERTEXTS);
    let mut reader = claim::io::CheckedReader::open(&path, &i.manifest.ciphertexts).unwrap();
    reader.preflight().unwrap();
    let mut bytes = fs::read(&path).unwrap();
    bytes[0] ^= 1;
    fs::write(&path, bytes).unwrap();
    let mut label = [0; 16];
    reader.read_exact(&mut label).unwrap();
    assert!(reader.finish().is_err());

    let j = Instance::new();
    let path = j.public.join(claim::CIPHERTEXTS);
    let mut reader = claim::io::CheckedReader::open(&path, &j.manifest.ciphertexts).unwrap();
    reader.preflight().unwrap();
    fs::rename(&path, j.public.join("original.bin")).unwrap();
    fs::write(&path, [0; 16]).unwrap();
    reader.read_exact(&mut label).unwrap();
    reader.finish().unwrap();
}

#[test]
fn bounded_json_and_malformed_pins_fail() {
    let i = Instance::new();
    for pin in ["", "1", "é", &"z".repeat(64), &"0".repeat(66)] {
        assert!(claim::parse_pin(pin).is_err());
    }
    fs::write(
        i.public.join(claim::MANIFEST),
        vec![b' '; claim::io::MAX_JSON_BYTES as usize + 1],
    )
    .unwrap();
    assert!(claim::load_manifest(&i.public, i.pin, &spec()).is_err());
}

#[cfg(unix)]
#[test]
fn private_state_and_release_journal_have_restricted_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let i = Instance::new();
    i.release("release", &[true, true]).unwrap();
    assert_eq!(
        fs::metadata(&i.private).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for name in ["private.json", "release-reservation.json"] {
        assert_eq!(
            fs::metadata(i.private.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn private_directory_cannot_be_inside_public_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let public = temp.path().join("public");
    assert!(claim::setup(
        &public,
        &public.join("private"),
        statement(),
        spec(),
        16,
        circuit
    )
    .is_err());
    assert!(!public.join("private").exists());
}

#[cfg(unix)]
#[test]
fn fifos_are_rejected_without_waiting_for_a_writer() {
    let temp = tempfile::tempdir().unwrap();
    let fifo = temp.path().join("fifo");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let expected = claim::Artifact {
        bytes: 16,
        sha256: [0; 32],
    };
    assert!(claim::io::CheckedReader::open(&fifo, &expected).is_err());
    assert!(claim::io::read_json::<Manifest>(&fifo).is_err());
    assert!(claim::io::open_regular(&fifo).is_err());
}

#[test]
fn verify_artifacts_enforces_pin_and_supported_circuit_directly() {
    let i = Instance::new();
    claim::verify_artifacts(&i.public, &i.manifest, &spec(), i.pin).unwrap();

    let mut wrong_pin = i.pin;
    wrong_pin[0] ^= 1;
    assert!(claim::verify_artifacts(&i.public, &i.manifest, &spec(), wrong_pin).is_err());

    let mut unsupported = spec();
    unsupported.source_sha256[0] ^= 1;
    assert!(claim::verify_artifacts(&i.public, &i.manifest, &unsupported, i.pin).is_err());
}

#[cfg(unix)]
#[test]
fn symlinks_are_rejected_across_public_released_and_private_paths() {
    use std::os::unix::fs::symlink;

    let i = Instance::new();
    let release = i.release("release", &[true, true]).unwrap();

    // Symlink replacement in public manifest
    let real_manifest = i.temp.path().join("real-manifest.json");
    fs::rename(i.public.join(claim::MANIFEST), &real_manifest).unwrap();
    symlink(&real_manifest, i.public.join(claim::MANIFEST)).unwrap();
    assert!(claim::load_manifest(&i.public, i.pin, &spec()).is_err());
    fs::remove_file(i.public.join(claim::MANIFEST)).unwrap();
    fs::rename(&real_manifest, i.public.join(claim::MANIFEST)).unwrap();

    // Symlink replacement in ciphertexts
    let real_ct = i.temp.path().join("real-ciphertexts.bin");
    fs::rename(i.public.join(claim::CIPHERTEXTS), &real_ct).unwrap();
    symlink(&real_ct, i.public.join(claim::CIPHERTEXTS)).unwrap();
    assert!(claim::verify_artifacts(&i.public, &i.manifest, &spec(), i.pin).is_err());
    assert!(i.evaluate(&release, &[true, true]).is_err());
    fs::remove_file(i.public.join(claim::CIPHERTEXTS)).unwrap();
    fs::rename(&real_ct, i.public.join(claim::CIPHERTEXTS)).unwrap();

    // Symlink replacement in selected-labels
    let real_labels = i.temp.path().join("real-selected-labels.bin");
    fs::rename(release.join(claim::SELECTED_LABELS), &real_labels).unwrap();
    symlink(&real_labels, release.join(claim::SELECTED_LABELS)).unwrap();
    assert!(i.evaluate(&release, &[true, true]).is_err());

    // Symlink replacement in private directory / private.json
    let j = Instance::new();
    let real_priv = j.temp.path().join("real-private.json");
    fs::rename(j.private.join("private.json"), &real_priv).unwrap();
    symlink(&real_priv, j.private.join("private.json")).unwrap();
    assert!(j.release("via-symlink-file", &[true, true]).is_err());
    fs::remove_file(j.private.join("private.json")).unwrap();
    fs::rename(&real_priv, j.private.join("private.json")).unwrap();

    let real_priv_dir = j.temp.path().join("real-private-dir");
    fs::rename(&j.private, &real_priv_dir).unwrap();
    symlink(&real_priv_dir, &j.private).unwrap();
    assert!(j.release("via-symlink-dir", &[true, true]).is_err());
}

#[cfg(unix)]
#[test]
fn permissive_private_directory_or_seed_file_is_refused_on_release() {
    use std::os::unix::fs::PermissionsExt;

    let i = Instance::new();
    fs::set_permissions(&i.private, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(i.release("group-readable-dir", &[true, true]).is_err());
    fs::set_permissions(&i.private, fs::Permissions::from_mode(0o700)).unwrap();

    fs::set_permissions(
        i.private.join("private.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(i.release("world-readable-seed", &[true, true]).is_err());
    assert!(!i.private.join("release-reservation.json").exists());

    fs::set_permissions(
        i.private.join("private.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    i.release("restored-permissions", &[true, true]).unwrap();
}

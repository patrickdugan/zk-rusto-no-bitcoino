#![forbid(unsafe_code)]

use lnm_batch_statement::{fixture, *};
use std::{collections::BTreeMap, env, fs, io::Read, path::Path, time::Instant};

fn read_bounded(path: &str, limit: usize) -> Result<Vec<u8>> {
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("input is not a bounded regular file".to_owned());
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("input exceeded byte limit during read".to_owned());
    }
    Ok(bytes)
}

fn args() -> Result<(String, BTreeMap<String, String>)> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or("expected demo, verify or inspect")?;
    let mut options = BTreeMap::new();
    while let Some(flag) = args.next() {
        if !flag.starts_with("--") {
            return Err("expected a named argument".to_owned());
        }
        let value = args.next().ok_or("missing argument value")?;
        if value.starts_with("--") || options.insert(flag, value).is_some() {
            return Err("missing value or duplicate argument".to_owned());
        }
    }
    Ok((command, options))
}

fn get<'a>(options: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    options
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing {key}"))
}

fn summary_json(j: &Journal, witness_bytes: usize, elapsed_us: u128) -> String {
    format!(concat!("{{\n",
        "  \"status\": \"native_verified_unproved\",\n",
        "  \"statement\": \"co_signed_batch_proposal_v1\",\n",
        "  \"network\": \"bitcoin-regtest\",\n",
        "  \"row_count\": {},\n  \"journal_bytes\": {},\n  \"witness_bytes\": {},\n  \"native_elapsed_ms\": {},\n  \"native_elapsed_us\": {},\n",
        "  \"batch_id\": \"{}\",\n  \"epoch\": {},\n",
        "  \"evaluation_height\": {},\n  \"valid_until_height\": {},\n",
        "  \"accepted_contracts_root\": \"{}\",\n  \"old_nullifier_root\": \"{}\",\n  \"new_nullifier_root\": \"{}\",\n",
        "  \"batch_tx_digest\": \"{}\",\n  \"batch_txid\": \"{}\",\n",
        "  \"total_collateral_sats\": {},\n  \"total_payout_sats\": {},\n  \"total_fee_sats\": {},\n",
        "  \"proof_generated\": false,\n  \"bitcoin_spend_authorized\": false,\n  \"funding_chain_status_verified\": false,\n",
        "  \"full_original_dlc_package_verified\": false,\n  \"known_fixture_keys_and_salts\": true\n}}\n"),
        j.row_count, JOURNAL_LEN, witness_bytes, elapsed_us / 1000, elapsed_us, hex(&j.batch_id), j.epoch, j.evaluation_height, j.valid_until_height,
        hex(&j.accepted_contracts_root), hex(&j.old_nullifier_root), hex(&j.new_nullifier_root), hex(&j.batch_tx_digest), hex(&j.batch_txid),
        j.total_collateral_sats, j.total_payout_sats, j.total_fee_sats)
}

fn main_result() -> Result<()> {
    let (command, options) = args()?;
    match command.as_str() {
        "demo" => {
            if options.len() != 2 {
                return Err("usage: lnm-native demo --rows 1|2|8|32 --out DIRECTORY".to_owned());
            }
            let count: usize = get(&options, "--rows")?
                .parse()
                .map_err(|_| "invalid row count")?;
            if ![1, 2, 8, 32].contains(&count) {
                return Err("demo sizes are 1, 2, 8 and 32".to_owned());
            }
            let out = Path::new(get(&options, "--out")?);
            let witness = fixture::demo_batch(count)?;
            let bytes = encode_batch(&witness)?;
            let start = Instant::now();
            let journal_bytes = verify_batch_bytes(&bytes)?;
            let elapsed = start.elapsed().as_micros();
            let journal =
                verify_expected_journal(&journal_bytes, &fixture::journal_pins(&witness.context))?;
            let summary = summary_json(&journal, bytes.len(), elapsed);
            fs::create_dir_all(out).map_err(|e| e.to_string())?;
            for (name, data) in [
                ("witness.bin", bytes),
                ("journal.bin", journal_bytes),
                (
                    "unsigned-batch.bin",
                    unsigned_batch_transaction(&witness.rows)?,
                ),
            ] {
                fs::write(out.join(name), data).map_err(|e| e.to_string())?;
            }
            fs::write(out.join("summary.json"), summary.as_bytes()).map_err(|e| e.to_string())?;
            print!("{summary}");
        }
        "verify" => {
            if options.len() != 2 {
                return Err(
                    "usage: lnm-native verify --witness FILE --journal TRUSTED_JOURNAL".to_owned(),
                );
            }
            let witness = read_bounded(get(&options, "--witness")?, MAX_WITNESS_BYTES)?;
            let expected = read_bounded(get(&options, "--journal")?, JOURNAL_LEN)?;
            let journal = verify_batch_bytes(&witness)?;
            if expected != journal {
                return Err(
                    "verified journal differs from independently retained expected bytes"
                        .to_owned(),
                );
            }
            println!(
                "{{\"status\":\"native_verified_unproved\",\"journal_sha256\":\"{}\"}}",
                hex(&sha256(&journal))
            );
        }
        "inspect" => {
            if options.len() != 1 {
                return Err("usage: lnm-native inspect --journal FILE".to_owned());
            }
            let bytes = read_bounded(get(&options, "--journal")?, JOURNAL_LEN)?;
            let journal = decode_journal(&bytes)?;
            // Parsing is not verification. This output is deliberately minimal.
            println!("{{\"status\":\"parsed_unverified\",\"row_count\":{},\"batch_id\":\"{}\",\"journal_sha256\":\"{}\"}}", journal.row_count, hex(&journal.batch_id), hex(&sha256(&bytes)));
        }
        _ => return Err("expected demo, verify or inspect".to_owned()),
    }
    Ok(())
}

fn main() {
    if let Err(error) = main_result() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

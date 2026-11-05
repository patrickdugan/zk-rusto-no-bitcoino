//! Differential execution using upstream BitVM's real Tapscript interpreter.
//! This accepts generated local fixtures only; it is not a network service.
use serde::Deserialize;
use std::{error::Error, fs};

#[derive(Deserialize)]
struct Vector {
    name: String,
    script_hex: String,
    expected_success: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1).ok_or("supply engine-vectors.json")?;
    if fs::metadata(&path)?.len() > 8 * 1024 * 1024 {
        return Err("fixture exceeds 8 MiB".into());
    }
    let vectors: Vec<Vector> = serde_json::from_slice(&fs::read(path)?)?;
    if vectors.is_empty() || vectors.len() > 1000 {
        return Err("fixture vector count out of bounds".into());
    }
    let count = vectors.len();
    for v in vectors {
        let bytes = hex::decode(&v.script_hex)?;
        if bytes.len() > 100_000 {
            return Err(format!("oversize primitive script: {}", v.name).into());
        }
        let result = bitvm::execute_script_buf(bitcoin::ScriptBuf::from_bytes(bytes));
        if result.success != v.expected_success {
            return Err(format!("{}: expected {}, got {:?}", v.name, v.expected_success, result).into());
        }
        println!("PASS {} expected_success={} stats={:?}", v.name, v.expected_success, result.stats);
    }
    println!("PASS {count} independent BitVM Tapscript vectors (stack limit enabled)");
    Ok(())
}

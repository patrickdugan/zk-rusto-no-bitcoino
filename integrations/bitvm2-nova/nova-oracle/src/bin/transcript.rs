//! Bounded conformance against actual crates.io Nova 0.76.0, non-EVM only.
//! No proving, setup, MSM, panic-catching, or locally reimplemented transcript.
use ff::PrimeField;
use halo2curves::CurveAffine;
use nova_snark::{
    provider::{
        keccak::Keccak256Transcript, pedersen::Commitment, traits::DlogGroup, PallasEngine,
        VestaEngine,
    },
    traits::{Engine, Group, TranscriptEngineTrait, TranscriptReprTrait},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{env, fs, io::Read};

const MAX_FILE: u64 = 2 << 20;
const MAX_BUFFER: usize = 1 << 20;

#[derive(Debug)]
enum Failure {
    Admission(String),
    Upstream,
    Conformance(String),
}
type Result<T> = std::result::Result<T, Failure>;
fn admission(message: &str) -> Failure {
    Failure::Admission(message.to_owned())
}
fn conformance(message: impl Into<String>) -> Failure {
    Failure::Conformance(message.into())
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| admission(&format!("missing {key}")))
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    field(value, key)?
        .as_str()
        .ok_or_else(|| admission("expected string"))
}
fn decode(value: &Value, key: &str, limit: usize) -> Result<Vec<u8>> {
    let text = string(value, key)?;
    if text.len() > 2 * limit {
        return Err(admission("hex length limit"));
    }
    hex::decode(text).map_err(|_| admission("invalid hex"))
}
// Upstream requires static labels. Leaks are bounded by the 2MiB case file and
// occur only in this short-lived CI harness, never in a network verifier.
fn label(value: &Value, key: &str) -> Result<&'static [u8]> {
    Ok(Box::leak(decode(value, key, 1024)?.into_boxed_slice()))
}
fn canonical<F: PrimeField>(bytes: &[u8]) -> Result<F> {
    let mut repr = F::Repr::default();
    if bytes.len() != repr.as_ref().len() {
        return Err(admission("field encoding must be exactly 32 bytes"));
    }
    repr.as_mut().copy_from_slice(bytes);
    Option::from(F::from_repr(repr)).ok_or_else(|| admission("noncanonical field"))
}
fn scalar<F: PrimeField>(value: &Value, key: &str) -> Result<F> {
    canonical(&decode(value, key, 32)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    round: u64,
    state: Vec<u8>,
    #[serde(default)]
    transcript_buffer: Vec<u8>,
}
fn check_snapshot(value: &Value) -> Result<()> {
    let snapshot: Snapshot = serde_json::from_value(value.clone())
        .map_err(|_| admission("malformed transcript snapshot"))?;
    if snapshot.state.len() != 64 || snapshot.transcript_buffer.len() > MAX_BUFFER {
        return Err(admission("snapshot length limit"));
    }
    // Read all fields here; exact round semantics are tested by upstream.
    let _ = snapshot.round;
    Ok(())
}

struct RawRepr(Vec<u8>);
impl<G: Group> TranscriptReprTrait<G> for RawRepr {
    fn to_transcript_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}
fn absorb<E: Engine, T: TranscriptReprTrait<E::GE>>(
    transcript: &mut Keccak256Transcript<E>,
    event: &Value,
    object: &T,
) -> Result<()> {
    let label = label(event, "label_hex")?;
    let repr = object.to_transcript_bytes();
    if let Some(expected) = event.get("repr_hex") {
        if expected.as_str() != Some(hex::encode(&repr).as_str()) {
            return Err(conformance("actual upstream object representation differs"));
        }
    }
    let state = serde_json::to_value(&*transcript).map_err(|e| conformance(e.to_string()))?;
    let buffer_len = state["transcript_buffer"].as_array().unwrap().len();
    if buffer_len + label.len() + repr.len() > MAX_BUFFER {
        return Err(admission("transcript buffer limit"));
    }
    transcript.absorb(label, object);
    Ok(())
}

fn point<E>(value: &Value) -> Result<Option<<E::GE as DlogGroup>::AffineGroupElement>>
where
    E: Engine,
    E::GE: DlogGroup,
    <E::GE as DlogGroup>::AffineGroupElement: CurveAffine<Base = E::Base>,
{
    let infinity = field(value, "infinity")?
        .as_bool()
        .ok_or_else(|| admission("invalid infinity flag"))?;
    let x = scalar::<E::Base>(value, "x_le")?;
    let y = scalar::<E::Base>(value, "y_le")?;
    if infinity {
        if x != E::Base::from(0u64) || y != E::Base::from(0u64) {
            return Err(admission("noncanonical identity coordinates"));
        }
        return Ok(None);
    }
    let affine = <E::GE as DlogGroup>::AffineGroupElement::from_xy(x, y);
    let affine = Option::from(affine).ok_or_else(|| admission("point not on curve"))?;
    // halo2curves also accepts (0, 0) as its identity sentinel in from_xy.
    // A successful constructor therefore does not establish finiteness.
    // Keep the transport's explicit infinity flag canonical, and never feed
    // a raw-affine identity into the upstream transcript representation.
    if E::GE::group(&affine).to_coordinates().2 {
        return Err(admission("identity encoded with finite point flag"));
    }
    Ok(Some(affine))
}

fn apply<E>(transcript: &mut Keccak256Transcript<E>, event: &Value) -> Result<Option<E::Scalar>>
where
    E: Engine,
    E::GE: DlogGroup,
    <E::GE as DlogGroup>::AffineGroupElement: CurveAffine<Base = E::Base>,
{
    match string(event, "op")? {
        "absorb_bytes" => {
            absorb(
                transcript,
                event,
                &RawRepr(decode(event, "data_hex", MAX_BUFFER)?),
            )?;
        }
        "absorb_scalar" => {
            absorb(transcript, event, &scalar::<E::Scalar>(event, "value_le")?)?;
        }
        "absorb_scalars" => {
            let values = field(event, "values_le")?
                .as_array()
                .ok_or_else(|| admission("expected vector"))?;
            if values.len() > 4096 {
                return Err(admission("scalar vector limit"));
            }
            let scalars = values
                .iter()
                .map(|v| scalar::<E::Scalar>(&json!({"x": v}), "x"))
                .collect::<Result<Vec<_>>>()?;
            absorb(transcript, event, &scalars.as_slice())?;
        }
        "absorb_affine" => {
            let affine = point::<E>(field(event, "point")?)?.ok_or_else(|| {
                admission("raw affine identity is unsupported: upstream coordinates unwrap")
            })?;
            absorb(transcript, event, &affine)?;
        }
        "absorb_commitment" => {
            let commitment = match point::<E>(field(event, "point")?)? {
                None => Commitment::<E>::default(),
                Some(affine) => {
                    let group = E::GE::group(&affine);
                    // Public serde constructs an actual upstream commitment;
                    // its TranscriptRepr implementation supplies the bytes.
                    serde_json::from_value::<Commitment<E>>(json!({"comm": group}))
                        .map_err(|e| conformance(format!("commitment serde: {e}")))?
                }
            };
            absorb(transcript, event, &commitment)?;
        }
        "dom_sep" => {
            let bytes = label(event, "data_hex")?;
            let state =
                serde_json::to_value(&*transcript).map_err(|e| conformance(e.to_string()))?;
            if state["transcript_buffer"].as_array().unwrap().len() + 4 + bytes.len() > MAX_BUFFER {
                return Err(admission("transcript buffer limit"));
            }
            transcript.dom_sep(bytes);
        }
        "squeeze" | "squeeze_bits" => {
            let label = label(event, "label_hex")?;
            let before =
                serde_json::to_value(&*transcript).map_err(|e| conformance(e.to_string()))?;
            let result = if string(event, "op")? == "squeeze" {
                transcript.squeeze(label)
            } else {
                let bits = field(event, "num_bits")?
                    .as_u64()
                    .ok_or_else(|| admission("invalid bits"))?;
                let force = field(event, "start_with_one")?
                    .as_bool()
                    .ok_or_else(|| admission("invalid force bit"))?;
                // These are assertions upstream. Validate first; a panic must
                // fail CI, and is never a successful rejection.
                if !(2..=254).contains(&bits) {
                    return Err(admission("invalid squeeze_bits range"));
                }
                transcript.squeeze_bits(label, bits as usize, force)
            };
            match result {
                Ok(challenge) => return Ok(Some(challenge)),
                Err(_) => {
                    let after = serde_json::to_value(&*transcript)
                        .map_err(|e| conformance(e.to_string()))?;
                    if before["round"].as_u64() == Some(u64::MAX) && before == after {
                        return Err(Failure::Upstream);
                    }
                    return Err(conformance(
                        "unexpected upstream transcript error or mutation",
                    ));
                }
            }
        }
        _ => return Err(admission("unknown operation")),
    }
    Ok(None)
}

fn run<E>(case: &Value) -> Result<usize>
where
    E: Engine,
    E::GE: DlogGroup,
    <E::GE as DlogGroup>::AffineGroupElement: CurveAffine<Base = E::Base>,
{
    let mut transcript = if let Some(initial) = case.get("initial_state") {
        check_snapshot(initial)?;
        serde_json::from_value::<Keccak256Transcript<E>>(initial.clone())
            .map_err(|e| conformance(format!("upstream restore: {e}")))?
    } else {
        Keccak256Transcript::<E>::new(label(case, "label_hex")?)
    };
    if let Some(expected) = case.get("initial_expected") {
        if serde_json::to_value(&transcript).map_err(|e| conformance(e.to_string()))? != *expected {
            return Err(conformance("initial state mismatch"));
        }
    }
    let events = field(case, "events")?
        .as_array()
        .ok_or_else(|| admission("expected events"))?;
    if events.len() > 512 {
        return Err(admission("event count limit"));
    }
    for (index, event) in events.iter().enumerate() {
        let challenge = apply::<E>(&mut transcript, event)?;
        if let Some(challenge) = challenge {
            if string(event, "challenge_le")? != hex::encode(challenge.to_repr().as_ref()) {
                return Err(conformance(format!("challenge mismatch at event {index}")));
            }
        }
        if let Some(expected) = event.get("expected") {
            if serde_json::to_value(&transcript).map_err(|e| conformance(e.to_string()))?
                != *expected
            {
                return Err(conformance(format!(
                    "state/buffer mismatch at event {index}"
                )));
            }
        } else {
            return Err(conformance("successful event missing expected state"));
        }
        // Also test restoration after every absorb, separator, and squeeze.
        let snapshot = serde_json::to_value(&transcript).map_err(|e| conformance(e.to_string()))?;
        transcript = serde_json::from_value(snapshot).map_err(|e| conformance(e.to_string()))?;
    }
    Ok(events.len())
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("usage: transcript CASES.json")?;
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > MAX_FILE {
        return Err("case file too large".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE {
        return Err("case file too large".into());
    }
    let cases: Vec<Value> = serde_json::from_slice(&bytes)?;
    if cases.len() > 128 {
        return Err("too many cases".into());
    }
    let (mut accepted, mut rejected, mut events) = (0, 0, 0);
    for case in &cases {
        let result = match case["engine"].as_str() {
            Some("pallas") => run::<PallasEngine>(case),
            Some("vesta") => run::<VestaEngine>(case),
            _ => Err(admission("unsupported engine")),
        };
        match (case.get("expected_error").and_then(Value::as_str), result) {
            (None, Ok(count)) => {
                accepted += 1;
                events += count;
            }
            (Some("admission"), Err(Failure::Admission(reason))) => {
                if reason.is_empty() {
                    return Err("empty admission reason".into());
                }
                rejected += 1;
            }
            (Some("upstream"), Err(Failure::Upstream)) => rejected += 1,
            (_, Err(Failure::Conformance(reason))) => {
                return Err(format!("{}: {reason}", case["name"]).into());
            }
            (expected, actual) => {
                return Err(
                    format!("{}: expected {expected:?}, actual {actual:?}", case["name"]).into(),
                );
            }
        }
    }
    println!(
        "{}",
        json!({"backend":"nova-snark=0.76.0/non-EVM", "cases":cases.len(),
        "accepted":accepted,"rejected":rejected,"checked_events":events,
        "panic_is_rejection":false,"proving":false,"complete_verifier":false})
    );
    Ok(())
}

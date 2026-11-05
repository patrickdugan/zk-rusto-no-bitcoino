//! Bounded observation of the actual released Nova verifier algorithms.
//!
//! Fields/groups/circuits and all cryptographic computations remain upstream.
//! Capture is explicitly enabled only around a positive, admitted verification.
//! Logging failures invalidate the trace; they are never proof rejections.
use ff::{PrimeField, PrimeFieldBits};
use nova_snark::{
    errors::NovaError,
    provider::{
        keccak::Keccak256Transcript,
        pedersen::CommitmentEngine,
        poseidon::{PoseidonConstantsCircuit, PoseidonRO, PoseidonROCircuit},
        PallasEngine, VestaEngine,
    },
    traits::{Engine, ROMode, ROTrait, TranscriptEngineTrait, TranscriptReprTrait},
};
use serde::{ser, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, OnceLock,
    },
};

const MAX_STREAMS: usize = 16;
const MAX_EVENTS: usize = 4096;
const MAX_BYTES: usize = 8 << 20;
const MAX_BUFFER: usize = 1 << 20;
const MAX_RO_STATE: usize = 1024;

#[derive(Serialize)]
pub struct TraceStream {
    kind: &'static str,
    engine: &'static str,
    field_role: &'static str,
    session: usize,
    events: Vec<Value>,
}

#[derive(Serialize)]
pub struct TraceReport {
    schema: &'static str,
    streams: Vec<TraceStream>,
    events: usize,
    recorded_event_bytes: usize,
    max_streams: usize,
    max_events: usize,
    max_recorded_event_bytes: usize,
    complete_capture: bool,
    panic_is_rejection: bool,
}

#[derive(Clone, Copy)]
struct Handle {
    generation: u64,
    index: usize,
}

struct Sink {
    enabled: bool,
    generation: u64,
    sessions: BTreeMap<(&'static str, &'static str), usize>,
    streams: Vec<TraceStream>,
    events: usize,
    bytes: usize,
    max_streams: usize,
    max_events: usize,
    max_bytes: usize,
}
impl Default for Sink {
    fn default() -> Self {
        Self {
            enabled: false,
            generation: 0,
            sessions: BTreeMap::new(),
            streams: Vec::new(),
            events: 0,
            bytes: 0,
            max_streams: MAX_STREAMS,
            max_events: MAX_EVENTS,
            max_bytes: MAX_BYTES,
        }
    }
}
static SINK: OnceLock<Mutex<Sink>> = OnceLock::new();
static FATAL: AtomicBool = AtomicBool::new(false);
fn sink() -> &'static Mutex<Sink> {
    SINK.get_or_init(|| Mutex::new(Sink::default()))
}
fn failed() {
    FATAL.store(true, Ordering::SeqCst);
}

/// Start a fresh capture after setup/key authentication, immediately before verify.
pub fn begin_capture() -> Result<(), String> {
    begin_with_limits(MAX_STREAMS, MAX_EVENTS, MAX_BYTES)
}
fn begin_with_limits(
    max_streams: usize,
    max_events: usize,
    max_bytes: usize,
) -> Result<(), String> {
    let mut s = sink().lock().map_err(|_| "trace sink mutex poisoned")?;
    if s.enabled {
        return Err("nested verifier trace capture".into());
    }
    let generation = s
        .generation
        .checked_add(1)
        .ok_or("trace generation overflow")?;
    *s = Sink {
        enabled: true,
        generation,
        max_streams,
        max_events,
        max_bytes,
        ..Sink::default()
    };
    FATAL.store(false, Ordering::SeqCst);
    Ok(())
}

/// Stop capture and fail closed on overflow, stale handles or mutex poisoning.
pub fn finish_capture() -> Result<TraceReport, String> {
    let mut s = sink().lock().map_err(|_| "trace sink mutex poisoned")?;
    if !s.enabled {
        return Err("verifier trace capture is not active".into());
    }
    s.enabled = false;
    if FATAL.load(Ordering::SeqCst) {
        s.streams.clear();
        return Err("verifier trace capture failed or exceeded its bounds".into());
    }
    let mut streams = std::mem::take(&mut s.streams);
    streams.sort_by_key(|stream| (stream.kind, stream.engine, stream.session));
    Ok(TraceReport {
        schema: "bitvm2-nova-real-verifier-trace/v1",
        streams,
        events: s.events,
        recorded_event_bytes: s.bytes,
        max_streams: s.max_streams,
        max_events: s.max_events,
        max_recorded_event_bytes: s.max_bytes,
        complete_capture: true,
        panic_is_rejection: false,
    })
}

fn new_stream(
    kind: &'static str,
    engine: &'static str,
    field_role: &'static str,
) -> Option<Handle> {
    let Ok(mut s) = sink().lock() else {
        failed();
        return None;
    };
    if !s.enabled {
        return None;
    }
    if FATAL.load(Ordering::SeqCst) || s.streams.len() >= s.max_streams {
        failed();
        return None;
    }
    let session = s.sessions.entry((kind, engine)).or_default();
    let ordinal = *session;
    *session += 1;
    let handle = Handle {
        generation: s.generation,
        index: s.streams.len(),
    };
    s.streams.push(TraceStream {
        kind,
        engine,
        field_role,
        session: ordinal,
        events: Vec::new(),
    });
    Some(handle)
}

fn record(handle: Option<Handle>, mut event: Value) {
    let Some(handle) = handle else {
        return;
    };
    let Ok(mut s) = sink().lock() else {
        failed();
        return;
    };
    if !s.enabled || s.generation != handle.generation || handle.index >= s.streams.len() {
        failed();
        return;
    }
    if FATAL.load(Ordering::SeqCst) {
        return;
    }
    let sequence = s.streams[handle.index].events.len();
    let Some(object) = event.as_object_mut() else {
        failed();
        return;
    };
    object.insert("sequence".into(), json!(sequence));
    let Ok(encoded) = serde_json::to_vec(&event) else {
        failed();
        return;
    };
    let Some(bytes) = s.bytes.checked_add(encoded.len()) else {
        failed();
        return;
    };
    if s.events >= s.max_events || bytes > s.max_bytes {
        failed();
        return;
    }
    s.bytes = bytes;
    s.events += 1;
    s.streams[handle.index].events.push(event);
}

pub trait TraceEngine: Engine {
    const NAME: &'static str;
    const SCALAR_ROLE: &'static str;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TracePallas;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraceVesta;

impl Engine for TracePallas {
    type Base = <PallasEngine as Engine>::Base;
    type Scalar = <PallasEngine as Engine>::Scalar;
    type GE = <PallasEngine as Engine>::GE;
    type RO = TracePoseidon<Self::Base, PallasBase>;
    type ROCircuit = <PallasEngine as Engine>::ROCircuit;
    type RO2 = TracePoseidon<Self::Scalar, PallasScalar>;
    type RO2Circuit = <PallasEngine as Engine>::RO2Circuit;
    type TE = TraceTranscript<Self>;
    type CE = CommitmentEngine<Self>;
}
impl Engine for TraceVesta {
    type Base = <VestaEngine as Engine>::Base;
    type Scalar = <VestaEngine as Engine>::Scalar;
    type GE = <VestaEngine as Engine>::GE;
    type RO = TracePoseidon<Self::Base, VestaBase>;
    type ROCircuit = <VestaEngine as Engine>::ROCircuit;
    type RO2 = TracePoseidon<Self::Scalar, VestaScalar>;
    type RO2Circuit = <VestaEngine as Engine>::RO2Circuit;
    type TE = TraceTranscript<Self>;
    type CE = CommitmentEngine<Self>;
}
impl TraceEngine for TracePallas {
    const NAME: &'static str = "pallas";
    const SCALAR_ROLE: &'static str = "pallas_scalar";
}
impl TraceEngine for TraceVesta {
    const NAME: &'static str = "vesta";
    const SCALAR_ROLE: &'static str = "vesta_scalar";
}

#[derive(Deserialize)]
struct KeccakSnapshot {
    round: u64,
    state: Vec<u8>,
    transcript_buffer: Vec<u8>,
}
impl KeccakSnapshot {
    fn event_value(&self) -> Value {
        json!({"round":self.round,"state_hex":hex::encode(&self.state),"buffer_hex":hex::encode(&self.transcript_buffer)})
    }
}

pub struct TraceTranscript<E: TraceEngine> {
    inner: Keccak256Transcript<E>,
    handle: Option<Handle>,
    buffer_len: usize,
}
impl<E: TraceEngine> Serialize for TraceTranscript<E> {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.inner.serialize(serializer)
    }
}
impl<E: TraceEngine> TraceTranscript<E> {
    fn snapshot(&self) -> Option<KeccakSnapshot> {
        if self.handle.is_none() || FATAL.load(Ordering::SeqCst) {
            return None;
        }
        let result =
            serde_json::to_value(&self.inner).and_then(serde_json::from_value::<KeccakSnapshot>);
        match result {
            Ok(snapshot)
                if snapshot.state.len() == 64 && snapshot.transcript_buffer.len() <= MAX_BUFFER =>
            {
                Some(snapshot)
            }
            _ => {
                failed();
                None
            }
        }
    }
    fn after_squeeze(&mut self, label: &[u8], challenge: &E::Scalar, bits: Option<(usize, bool)>) {
        if let Some(snapshot) = self.snapshot() {
            if !snapshot.transcript_buffer.is_empty() {
                failed();
                return;
            }
            self.buffer_len = 0;
            let mut event = json!({"op":"squeeze","label_hex":hex::encode(label),
                "challenge_le":hex::encode(challenge.to_repr().as_ref()),"after":snapshot.event_value()});
            if let Some((num_bits, start_with_one)) = bits {
                event["op"] = json!("squeeze_bits");
                event["num_bits"] = json!(num_bits);
                event["start_with_one"] = json!(start_with_one);
            }
            record(self.handle, event);
        }
    }
}
impl<E: TraceEngine> TranscriptEngineTrait<E> for TraceTranscript<E> {
    fn new(label: &'static [u8]) -> Self {
        let inner = Keccak256Transcript::<E>::new(label);
        let trace = Self {
            inner,
            handle: new_stream("keccak", E::NAME, E::SCALAR_ROLE),
            buffer_len: 0,
        };
        if let Some(snapshot) = trace.snapshot() {
            record(
                trace.handle,
                json!({"op":"new","label_hex":hex::encode(label),"after":snapshot.event_value()}),
            );
        }
        trace
    }
    fn squeeze(&mut self, label: &'static [u8]) -> Result<E::Scalar, NovaError> {
        let result = self.inner.squeeze(label);
        match &result {
            Ok(challenge) => self.after_squeeze(label, challenge, None),
            Err(_) => failed(),
        }
        result
    }
    fn squeeze_bits(
        &mut self,
        label: &'static [u8],
        num_bits: usize,
        start_with_one: bool,
    ) -> Result<E::Scalar, NovaError> {
        let result = self.inner.squeeze_bits(label, num_bits, start_with_one);
        match &result {
            Ok(challenge) => self.after_squeeze(label, challenge, Some((num_bits, start_with_one))),
            Err(_) => failed(),
        }
        result
    }
    fn absorb<T: TranscriptReprTrait<E::GE>>(&mut self, label: &'static [u8], object: &T) {
        // Delegate the actual object once; observe exact bytes through public
        // upstream snapshot serialization instead of invoking its repr again.
        self.inner.absorb(label, object);
        if let Some(snapshot) = self.snapshot() {
            let Some(start) = self.buffer_len.checked_add(label.len()) else {
                failed();
                return;
            };
            if start > snapshot.transcript_buffer.len()
                || snapshot.transcript_buffer[self.buffer_len..start] != *label
            {
                failed();
                return;
            }
            let repr = hex::encode(&snapshot.transcript_buffer[start..]);
            self.buffer_len = snapshot.transcript_buffer.len();
            record(
                self.handle,
                json!({"op":"absorb","label_hex":hex::encode(label),"repr_hex":repr,"after":snapshot.event_value()}),
            );
        }
    }
    fn dom_sep(&mut self, bytes: &'static [u8]) {
        self.inner.dom_sep(bytes);
        if let Some(snapshot) = self.snapshot() {
            let expected = [b"NoDS".as_slice(), bytes].concat();
            let Some(end) = self.buffer_len.checked_add(expected.len()) else {
                failed();
                return;
            };
            if snapshot.transcript_buffer.len() != end
                || snapshot.transcript_buffer[self.buffer_len..] != expected
            {
                failed();
                return;
            }
            self.buffer_len = end;
            record(
                self.handle,
                json!({"op":"dom_sep","data_hex":hex::encode(bytes),"after":snapshot.event_value()}),
            );
        }
    }
}

pub trait PoseidonRole: Send + Sync {
    const KIND: &'static str;
    const ENGINE: &'static str;
    const FIELD: &'static str;
}
pub struct PallasBase;
pub struct PallasScalar;
pub struct VestaBase;
pub struct VestaScalar;
macro_rules! role {
    ($tag:ident,$kind:literal,$engine:literal,$field:literal) => {
        impl PoseidonRole for $tag {
            const KIND: &'static str = $kind;
            const ENGINE: &'static str = $engine;
            const FIELD: &'static str = $field;
        }
    };
}
role!(PallasBase, "poseidon_base", "pallas", "pallas_base");
role!(PallasScalar, "poseidon_scalar", "pallas", "pallas_scalar");
role!(VestaBase, "poseidon_base", "vesta", "vesta_base");
role!(VestaScalar, "poseidon_scalar", "vesta", "vesta_scalar");

pub struct TracePoseidon<F: PrimeField, Tag: PoseidonRole> {
    inner: PoseidonRO<F>,
    handle: Option<Handle>,
    mode: ROMode,
    _tag: PhantomData<Tag>,
}
impl<F, Tag> TracePoseidon<F, Tag>
where
    F: PrimeField + PrimeFieldBits + Serialize + for<'de> Deserialize<'de>,
    Tag: PoseidonRole,
{
    fn snapshot(&self) -> Option<Value> {
        if self.handle.is_none() || FATAL.load(Ordering::SeqCst) {
            return None;
        }
        let mut fields = StateFields::default();
        if self.inner.serialize(&mut fields).is_err() {
            failed();
            return None;
        }
        let Some(state) = fields.state else {
            failed();
            return None;
        };
        Some(json!({"state_le":state,"mode":mode_name(self.mode)}))
    }
}
fn mode_name(mode: ROMode) -> &'static str {
    match mode {
        ROMode::Wide => "wide",
        ROMode::Narrow => "narrow",
    }
}
impl<F, Tag> ROTrait<F> for TracePoseidon<F, Tag>
where
    F: PrimeField + PrimeFieldBits + Serialize + for<'de> Deserialize<'de>,
    Tag: PoseidonRole,
{
    type CircuitRO = PoseidonROCircuit<F>;
    type Constants = PoseidonConstantsCircuit<F>;
    fn new(constants: Self::Constants) -> Self {
        Self::new_with_mode(constants, ROMode::Wide)
    }
    fn new_with_mode(constants: Self::Constants, mode: ROMode) -> Self {
        let trace = Self {
            inner: PoseidonRO::new_with_mode(constants, mode),
            handle: new_stream(Tag::KIND, Tag::ENGINE, Tag::FIELD),
            mode,
            _tag: PhantomData,
        };
        if let Some(after) = trace.snapshot() {
            record(
                trace.handle,
                json!({"op":"new","mode":mode_name(mode),"after":after}),
            );
        }
        trace
    }
    fn absorb(&mut self, value: F) {
        self.inner.absorb(value);
        if let Some(after) = self.snapshot() {
            record(
                self.handle,
                json!({"op":"absorb","value_le":hex::encode(value.to_repr().as_ref()),"after":after}),
            );
        }
    }
    fn squeeze(&mut self, num_bits: usize, start_with_one: bool) -> F {
        let challenge = self.inner.squeeze(num_bits, start_with_one);
        if let Some(after) = self.snapshot() {
            record(
                self.handle,
                json!({"op":"squeeze","num_bits":num_bits,"start_with_one":start_with_one,
            "challenge_le":hex::encode(challenge.to_repr().as_ref()),"after":after}),
            );
        }
        challenge
    }
}

// Select only PoseidonRO.state, avoiding serialization of its large constants.
#[derive(Default)]
struct StateFields {
    state: Option<Vec<String>>,
}
fn state_error() -> serde_json::Error {
    <serde_json::Error as ser::Error>::custom("unexpected native Poseidon snapshot")
}
macro_rules! reject_fields {
    ($($method:ident($ty:ty)),* $(,)?) => { $(fn $method(self,_:$ty)->Result<(),Self::Error>{Err(state_error())})* };
}
impl<'a> ser::Serializer for &'a mut StateFields {
    type Ok = ();
    type Error = serde_json::Error;
    type SerializeSeq = ser::Impossible<(), Self::Error>;
    type SerializeTuple = ser::Impossible<(), Self::Error>;
    type SerializeTupleStruct = ser::Impossible<(), Self::Error>;
    type SerializeTupleVariant = ser::Impossible<(), Self::Error>;
    type SerializeMap = ser::Impossible<(), Self::Error>;
    type SerializeStruct = Self;
    type SerializeStructVariant = ser::Impossible<(), Self::Error>;
    reject_fields!(
        serialize_bool(bool),
        serialize_i8(i8),
        serialize_i16(i16),
        serialize_i32(i32),
        serialize_i64(i64),
        serialize_i128(i128),
        serialize_u8(u8),
        serialize_u16(u16),
        serialize_u32(u32),
        serialize_u64(u64),
        serialize_u128(u128),
        serialize_f32(f32),
        serialize_f64(f64),
        serialize_char(char),
        serialize_str(&str),
        serialize_bytes(&[u8])
    );
    fn serialize_none(self) -> Result<(), Self::Error> {
        Err(state_error())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, _: &T) -> Result<(), Self::Error> {
        Err(state_error())
    }
    fn serialize_unit(self) -> Result<(), Self::Error> {
        Err(state_error())
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), Self::Error> {
        Err(state_error())
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
    ) -> Result<(), Self::Error> {
        Err(state_error())
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: &T,
    ) -> Result<(), Self::Error> {
        Err(state_error())
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: &T,
    ) -> Result<(), Self::Error> {
        Err(state_error())
    }
    fn serialize_seq(self, _: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Err(state_error())
    }
    fn serialize_tuple(self, _: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Err(state_error())
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Err(state_error())
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(state_error())
    }
    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Err(state_error())
    }
    fn serialize_struct(
        self,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(self)
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Err(state_error())
    }
    fn is_human_readable(&self) -> bool {
        true
    }
}
impl ser::SerializeStruct for &mut StateFields {
    type Ok = ();
    type Error = serde_json::Error;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        if key == "state" {
            if self.state.is_some() {
                return Err(state_error());
            }
            let state: Vec<String> = serde_json::from_value(serde_json::to_value(value)?)?;
            if state.len() > MAX_RO_STATE
                || state.iter().any(|x| {
                    x.len() != 64
                        || !x
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
            {
                return Err(state_error());
            }
            self.state = Some(state);
        }
        Ok(())
    }
    fn end(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as CountOrdering};
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    type F = <TracePallas as Engine>::Scalar;

    #[test]
    fn golden_native_keccak_and_single_repr_evaluation() {
        let _guard = TEST_LOCK.lock().unwrap();
        begin_capture().unwrap();
        let mut transcript = TraceTranscript::<TracePallas>::new(b"test");
        transcript.absorb(b"s1", &F::from(2));
        transcript.absorb(b"s2", &F::from(5));
        let challenge = transcript.squeeze(b"c1").unwrap();
        assert_eq!(
            hex::encode(challenge.to_repr().as_ref()),
            "60dba8657186ff1abbeb237854707faf6ea79361546f8aae65a8fbb722c9ca0c"
        );
        struct Once<'a>(&'a AtomicUsize);
        impl TranscriptReprTrait<<TracePallas as Engine>::GE> for Once<'_> {
            fn to_transcript_bytes(&self) -> Vec<u8> {
                self.0.fetch_add(1, CountOrdering::SeqCst);
                vec![1, 2, 3]
            }
        }
        let calls = AtomicUsize::new(0);
        transcript.absorb(b"once", &Once(&calls));
        assert_eq!(calls.load(CountOrdering::SeqCst), 1);
        let snapshot = serde_json::to_value(&transcript).unwrap();
        assert_eq!(snapshot, serde_json::to_value(&transcript.inner).unwrap());
        let report = finish_capture().unwrap();
        assert_eq!(report.streams.len(), 1);
        assert_eq!(report.events, 5);
        assert_eq!(report.streams[0].events[4]["repr_hex"], "010203");
    }

    #[test]
    fn poseidon_wide_and_narrow_forward_native_and_capture_only_state() {
        let _guard = TEST_LOCK.lock().unwrap();
        begin_capture().unwrap();
        for mode in [ROMode::Wide, ROMode::Narrow] {
            let constants = PoseidonConstantsCircuit::<F>::default();
            let mut native = PoseidonRO::<F>::new_with_mode(constants.clone(), mode);
            let mut traced = TracePoseidon::<F, PallasScalar>::new_with_mode(constants, mode);
            for value in [F::from(2), F::from(5)] {
                native.absorb(value);
                traced.absorb(value);
            }
            assert_eq!(native.squeeze(128, true), traced.squeeze(128, true));
        }
        let report = finish_capture().unwrap();
        assert_eq!(report.streams.len(), 2);
        assert_eq!(report.events, 8);
        assert_eq!(report.streams[0].events[0]["mode"], "wide");
        assert_eq!(report.streams[1].events[0]["mode"], "narrow");
        assert_eq!(
            report.streams[0].events[3]["after"]["state_le"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("constants"));
    }

    #[test]
    fn event_stream_and_byte_caps_invalidate_capture_without_changing_native_calls() {
        let _guard = TEST_LOCK.lock().unwrap();
        for limits in [(0, 4096, MAX_BYTES), (16, 1, MAX_BYTES), (16, 4096, 1)] {
            begin_with_limits(limits.0, limits.1, limits.2).unwrap();
            let mut transcript = TraceTranscript::<TracePallas>::new(b"bounds");
            transcript.absorb(b"value", &F::from(1));
            assert!(transcript.squeeze(b"challenge").is_ok());
            assert!(finish_capture().is_err());
        }
    }

    #[test]
    fn inactive_setup_is_excluded_and_role_order_is_deterministic() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut inactive = TraceTranscript::<TracePallas>::new(b"setup");
        inactive.absorb(b"before", &F::from(1));
        begin_capture().unwrap();
        assert!(begin_capture().is_err());
        let _vesta = TraceTranscript::<TraceVesta>::new(b"verify");
        let _pallas = TraceTranscript::<TracePallas>::new(b"verify");
        let report = finish_capture().unwrap();
        assert_eq!(report.events, 2);
        assert_eq!(report.streams[0].engine, "pallas");
        assert_eq!(report.streams[1].engine, "vesta");
    }
}

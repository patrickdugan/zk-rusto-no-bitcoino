//! serde helpers: fixed byte arrays and byte vectors as lowercase hex strings.
use serde::{de::Error, Deserialize, Deserializer, Serializer};

pub fn ser<S: Serializer, T: AsRef<[u8]>>(v: &T, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(v.as_ref()))
}

pub fn de_vec<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    hex::decode(s).map_err(D::Error::custom)
}

pub fn de_arr<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
    let v = de_vec(d)?;
    v.try_into().map_err(|_| D::Error::custom(format!("expected {N} bytes")))
}

pub mod a32 {
    pub use super::ser as serialize;
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        super::de_arr::<D, 32>(d)
    }
}
pub mod a64 {
    pub use super::ser as serialize;
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        super::de_arr::<D, 64>(d)
    }
}
pub mod a65 {
    pub use super::ser as serialize;
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 65], D::Error> {
        super::de_arr::<D, 65>(d)
    }
}
pub mod bytes {
    pub use super::ser as serialize;
    pub use super::de_vec as deserialize;
}
pub mod v32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(hex::encode))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
        let v: Vec<String> = Vec::deserialize(d)?;
        v.into_iter()
            .map(|s| {
                let b = hex::decode(s).map_err(serde::de::Error::custom)?;
                b.try_into().map_err(|_| serde::de::Error::custom("expected 32 bytes"))
            })
            .collect()
    }
}
pub mod pair64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[[u8; 64]; 2], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(hex::encode))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[[u8; 64]; 2], D::Error> {
        let v: Vec<String> = Vec::deserialize(d)?;
        if v.len() != 2 {
            return Err(serde::de::Error::custom("expected a pair"));
        }
        let f = |s: &String| -> Result<[u8; 64], D::Error> {
            let b = hex::decode(s).map_err(serde::de::Error::custom)?;
            b.try_into().map_err(|_| serde::de::Error::custom("expected 64 bytes"))
        };
        Ok([f(&v[0])?, f(&v[1])?])
    }
}

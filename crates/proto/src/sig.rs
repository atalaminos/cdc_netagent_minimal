//! Tuple (de)serialization of a 64-byte Ed25519 signature.
//!
//! Byte-identical to the helper in NetEdge `src/license.rs`, so signed structs
//! stay wire-compatible. Use via `#[serde(with = "crate::sig")]`.

use crate::crypto::SIG_LEN;
use serde::de::{Error, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserializer, Serializer};
use std::fmt;

pub fn serialize<S: Serializer>(sig: &[u8; SIG_LEN], s: S) -> Result<S::Ok, S::Error> {
    let mut tup = s.serialize_tuple(SIG_LEN)?;
    for b in sig.iter() {
        tup.serialize_element(b)?;
    }
    tup.end()
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; SIG_LEN], D::Error> {
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = [u8; SIG_LEN];
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "exactly {SIG_LEN} bytes")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = [0u8; SIG_LEN];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = seq.next_element()?.ok_or_else(|| {
                    A::Error::custom(format!("expected {SIG_LEN} bytes, got {i}"))
                })?;
            }
            Ok(out)
        }
    }
    d.deserialize_tuple(SIG_LEN, V)
}

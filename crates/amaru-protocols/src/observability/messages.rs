// Copyright 2026 PRAGMA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Observability mini-protocol wire messages (draft observability-CIP CDDL).
//!
//! Experimental mux protocol number 11. One-shot: GetPublications → Publications.

use std::collections::BTreeMap;

use amaru_kernel::{NonEmptyBytes, cbor};

/// Maximum publications in one `MsgPublications` (CDDL `*32`).
pub const MAX_PUBLICATIONS: usize = 32;

/// Maximum encoded ciphertext bytes per encrypted publication.
pub const MAX_CIPHERTEXT_BYTES: usize = 16384;

/// X25519 observer public key length.
pub const OBSERVER_PUBLIC_KEY_LEN: usize = 32;

/// Only `publicationVersion = 1` is defined for this prototype.
pub const PUBLICATION_VERSION: u64 = 1;

/// Maximum mux buffer / encoded MsgPublications size (codec/mux limit).
pub const MAX_MESSAGE_BYTES: usize = 65535;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum ExperimentalValue {
    Text(String),
    Uint(u64),
    Bool(bool),
    Bytes(Vec<u8>),
    UintArray(Vec<u64>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize, Default)]
pub struct OpenPayload {
    pub node_name: Option<String>,
    pub node_version_major: Option<u16>,
    pub experimental: BTreeMap<String, ExperimentalValue>,
}

impl OpenPayload {
    pub fn stub_amaru(major: u16) -> Self {
        Self { node_name: Some("amaru".to_string()), node_version_major: Some(major), experimental: BTreeMap::new() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Publication {
    Open { version: u64, snapshot_slot: u64, payload: OpenPayload },
    Encrypted {
        version: u64,
        snapshot_slot: u64,
        observer_public_key: [u8; OBSERVER_PUBLIC_KEY_LEN],
        ciphertext: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Message {
    GetPublications,
    Publications(Vec<Publication>),
    /// Pre-encoded `MsgPublications` CBOR. Encode writes these bytes verbatim so the
    /// observe hot path never re-serializes. Not produced by Decode (wire peers send
    /// the logical [`Self::Publications`] form).
    CachedPublications(NonEmptyBytes),
}

impl Message {
    pub fn message_type(&self) -> &'static str {
        match self {
            Message::GetPublications => "GetPublications",
            Message::Publications(_) | Message::CachedPublications(_) => "Publications",
        }
    }

    /// Stub cached response: one open publication for Amaru (pre-encoded).
    pub fn stub_cache(snapshot_slot: u64, major: u16) -> Self {
        Self::cache_publications(vec![Publication::Open {
            version: PUBLICATION_VERSION,
            snapshot_slot,
            payload: OpenPayload::stub_amaru(major),
        }])
    }

    /// Build a wire reply that Encode serves as already-serialized CBOR bytes.
    pub fn cache_publications(pubs: Vec<Publication>) -> Self {
        let logical = Message::Publications(pubs);
        Message::CachedPublications(NonEmptyBytes::encode(&logical))
    }

    /// Decode a cached bag back to the logical publications list (for tests / tooling).
    pub fn logical_publications(&self) -> Option<Vec<Publication>> {
        match self {
            Message::Publications(pubs) => Some(pubs.clone()),
            Message::CachedPublications(bytes) => match cbor::decode::<Message>(bytes.as_ref()) {
                Ok(Message::Publications(pubs)) => Some(pubs),
                _ => None,
            },
            Message::GetPublications => None,
        }
    }
}

impl<C> cbor::Encode<C> for ExperimentalValue {
    fn encode<W: cbor::encode::Write>(
        &self,
        e: &mut cbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), cbor::encode::Error<W::Error>> {
        match self {
            ExperimentalValue::Text(s) => {
                e.str(s)?;
            }
            ExperimentalValue::Uint(n) => {
                e.u64(*n)?;
            }
            ExperimentalValue::Bool(b) => {
                e.bool(*b)?;
            }
            ExperimentalValue::Bytes(b) => {
                e.bytes(b)?;
            }
            ExperimentalValue::UintArray(xs) => {
                e.array(xs.len() as u64)?;
                for x in xs {
                    e.u64(*x)?;
                }
            }
        }
        Ok(())
    }
}

impl<'b, C> cbor::Decode<'b, C> for ExperimentalValue {
    fn decode(d: &mut cbor::Decoder<'b>, _ctx: &mut C) -> Result<Self, cbor::decode::Error> {
        match d.datatype()? {
            cbor::data::Type::String | cbor::data::Type::StringIndef => Ok(ExperimentalValue::Text(d.str()?.to_string())),
            cbor::data::Type::Bool => Ok(ExperimentalValue::Bool(d.bool()?)),
            cbor::data::Type::Bytes | cbor::data::Type::BytesIndef => Ok(ExperimentalValue::Bytes(d.bytes()?.to_vec())),
            cbor::data::Type::Array | cbor::data::Type::ArrayIndef => {
                let len = d.array()?;
                let mut xs = Vec::new();
                match len {
                    Some(n) => {
                        for _ in 0..n {
                            xs.push(d.u64()?);
                        }
                    }
                    None => {
                        while d.datatype()? != cbor::data::Type::Break {
                            xs.push(d.u64()?);
                        }
                        d.skip()?;
                    }
                }
                Ok(ExperimentalValue::UintArray(xs))
            }
            cbor::data::Type::U8
            | cbor::data::Type::U16
            | cbor::data::Type::U32
            | cbor::data::Type::U64
            | cbor::data::Type::I8
            | cbor::data::Type::I16
            | cbor::data::Type::I32
            | cbor::data::Type::I64 => Ok(ExperimentalValue::Uint(d.u64()?)),
            other => Err(cbor::decode::Error::message(format!("unsupported experimental field value type: {other:?}"))),
        }
    }
}

impl<C> cbor::Encode<C> for OpenPayload {
    fn encode<W: cbor::encode::Write>(
        &self,
        e: &mut cbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), cbor::encode::Error<W::Error>> {
        let mut n = 0u64;
        if self.node_name.is_some() {
            n += 1;
        }
        if self.node_version_major.is_some() {
            n += 1;
        }
        n += self.experimental.len() as u64;
        e.map(n)?;
        if let Some(name) = &self.node_name {
            e.u64(1)?;
            e.str(name)?;
        }
        if let Some(major) = self.node_version_major {
            e.u64(2)?;
            e.u16(major)?;
        }
        for (k, v) in &self.experimental {
            e.str(k)?;
            v.encode(e, ctx)?;
        }
        Ok(())
    }
}

impl<'b, C> cbor::Decode<'b, C> for OpenPayload {
    fn decode(d: &mut cbor::Decoder<'b>, ctx: &mut C) -> Result<Self, cbor::decode::Error> {
        let len = d.map()?.ok_or_else(|| cbor::decode::Error::message("openPayload requires definite-length map"))?;
        let mut payload = OpenPayload::default();
        let mut seen_name = false;
        let mut seen_major = false;
        for _ in 0..len {
            match d.datatype()? {
                cbor::data::Type::U8
                | cbor::data::Type::U16
                | cbor::data::Type::U32
                | cbor::data::Type::U64
                | cbor::data::Type::I8
                | cbor::data::Type::I16
                | cbor::data::Type::I32
                | cbor::data::Type::I64 => {
                    let key = d.u64()?;
                    match key {
                        1 => {
                            if seen_name {
                                return Err(cbor::decode::Error::message("duplicate openPayload key 1 (node_name)"));
                            }
                            seen_name = true;
                            payload.node_name = Some(d.str()?.to_string());
                        }
                        2 => {
                            if seen_major {
                                return Err(cbor::decode::Error::message(
                                    "duplicate openPayload key 2 (node_version_major)",
                                ));
                            }
                            seen_major = true;
                            payload.node_version_major = Some(d.u16()?);
                        }
                        _ => {
                            // Unknown future integer keys: ignore value.
                            d.skip()?;
                        }
                    }
                }
                cbor::data::Type::String | cbor::data::Type::StringIndef => {
                    let key = d.str()?.to_string();
                    if payload.experimental.contains_key(&key) {
                        return Err(cbor::decode::Error::message(format!("duplicate experimental key {key}")));
                    }
                    let value = ExperimentalValue::decode(d, ctx)?;
                    payload.experimental.insert(key, value);
                }
                other => {
                    return Err(cbor::decode::Error::message(format!("invalid openPayload map key type: {other:?}")));
                }
            }
        }
        Ok(payload)
    }
}

impl<C> cbor::Encode<C> for Publication {
    fn encode<W: cbor::encode::Write>(
        &self,
        e: &mut cbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), cbor::encode::Error<W::Error>> {
        match self {
            Publication::Open { version, snapshot_slot, payload } => {
                e.array(4)?;
                e.u16(0)?;
                e.u64(*version)?;
                e.u64(*snapshot_slot)?;
                payload.encode(e, ctx)?;
            }
            Publication::Encrypted { version, snapshot_slot, observer_public_key, ciphertext } => {
                e.array(5)?;
                e.u16(1)?;
                e.u64(*version)?;
                e.u64(*snapshot_slot)?;
                e.bytes(observer_public_key.as_slice())?;
                e.bytes(ciphertext)?;
            }
        }
        Ok(())
    }
}

impl<'b, C> cbor::Decode<'b, C> for Publication {
    fn decode(d: &mut cbor::Decoder<'b>, ctx: &mut C) -> Result<Self, cbor::decode::Error> {
        let len = d.array()?;
        let tag = d.u16()?;
        match tag {
            0 => {
                cbor::check_tagged_array_length(0, len, 4)?;
                let version = d.u64()?;
                if version != PUBLICATION_VERSION {
                    return Err(cbor::decode::Error::message(format!(
                        "unsupported publicationVersion {version}; expected {PUBLICATION_VERSION}"
                    )));
                }
                let snapshot_slot = d.u64()?;
                let payload = OpenPayload::decode(d, ctx)?;
                Ok(Publication::Open { version, snapshot_slot, payload })
            }
            1 => {
                cbor::check_tagged_array_length(1, len, 5)?;
                let version = d.u64()?;
                if version != PUBLICATION_VERSION {
                    return Err(cbor::decode::Error::message(format!(
                        "unsupported publicationVersion {version}; expected {PUBLICATION_VERSION}"
                    )));
                }
                let snapshot_slot = d.u64()?;
                let key = d.bytes()?;
                if key.len() != OBSERVER_PUBLIC_KEY_LEN {
                    return Err(cbor::decode::Error::message(format!(
                        "observerPublicKey length {}; expected {OBSERVER_PUBLIC_KEY_LEN}",
                        key.len()
                    )));
                }
                let mut observer_public_key = [0u8; OBSERVER_PUBLIC_KEY_LEN];
                observer_public_key.copy_from_slice(key);
                let ciphertext = d.bytes()?.to_vec();
                if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
                    return Err(cbor::decode::Error::message(format!(
                        "ciphertext length {}; expected 1..{MAX_CIPHERTEXT_BYTES}",
                        ciphertext.len()
                    )));
                }
                Ok(Publication::Encrypted { version, snapshot_slot, observer_public_key, ciphertext })
            }
            other => Err(cbor::decode::Error::message(format!("unknown publication tag {other}"))),
        }
    }
}

impl<C> cbor::Encode<C> for Message {
    fn encode<W: cbor::encode::Write>(
        &self,
        e: &mut cbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), cbor::encode::Error<W::Error>> {
        match self {
            Message::GetPublications => {
                e.array(1)?.u16(0)?;
            }
            Message::Publications(pubs) => {
                if pubs.len() > MAX_PUBLICATIONS {
                    return Err(cbor::encode::Error::message("publications exceed MAX_PUBLICATIONS"));
                }
                e.array(2)?.u16(1)?;
                e.array(pubs.len() as u64)?;
                for p in pubs {
                    p.encode(e, ctx)?;
                }
            }
            Message::CachedPublications(bytes) => {
                // Verbatim CBOR item: no structural re-encode on the observe hot path.
                e.writer_mut().write_all(bytes.as_ref()).map_err(cbor::encode::Error::write)?;
            }
        }
        Ok(())
    }
}

impl<'b, C> cbor::Decode<'b, C> for Message {
    fn decode(d: &mut cbor::Decoder<'b>, ctx: &mut C) -> Result<Self, cbor::decode::Error> {
        let len = d.array()?;
        let label = d.u16()?;
        match label {
            0 => {
                cbor::check_tagged_array_length(0, len, 1)?;
                Ok(Message::GetPublications)
            }
            1 => {
                cbor::check_tagged_array_length(1, len, 2)?;
                let n = d
                    .array()?
                    .ok_or_else(|| cbor::decode::Error::message("publications list requires definite length"))?;
                if n > MAX_PUBLICATIONS as u64 {
                    return Err(cbor::decode::Error::message(format!(
                        "publications count {n} exceeds max {MAX_PUBLICATIONS}"
                    )));
                }
                let mut pubs = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    pubs.push(Publication::decode(d, ctx)?);
                }
                Ok(Message::Publications(pubs))
            }
            other => Err(cbor::decode::Error::message(format!("unknown observability message tag {other}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use amaru_kernel::{from_cbor_no_leftovers, prop_cbor_roundtrip, to_cbor};
    use proptest::{collection::btree_map, prelude::*, prop_compose, prop_oneof};

    use super::*;

    prop_cbor_roundtrip!(Message, any_message());

    prop_compose! {
        fn any_open_payload()(
            node_name in proptest::option::of("[a-zA-Z0-9._-]{1,32}"),
            node_version_major in proptest::option::of(any::<u16>()),
            experimental in btree_map("[a-z]+\\.[a-z0-9_]{1,16}", any_experimental_value(), 0..3),
        ) -> OpenPayload {
            OpenPayload { node_name, node_version_major, experimental }
        }
    }

    fn any_experimental_value() -> impl Strategy<Value = ExperimentalValue> {
        prop_oneof![
            any::<u64>().prop_map(ExperimentalValue::Uint),
            any::<bool>().prop_map(ExperimentalValue::Bool),
            "[a-zA-Z0-9]{0,16}".prop_map(ExperimentalValue::Text),
        ]
    }

    prop_compose! {
        fn any_open_publication()(
            snapshot_slot in any::<u64>(),
            payload in any_open_payload(),
        ) -> Publication {
            Publication::Open { version: PUBLICATION_VERSION, snapshot_slot, payload }
        }
    }

    prop_compose! {
        fn any_encrypted_publication()(
            snapshot_slot in any::<u64>(),
            observer_public_key in any::<[u8; OBSERVER_PUBLIC_KEY_LEN]>(),
            ciphertext in prop::collection::vec(any::<u8>(), 1..64),
        ) -> Publication {
            Publication::Encrypted {
                version: PUBLICATION_VERSION,
                snapshot_slot,
                observer_public_key,
                ciphertext,
            }
        }
    }

    fn any_publication() -> impl Strategy<Value = Publication> {
        prop_oneof![any_open_publication(), any_encrypted_publication()]
    }

    fn any_message() -> impl Strategy<Value = Message> {
        prop_oneof![
            Just(Message::GetPublications),
            prop::collection::vec(any_publication(), 0..=MAX_PUBLICATIONS).prop_map(Message::Publications),
        ]
    }

    fn parse_hex(s: &str) -> Vec<u8> {
        let s = s.trim();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
    }

    fn load_vector(name: &str) -> Vec<u8> {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/observability/vectors").join(format!("{name}.hex"));
        parse_hex(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display())))
    }

    #[test]
    fn golden_accept_vectors() {
        let cases = [
            "msg_get_publications",
            "msg_publications_empty",
            "msg_publications_one_open",
            "msg_publications_multi_open",
            "msg_publications_one_open_with_experimental",
            "bnd_unknown_future_integer_key",
            "bnd_max_publications_32",
        ];
        for name in cases {
            let bytes = load_vector(name);
            let msg: Message = from_cbor_no_leftovers(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
            let round = to_cbor(&msg);
            // Roundtrip equality for deterministic encodings (skip experimental key order edge cases if needed)
            let again: Message = from_cbor_no_leftovers(&round).expect(name);
            assert_eq!(msg, again, "{name}");
        }
    }

    #[test]
    fn golden_reject_vectors() {
        let cases = [
            "neg_unknown_message_tag",
            "neg_malformed_get_publications_len",
            "neg_observer_pubkey_wrong_len",
            "neg_wrong_type_node_name",
            "neg_wrong_type_version_major",
            "neg_duplicate_standard_key",
            "neg_publications_over_max_33",
            "neg_invalid_publication_version",
        ];
        for name in cases {
            let bytes = load_vector(name);
            assert!(from_cbor_no_leftovers::<Message>(&bytes).is_err(), "{name} should reject");
        }
    }

    #[test]
    fn one_open_matches_golden_bytes() {
        let msg = Message::Publications(vec![Publication::Open {
            version: PUBLICATION_VERSION,
            snapshot_slot: 123456600,
            payload: OpenPayload::stub_amaru(1),
        }]);
        let encoded = to_cbor(&msg);
        assert_eq!(encoded, load_vector("msg_publications_one_open"));
    }

    #[test]
    fn cached_publications_encode_matches_logical_bytes() {
        let pubs = vec![Publication::Open {
            version: PUBLICATION_VERSION,
            snapshot_slot: 123456600,
            payload: OpenPayload::stub_amaru(1),
        }];
        let logical = Message::Publications(pubs.clone());
        let cached = Message::cache_publications(pubs);
        assert_eq!(to_cbor(&logical), to_cbor(&cached));
        assert_eq!(to_cbor(&cached), load_vector("msg_publications_one_open"));
        assert_eq!(cached.logical_publications().unwrap().len(), 1);
    }
}

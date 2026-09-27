// Copyright 2025 PRAGMA
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

use std::{
    collections::BTreeMap,
    fmt,
    fmt::{Debug, Display},
};

use amaru_kernel::{NetworkMagic, cbor};

use crate::protocol_messages::{
    version_data::{PeerSharing, VersionData},
    version_number::VersionNumber,
};

#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct VersionTable<T> {
    pub values: BTreeMap<VersionNumber, T>,
}

impl VersionTable<VersionData> {
    pub fn empty() -> VersionTable<VersionData> {
        VersionTable { values: BTreeMap::new() }
    }

    pub fn query(network_magic: NetworkMagic) -> VersionTable<VersionData> {
        let data = VersionData::new(network_magic, false, PeerSharing::Disabled, true, false);
        Self::from_v11_through(VersionNumber::CURRENT, data)
    }

    /// Handshake offer from V11 through [`VersionNumber::CURRENT`] (V15).
    pub fn v11_and_above(
        network_magic: NetworkMagic,
        initiator_only_diffusion_mode: bool,
        advertisable: bool,
    ) -> VersionTable<VersionData> {
        Self::v11_through(VersionNumber::CURRENT, network_magic, initiator_only_diffusion_mode, advertisable)
    }

    /// Handshake offer from V11 up to and including `max` (clamped to [`VersionNumber::CURRENT`]).
    pub fn v11_through(
        max: VersionNumber,
        network_magic: NetworkMagic,
        initiator_only_diffusion_mode: bool,
        advertisable: bool,
    ) -> VersionTable<VersionData> {
        let data = VersionData::new(network_magic, initiator_only_diffusion_mode, advertisable.into(), false, false);
        Self::from_v11_through(max, data)
    }

    fn from_v11_through(max: VersionNumber, data: VersionData) -> VersionTable<VersionData> {
        let values = VersionNumber::SUPPORTED
            .into_iter()
            .filter(|version| *version <= max)
            .map(|version| (version, data.clone()))
            .collect();
        VersionTable { values }
    }
}

impl<T: Display + Ord> Display for VersionTable<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut entries = self.values.iter().collect::<Vec<_>>();
        entries.sort();
        for (idx, (version, data)) in entries.into_iter().enumerate() {
            if idx > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}: {}", version.as_u64(), data)?;
        }
        Ok(())
    }
}

impl<T> cbor::Encode<()> for VersionTable<T>
where
    T: fmt::Debug + Clone + cbor::Encode<VersionNumber>,
{
    fn encode<W: cbor::encode::Write>(
        &self,
        e: &mut cbor::Encoder<W>,
        _ctx: &mut (),
    ) -> Result<(), cbor::encode::Error<W::Error>> {
        e.map(self.values.len() as u64)?;

        for key in self.values.keys() {
            e.encode(key)?;
            let mut ctx = *key;
            e.encode_with(&self.values[key], &mut ctx)?;
        }

        Ok(())
    }
}

impl<'b, T> cbor::Decode<'b, ()> for VersionTable<T>
where
    T: fmt::Debug + Clone + cbor::Decode<'b, VersionNumber>,
{
    fn decode(d: &mut cbor::Decoder<'b>, _ctx: &mut ()) -> Result<Self, cbor::decode::Error> {
        let len = d.map()?.ok_or(cbor::decode::Error::message("expected def-length map for versiontable"))?;
        let mut values = BTreeMap::new();

        for _ in 0..len {
            let key = d.decode()?;
            let mut ctx = key;
            let value = d.decode_with(&mut ctx)?;
            values.insert(key, value);
        }
        Ok(VersionTable { values })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use amaru_kernel::prop_cbor_roundtrip;
    use proptest::prelude::Strategy;

    use super::*;
    use crate::protocol_messages::{
        version_data::{
            VersionData,
            tests::{any_version_data, normalize_version_data},
        },
        version_number::tests::any_version_number,
    };

    prop_cbor_roundtrip!(VersionTable<VersionData>, any_version_table());

    /// Tables whose VersionData matches each key's CBOR shape (V16+ may carry `peras_support`).
    pub fn any_version_table() -> impl Strategy<Value = VersionTable<VersionData>> {
        proptest::collection::btree_map(any_version_number(), any_version_data(), 0..3).prop_map(|values| {
            VersionTable {
                values: values
                    .into_iter()
                    .map(|(version, data)| (version, normalize_version_data(version, data)))
                    .collect(),
            }
        })
    }

    #[test]
    fn v11_and_above_offers_current_version() {
        let table = VersionTable::v11_and_above(NetworkMagic::PREPROD, true, true);
        let expected: Vec<_> =
            VersionNumber::SUPPORTED.into_iter().filter(|v| *v <= VersionNumber::CURRENT).collect();
        assert_eq!(table.values.keys().copied().collect::<Vec<_>>(), expected);
        assert_eq!(table.values.keys().next_back().copied(), Some(VersionNumber::CURRENT));
        assert!(!table.values.contains_key(&VersionNumber::V16));
    }

    #[test]
    fn v11_through_v16_includes_experimental_version() {
        let table = VersionTable::v11_through(VersionNumber::V16, NetworkMagic::PREPROD, false, true);
        assert!(table.values.contains_key(&VersionNumber::V16));
        assert_eq!(table.values.keys().next_back().copied(), Some(VersionNumber::V16));
    }

    #[test]
    fn v11_through_v14_excludes_v15() {
        let table = VersionTable::v11_through(VersionNumber::V14, NetworkMagic::PREPROD, false, true);
        assert!(table.values.contains_key(&VersionNumber::V14));
        assert!(!table.values.contains_key(&VersionNumber::V15));
    }
}

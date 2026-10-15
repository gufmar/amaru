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

//! Build observability mini-protocol publications from a compact CLI/env DSL.
//!
//! Enabled when `--observability` / `AMARU_OBSERVABILITY` is set. The DSL only selects
//! **which** built-in fields appear in **which** publications. Identity values (node
//! name, versions, git revision, live samples) always come from the running binary /
//! host — never from the operator string.
//!
//! Grammar (PEERS_MIX-style):
//! - CLI: repeat `--observability SPEC` (or bare `--observability` → `open:all`)
//! - Env: one value; `;` separates publications (`,` separates fields inside a bag)
//! - `open[:fields]` / `o[:fields]` — open publication (`all` or omit = every field)
//! - `enc:<64hex>:<fields>` / `e:<64hex>:<fields>` — encrypted (skipped until sealed-box)
//!
//! Unknown field ids and parse problems are **warnings**: the node keeps running and
//! falls back to remaining known fields (or the default all-fields bag). Config must
//! never abort node startup.
//!
//! A background refresher rebuilds a shared cache on each 600-slot window aligned from
//! slot 0 (`snapshot_slot = floor(tip_slot / 600) * 600`). Observe serves that bag.

use std::{collections::BTreeMap, str::FromStr, sync::Arc, time::Duration};

use amaru_consensus::stages::peer_selection::{PeerConnectionSnapshot, PeerConnectionStats};
use amaru_observability::warn;
use amaru_protocols::observability::{
    ExperimentalValue, MAX_MESSAGE_BYTES, MAX_PUBLICATIONS, Message, OBSERVER_PUBLIC_KEY_LEN, OpenPayload,
    PUBLICATION_VERSION, Publication, PublicationsCache,
};
use anyhow::bail;
use tokio::task::JoinHandle;

use crate::version;

/// Snapshot window length in slots (aligned from slot 0).
pub const SNAPSHOT_SLOT_PERIOD: u64 = 600;

/// Hardcoded standard openPayload node_name (key 1). Not configurable.
const NODE_NAME: &str = "amaru";

/// Hardcoded standard openPayload node_type (key 5). Not configurable yet.
const NODE_TYPE: &str = "full";

/// How often the refresher re-reads the chain tip while waiting for the next window.
const TIP_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Catalogue of built-in fields operators may enable. Values are never taken from the DSL.
///
/// Spec strings accept short aliases or the wire/catalogue id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldId {
    /// Standard openPayload key 1 (`"amaru"`).
    NodeName,
    /// Standard openPayload key 2 (package major).
    NodeVersionMajor,
    /// Standard openPayload key 3 (package minor).
    NodeVersionMinor,
    /// Standard openPayload key 4 (package patch).
    NodeVersionPatch,
    /// Standard openPayload key 5 (`"full"` until roles are differentiated).
    NodeType,
    /// Standard openPayload key 6 (short SHA from `amaru --version`).
    GitRevision,
    /// Experimental `amaru.version` (semver string, e.g. `10.11.0`).
    Version,
    /// Experimental `amaru.cpu_cores`.
    CpuCores,
    /// Experimental `amaru.process_rss_bytes`.
    ProcessRssBytes,
    /// Experimental `amaru.peers_inbound` — accepted inbound connections.
    PeersInbound,
    /// Experimental `amaru.peers_outbound` — established outbound connections.
    PeersOutbound,
    /// Experimental `amaru.peers_outbound_connecting` — outbound dials in flight.
    PeersOutboundConnecting,
    /// Experimental `amaru.peers_using` — connections in Diffusion local use.
    PeersUsing,
    /// Experimental `amaru.peers_target_upstream` — configured upstream target.
    PeersTargetUpstream,
    /// Experimental `amaru.peers_target_downstream` — configured downstream cap.
    PeersTargetDownstream,
}

impl FieldId {
    const ALL: [FieldId; 15] = [
        Self::NodeName,
        Self::NodeVersionMajor,
        Self::NodeVersionMinor,
        Self::NodeVersionPatch,
        Self::NodeType,
        Self::GitRevision,
        Self::Version,
        Self::CpuCores,
        Self::ProcessRssBytes,
        Self::PeersInbound,
        Self::PeersOutbound,
        Self::PeersOutboundConnecting,
        Self::PeersUsing,
        Self::PeersTargetUpstream,
        Self::PeersTargetDownstream,
    ];

    /// Canonical catalogue string (same as wire key for experimental fields).
    fn as_str(self) -> &'static str {
        match self {
            Self::NodeName => "node_name",
            Self::NodeVersionMajor => "node_version_major",
            Self::NodeVersionMinor => "node_version_minor",
            Self::NodeVersionPatch => "node_version_patch",
            Self::NodeType => "node_type",
            Self::GitRevision => "git_revision",
            Self::Version => "amaru.version",
            Self::CpuCores => "amaru.cpu_cores",
            Self::ProcessRssBytes => "amaru.process_rss_bytes",
            Self::PeersInbound => "amaru.peers_inbound",
            Self::PeersOutbound => "amaru.peers_outbound",
            Self::PeersOutboundConnecting => "amaru.peers_outbound_connecting",
            Self::PeersUsing => "amaru.peers_using",
            Self::PeersTargetUpstream => "amaru.peers_target_upstream",
            Self::PeersTargetDownstream => "amaru.peers_target_downstream",
        }
    }
}

impl FromStr for FieldId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "name" | "node_name" => Self::NodeName,
            "maj" | "node_version_major" => Self::NodeVersionMajor,
            "min" | "node_version_minor" => Self::NodeVersionMinor,
            "pat" | "node_version_patch" => Self::NodeVersionPatch,
            "type" | "node_type" => Self::NodeType,
            "git" | "git_revision" => Self::GitRevision,
            "ver" | "amaru.version" => Self::Version,
            "cpu" | "amaru.cpu_cores" => Self::CpuCores,
            "rss" | "amaru.process_rss_bytes" => Self::ProcessRssBytes,
            "pin" | "amaru.peers_inbound" => Self::PeersInbound,
            "pout" | "amaru.peers_outbound" => Self::PeersOutbound,
            "pconn" | "amaru.peers_outbound_connecting" => Self::PeersOutboundConnecting,
            "puse" | "amaru.peers_using" => Self::PeersUsing,
            "ptup" | "amaru.peers_target_upstream" => Self::PeersTargetUpstream,
            "ptdown" | "amaru.peers_target_downstream" => Self::PeersTargetDownstream,
            other => bail!(
                "unknown field '{other}'; known: name,maj,min,pat,type,git,ver,cpu,rss,pin,pout,pconn,puse,ptup,ptdown,all (or full catalogue ids)"
            ),
        })
    }
}

#[derive(Debug, Clone)]
struct ResolvedPublication {
    fields: Vec<FieldId>,
}

#[derive(Debug, Clone)]
struct ResolvedConfig {
    publications: Vec<ResolvedPublication>,
}

#[derive(Debug, Clone)]
struct NodeIdentity {
    version: &'static str,
    major: u16,
    minor: u16,
    patch: u16,
    /// Short SHA shown in `amaru --version` parentheses (`rev-parse --short`).
    git_revision: &'static str,
}

impl NodeIdentity {
    fn from_build() -> Self {
        let version = version::package_version();
        let (major, minor, patch) = parse_semver_parts(version);
        Self { version, major, minor, patch, git_revision: version::git_commit_hash_short().unwrap_or("unknown") }
    }
}

fn parse_semver_parts(version: &str) -> (u16, u16, u16) {
    let mut parts = version.split(['.', '-']);
    let major = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor, patch)
}

/// Align a tip slot down to the start of its 600-slot snapshot window (from slot 0).
pub fn aligned_snapshot_slot(tip_slot: u64) -> u64 {
    tip_slot.div_euclid(SNAPSHOT_SLOT_PERIOD).saturating_mul(SNAPSHOT_SLOT_PERIOD)
}

/// Flatten clap Append values and env `;`-lists into individual publication specs.
pub fn flatten_specs(parts: &[String]) -> Vec<String> {
    parts.iter().flat_map(|part| part.split(';')).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
}

/// Install the shared cache from operator specs and return a handle for the refresher.
///
/// Never fails the node: invalid specs become warnings and fall back to remaining known
/// fields or the default all-fields publication.
pub fn install_for_node(specs: &[String]) -> PublicationsCacheHandle {
    let flattened = flatten_specs(specs);
    let resolved = resolve_specs(&flattened);
    let identity = NodeIdentity::from_build();
    let peer_stats = PeerConnectionStats::new();
    // Before the tip source is available, publish snapshot_slot 0 with current live samples.
    let cache = PublicationsCache::new(build_message(&resolved, &identity, 0, &peer_stats.snapshot()));
    cache.install_as_provider();
    PublicationsCacheHandle { cache, config: resolved, identity, peer_stats }
}

/// Process-local handle that rebuilds the pre-built publications bag from chain tip.
#[derive(Clone)]
pub struct PublicationsCacheHandle {
    cache: PublicationsCache,
    config: ResolvedConfig,
    identity: NodeIdentity,
    peer_stats: Arc<PeerConnectionStats>,
}

impl PublicationsCacheHandle {
    /// Replace the peer-stats gauge with the node-owned one (shared with peer_selection).
    pub fn set_peer_stats(&mut self, peer_stats: Arc<PeerConnectionStats>) {
        self.peer_stats = peer_stats;
    }

    /// Rebuild the cache for `tip_slot` when the aligned snapshot window changed (or force).
    pub fn refresh_for_tip_slot(&self, tip_slot: u64) -> u64 {
        let snapshot = aligned_snapshot_slot(tip_slot);
        if cached_snapshot_slot(&self.cache.get()) != Some(snapshot) {
            self.cache.replace(build_message(&self.config, &self.identity, snapshot, &self.peer_stats.snapshot()));
        }
        snapshot
    }

    /// Spawn a background task that refreshes the cache on each new 600-slot window.
    pub fn spawn_refresher(&self, tip_slot: Arc<dyn Fn() -> u64 + Send + Sync>) -> JoinHandle<()> {
        let handle = self.clone();
        tokio::spawn(async move {
            let mut last_snapshot = None;
            loop {
                let tip = tip_slot();
                let snapshot = aligned_snapshot_slot(tip);
                if last_snapshot != Some(snapshot) {
                    handle.cache.replace(build_message(
                        &handle.config,
                        &handle.identity,
                        snapshot,
                        &handle.peer_stats.snapshot(),
                    ));
                    last_snapshot = Some(snapshot);
                }
                tokio::time::sleep(TIP_POLL_INTERVAL).await;
            }
        })
    }
}

fn cached_snapshot_slot(message: &Message) -> Option<u64> {
    match message {
        Message::Publications(pubs) => pubs.first().map(|p| match p {
            Publication::Open { snapshot_slot, .. } | Publication::Encrypted { snapshot_slot, .. } => *snapshot_slot,
        }),
        Message::CachedPublications(_) => message.logical_publications().and_then(|pubs| {
            pubs.first().map(|p| match p {
                Publication::Open { snapshot_slot, .. } | Publication::Encrypted { snapshot_slot, .. } => {
                    *snapshot_slot
                }
            })
        }),
        Message::GetPublications => None,
    }
}

fn resolve_specs(specs: &[String]) -> ResolvedConfig {
    let mut sections = specs;
    let truncated: Vec<String>;
    if sections.len() > MAX_PUBLICATIONS {
        warn!(
            setup::observability::PUBLICATIONS_CONFIG,
            reason = "too_many_publications",
            detail = format!("spec has {} publications; using the first {MAX_PUBLICATIONS}", sections.len()),
        );
        truncated = sections[..MAX_PUBLICATIONS].to_vec();
        sections = &truncated;
    }

    let mut publications = Vec::with_capacity(sections.len());
    for (index, raw) in sections.iter().enumerate() {
        let label = format!("publication[{index}]");
        match parse_publication_spec(raw) {
            Ok(ParsedPublication::Open { fields }) => {
                if let Some(resolved) = resolve_fields(&label, &fields) {
                    publications.push(resolved);
                }
            }
            Ok(ParsedPublication::Encrypted { .. }) => {
                warn!(
                    setup::observability::PUBLICATIONS_CONFIG,
                    reason = "encrypted_not_implemented",
                    detail = format!("{label}: enc:… set; skipping this bag until sealed-box lands"),
                );
            }
            Err(err) => {
                warn!(
                    setup::observability::PUBLICATIONS_CONFIG,
                    reason = "parse_failed",
                    detail = format!("{label}: {err:#}"),
                );
            }
        }
    }

    if publications.is_empty() {
        warn!(
            setup::observability::PUBLICATIONS_CONFIG,
            reason = "no_valid_publications",
            detail = "no usable publication specs; falling back to default all-fields bag".to_string(),
        );
        publications.push(ResolvedPublication { fields: FieldId::ALL.to_vec() });
    }

    ResolvedConfig { publications }
}

enum ParsedPublication {
    Open { fields: Vec<String> },
    Encrypted { _observer_public_key: [u8; OBSERVER_PUBLIC_KEY_LEN], _fields: Vec<String> },
}

fn parse_publication_spec(raw: &str) -> anyhow::Result<ParsedPublication> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("empty publication spec");
    }

    let (kind, rest) = match raw.split_once(':') {
        Some((kind, rest)) => (kind.trim(), Some(rest.trim())),
        None => (raw, None),
    };

    match kind {
        "open" | "o" => {
            let fields = parse_field_list(rest.unwrap_or("all"))?;
            Ok(ParsedPublication::Open { fields })
        }
        "enc" | "e" => {
            let rest = rest.ok_or_else(|| anyhow::anyhow!("enc: requires <64hex>:<fields>"))?;
            let (key_hex, fields_raw) =
                rest.split_once(':').ok_or_else(|| anyhow::anyhow!("enc: requires <64hex>:<fields>"))?;
            let key = parse_observer_public_key(key_hex.trim())?;
            let fields = parse_field_list(fields_raw.trim())?;
            Ok(ParsedPublication::Encrypted { _observer_public_key: key, _fields: fields })
        }
        other => bail!("unknown publication kind '{other}' (expected open|o|enc|e)"),
    }
}

fn parse_field_list(raw: &str) -> anyhow::Result<Vec<String>> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("field list is empty");
    }
    if raw.eq_ignore_ascii_case("all") {
        return Ok(FieldId::ALL.iter().map(|f| f.as_str().to_string()).collect());
    }
    let fields: Vec<String> = raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect();
    if fields.is_empty() {
        bail!("field list is empty");
    }
    Ok(fields)
}

fn parse_observer_public_key(hex_key: &str) -> anyhow::Result<[u8; OBSERVER_PUBLIC_KEY_LEN]> {
    let bytes = hex::decode(hex_key).map_err(|e| anyhow::anyhow!("invalid observer_public_key hex: {e}"))?;
    if bytes.len() != OBSERVER_PUBLIC_KEY_LEN {
        bail!(
            "observer_public_key must be {OBSERVER_PUBLIC_KEY_LEN} bytes ({} hex chars), got {} bytes",
            OBSERVER_PUBLIC_KEY_LEN * 2,
            bytes.len()
        );
    }
    let mut out = [0u8; OBSERVER_PUBLIC_KEY_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn resolve_fields(label: &str, items: &[String]) -> Option<ResolvedPublication> {
    let mut fields = Vec::with_capacity(items.len());
    let mut seen = BTreeMap::new();
    for item in items {
        let Ok(field) = FieldId::from_str(item) else {
            warn!(
                setup::observability::PUBLICATIONS_CONFIG,
                reason = "unknown_field",
                detail = format!("{label}: ignoring unknown field '{item}'"),
            );
            continue;
        };
        if seen.insert(field.as_str(), ()).is_some() {
            warn!(
                setup::observability::PUBLICATIONS_CONFIG,
                reason = "duplicate_field",
                detail = format!("{label}: duplicate field '{}'; keeping first", field.as_str()),
            );
            continue;
        }
        fields.push(field);
    }

    if fields.is_empty() {
        warn!(
            setup::observability::PUBLICATIONS_CONFIG,
            reason = "empty_items",
            detail = format!("{label}: no known fields left after filtering; skipping"),
        );
        return None;
    }

    Some(ResolvedPublication { fields })
}

fn build_message(
    config: &ResolvedConfig,
    identity: &NodeIdentity,
    snapshot_slot: u64,
    peers: &PeerConnectionSnapshot,
) -> Message {
    let live = LiveSamples::capture(*peers);
    let pubs: Vec<Publication> = config
        .publications
        .iter()
        .map(|section| Publication::Open {
            version: PUBLICATION_VERSION,
            snapshot_slot,
            payload: build_payload(&section.fields, identity, &live),
        })
        .collect();
    // Pre-encode once per snapshot window; observe serves these CBOR bytes verbatim.
    let msg = Message::cache_publications(pubs);
    if let Message::CachedPublications(bytes) = &msg
        && bytes.as_ref().len() > MAX_MESSAGE_BYTES
    {
        warn!(
            setup::observability::PUBLICATIONS_CONFIG,
            reason = "oversized_message",
            detail = format!(
                "encoded MsgPublications is {} bytes (limit {MAX_MESSAGE_BYTES}); falling back to node_name-only bag",
                bytes.as_ref().len()
            ),
        );
        return Message::cache_publications(vec![Publication::Open {
            version: PUBLICATION_VERSION,
            snapshot_slot,
            payload: OpenPayload { node_name: Some(NODE_NAME.to_string()), ..OpenPayload::default() },
        }]);
    }
    msg
}

struct LiveSamples {
    cpu_cores: u64,
    process_rss_bytes: Option<u64>,
    peers: PeerConnectionSnapshot,
}

impl LiveSamples {
    fn capture(peers: PeerConnectionSnapshot) -> Self {
        Self {
            cpu_cores: std::thread::available_parallelism().map(|n| n.get() as u64).unwrap_or(0),
            process_rss_bytes: sample_process_rss_bytes(),
            peers,
        }
    }
}

fn build_payload(fields: &[FieldId], identity: &NodeIdentity, live: &LiveSamples) -> OpenPayload {
    let mut payload = OpenPayload::default();

    for field in fields {
        match field {
            FieldId::NodeName => {
                payload.node_name = Some(NODE_NAME.to_string());
            }
            FieldId::NodeVersionMajor => {
                payload.node_version_major = Some(identity.major);
            }
            FieldId::NodeVersionMinor => {
                payload.node_version_minor = Some(identity.minor);
            }
            FieldId::NodeVersionPatch => {
                payload.node_version_patch = Some(identity.patch);
            }
            FieldId::NodeType => {
                payload.node_type = Some(NODE_TYPE.to_string());
            }
            FieldId::GitRevision => {
                payload.git_revision = Some(identity.git_revision.to_string());
            }
            FieldId::Version => {
                payload
                    .experimental
                    .insert("amaru.version".into(), ExperimentalValue::Text(identity.version.to_string()));
            }
            FieldId::CpuCores => {
                payload.experimental.insert("amaru.cpu_cores".into(), ExperimentalValue::Uint(live.cpu_cores));
            }
            FieldId::ProcessRssBytes => {
                if let Some(rss) = live.process_rss_bytes {
                    payload.experimental.insert("amaru.process_rss_bytes".into(), ExperimentalValue::Uint(rss));
                }
            }
            FieldId::PeersInbound => {
                payload.experimental.insert("amaru.peers_inbound".into(), ExperimentalValue::Uint(live.peers.inbound));
            }
            FieldId::PeersOutbound => {
                payload
                    .experimental
                    .insert("amaru.peers_outbound".into(), ExperimentalValue::Uint(live.peers.outbound));
            }
            FieldId::PeersOutboundConnecting => {
                payload.experimental.insert(
                    "amaru.peers_outbound_connecting".into(),
                    ExperimentalValue::Uint(live.peers.outbound_connecting),
                );
            }
            FieldId::PeersUsing => {
                payload.experimental.insert("amaru.peers_using".into(), ExperimentalValue::Uint(live.peers.using));
            }
            FieldId::PeersTargetUpstream => {
                payload
                    .experimental
                    .insert("amaru.peers_target_upstream".into(), ExperimentalValue::Uint(live.peers.target_upstream));
            }
            FieldId::PeersTargetDownstream => {
                payload.experimental.insert(
                    "amaru.peers_target_downstream".into(),
                    ExperimentalValue::Uint(live.peers.target_downstream),
                );
            }
        }
    }

    payload
}

fn sample_process_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        read_proc_self_vm_rss()
    }
    #[cfg(not(target_os = "linux"))]
    {
        sample_rss_via_sysinfo()
    }
}

#[cfg(target_os = "linux")]
fn read_proc_self_vm_rss() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("VmRSS:") else {
            continue;
        };
        let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
        return Some(kb.saturating_mul(1024));
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn sample_rss_via_sysinfo() -> Option<u64> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

    let pid = sysinfo::get_current_pid().ok()?;
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[Pid::from_u32(pid.as_u32())]),
        true,
        ProcessRefreshKind::nothing().with_memory(),
    );
    sys.process(pid).map(|p| p.memory())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> NodeIdentity {
        NodeIdentity::from_build()
    }

    #[test]
    fn default_open_all_builds_one_open_publication_with_all_fields() {
        let resolved = resolve_specs(&["open:all".into()]);
        let msg = build_message(&resolved, &identity(), 1200, &PeerConnectionSnapshot::default());
        assert!(matches!(msg, Message::CachedPublications(_)));
        let pubs = msg.logical_publications().expect("cached logical pubs");
        assert_eq!(pubs.len(), 1);
        let Publication::Open { snapshot_slot, payload, .. } = &pubs[0] else {
            panic!("expected open publication");
        };
        assert_eq!(*snapshot_slot, 1200);
        assert_eq!(payload.node_name.as_deref(), Some("amaru"));
        assert_eq!(payload.node_version_major, Some(identity().major));
        assert_eq!(payload.node_version_minor, Some(identity().minor));
        assert_eq!(payload.node_version_patch, Some(identity().patch));
        assert_eq!(payload.node_type.as_deref(), Some("full"));
        assert_eq!(payload.git_revision.as_deref(), Some(identity().git_revision));
        assert!(payload.experimental.contains_key("amaru.version"));
        assert!(payload.experimental.contains_key("amaru.cpu_cores"));
    }

    #[test]
    fn bare_open_means_all_fields() {
        let resolved = resolve_specs(&["open".into()]);
        assert_eq!(resolved.publications[0].fields.len(), FieldId::ALL.len());
    }

    #[test]
    fn flatten_specs_splits_semicolons() {
        assert_eq!(
            flatten_specs(&["open:name;open:cpu".into(), "open:ver".into()]),
            vec!["open:name".to_string(), "open:cpu".to_string(), "open:ver".to_string()]
        );
    }

    #[test]
    fn aligned_snapshot_slot_floors_to_600() {
        assert_eq!(aligned_snapshot_slot(0), 0);
        assert_eq!(aligned_snapshot_slot(599), 0);
        assert_eq!(aligned_snapshot_slot(600), 600);
        assert_eq!(aligned_snapshot_slot(199_018_204), 199_018_200);
    }

    #[test]
    fn multiple_publications_can_share_fields() {
        let resolved = resolve_specs(&["open:name,maj,ver".into(), "o:name,cpu,rss".into()]);
        let msg = build_message(&resolved, &identity(), 600, &PeerConnectionSnapshot::default());
        let pubs = msg.logical_publications().expect("cached logical pubs");
        assert_eq!(pubs.len(), 2);

        let Publication::Open { snapshot_slot, payload: first, .. } = &pubs[0] else {
            panic!("expected open");
        };
        assert_eq!(*snapshot_slot, 600);
        assert_eq!(first.node_name.as_deref(), Some("amaru"));
        assert!(first.experimental.contains_key("amaru.version"));
        assert!(!first.experimental.contains_key("amaru.cpu_cores"));

        let Publication::Open { payload: second, .. } = &pubs[1] else {
            panic!("expected open");
        };
        assert_eq!(second.node_name.as_deref(), Some("amaru"));
        assert!(second.node_version_major.is_none());
        assert!(second.experimental.contains_key("amaru.cpu_cores"));
        assert!(!second.experimental.contains_key("amaru.version"));
    }

    #[test]
    fn ignores_unknown_field_id_and_keeps_known_ones() {
        let resolved = resolve_specs(&["open:name,fake_slot,ver".into()]);
        assert_eq!(resolved.publications.len(), 1);
        assert_eq!(resolved.publications[0].fields, vec![FieldId::NodeName, FieldId::Version]);
    }

    #[test]
    fn skips_encrypted_publication_until_implemented() {
        let key = "00".repeat(32);
        let resolved = resolve_specs(&[format!("enc:{key}:name,cpu"), "open:name".into()]);
        assert_eq!(resolved.publications.len(), 1);
        assert_eq!(resolved.publications[0].fields, vec![FieldId::NodeName]);
    }

    #[test]
    fn ignores_duplicate_field_keeping_first() {
        let resolved = resolve_specs(&["open:name,name,ver".into()]);
        assert_eq!(resolved.publications[0].fields, vec![FieldId::NodeName, FieldId::Version]);
    }

    #[test]
    fn falls_back_to_default_when_all_items_unknown() {
        let resolved = resolve_specs(&["open:not_a_real_field".into()]);
        assert_eq!(resolved.publications.len(), 1);
        assert_eq!(resolved.publications[0].fields.len(), FieldId::ALL.len());
    }

    #[test]
    fn falls_back_on_parse_failure() {
        let resolved = resolve_specs(&["nope:name".into()]);
        assert_eq!(resolved.publications[0].fields.len(), FieldId::ALL.len());
    }

    #[test]
    fn node_name_is_always_amaru_even_if_only_that_field_is_selected() {
        let resolved = resolve_specs(&["open:name".into()]);
        let msg = build_message(&resolved, &identity(), 0, &PeerConnectionSnapshot::default());
        let pubs = msg.logical_publications().expect("cached logical pubs");
        let Publication::Open { payload, .. } = &pubs[0] else {
            panic!("expected open");
        };
        assert_eq!(payload.node_name.as_deref(), Some("amaru"));
        assert!(payload.node_version_major.is_none());
        assert!(payload.experimental.is_empty());
    }

    #[test]
    fn git_revision_matches_build_short_sha() {
        let id = identity();
        let resolved = resolve_specs(&["open:git".into()]);
        let msg = build_message(&resolved, &id, 0, &PeerConnectionSnapshot::default());
        let pubs = msg.logical_publications().unwrap();
        let Publication::Open { payload, .. } = &pubs[0] else {
            panic!("expected open");
        };
        assert_eq!(payload.git_revision.as_deref(), Some(id.git_revision));
        assert!(payload.experimental.is_empty());
    }

    #[test]
    fn accepts_full_catalogue_ids() {
        let resolved = resolve_specs(&["open:node_name,amaru.cpu_cores".into()]);
        assert_eq!(resolved.publications[0].fields, vec![FieldId::NodeName, FieldId::CpuCores]);
    }
}

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

//! Build observability mini-protocol publications from an optional TOML config.
//!
//! Used when `AMARU_OBSERVABILITY` is set. The config only selects **which** built-in
//! fields appear in **which** publications. Identity values (node name, versions, git
//! revision, live samples) always come from the running binary / host — never from the
//! config file.
//!
//! Unknown field ids, unsupported options, and load/parse problems are **warnings**:
//! the node keeps running and falls back to the remaining known fields (or the default
//! all-fields bag). Config must never abort node startup.
//!
//! A background refresher rebuilds a shared cache on each 600-slot window aligned from
//! slot 0 (`snapshot_slot = floor(tip_slot / 600) * 600`). Observe serves that bag.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use amaru_consensus::stages::peer_selection::{PeerConnectionSnapshot, PeerConnectionStats};
use amaru_observability::warn;
use amaru_protocols::observability::{
    ExperimentalValue, MAX_PUBLICATIONS, Message, OpenPayload, PUBLICATION_VERSION, Publication, PublicationsCache,
};
use anyhow::{Context, bail};
use serde::Deserialize;
use tokio::task::JoinHandle;

use crate::version;

/// Default path env for the publications config.
pub const OBSERVABILITY_CONFIG_ENV: &str = "AMARU_OBSERVABILITY_CONFIG";

/// Snapshot window length in slots (aligned from slot 0).
pub const SNAPSHOT_SLOT_PERIOD: u64 = 600;

/// Hardcoded standard openPayload node_name (key 1). Not configurable.
const NODE_NAME: &str = "amaru";

/// How often the refresher re-reads the chain tip while waiting for the next window.
const TIP_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Catalogue of built-in fields operators may enable. Values are never taken from config.
///
/// Config `items` strings match the wire identity: CDDL logical ids for standard keys,
/// and the experimental tstr key (including `amaru.` namespace) for everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldId {
    /// Standard openPayload key 1 (`"amaru"`).
    NodeName,
    /// Standard openPayload key 2 (package major).
    NodeVersionMajor,
    /// Experimental `amaru.version` (semver string, e.g. `10.11.0`).
    Version,
    /// Experimental `amaru.version_minor` (uint).
    VersionMinor,
    /// Experimental `amaru.version_patch` (uint).
    VersionPatch,
    /// Experimental `amaru.git_revision` — short SHA from `amaru --version` parentheses.
    GitRevision,
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
    const ALL: [FieldId; 14] = [
        Self::NodeName,
        Self::NodeVersionMajor,
        Self::Version,
        Self::VersionMinor,
        Self::VersionPatch,
        Self::GitRevision,
        Self::CpuCores,
        Self::ProcessRssBytes,
        Self::PeersInbound,
        Self::PeersOutbound,
        Self::PeersOutboundConnecting,
        Self::PeersUsing,
        Self::PeersTargetUpstream,
        Self::PeersTargetDownstream,
    ];

    /// Config / catalogue string (same as wire key for experimental fields).
    fn as_str(self) -> &'static str {
        match self {
            Self::NodeName => "node_name",
            Self::NodeVersionMajor => "node_version_major",
            Self::Version => "amaru.version",
            Self::VersionMinor => "amaru.version_minor",
            Self::VersionPatch => "amaru.version_patch",
            Self::GitRevision => "amaru.git_revision",
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
            "node_name" => Self::NodeName,
            "node_version_major" => Self::NodeVersionMajor,
            "amaru.version" => Self::Version,
            "amaru.version_minor" => Self::VersionMinor,
            "amaru.version_patch" => Self::VersionPatch,
            "amaru.git_revision" => Self::GitRevision,
            "amaru.cpu_cores" => Self::CpuCores,
            "amaru.process_rss_bytes" => Self::ProcessRssBytes,
            "amaru.peers_inbound" => Self::PeersInbound,
            "amaru.peers_outbound" => Self::PeersOutbound,
            "amaru.peers_outbound_connecting" => Self::PeersOutboundConnecting,
            "amaru.peers_using" => Self::PeersUsing,
            "amaru.peers_target_upstream" => Self::PeersTargetUpstream,
            "amaru.peers_target_downstream" => Self::PeersTargetDownstream,
            other => bail!(
                "unknown field '{other}'; known fields: {}",
                FieldId::ALL.iter().map(|f| f.as_str()).collect::<Vec<_>>().join(", ")
            ),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublicationsFile {
    /// One or more publications. Same field ids may appear in several entries.
    #[serde(default = "default_publications", rename = "publication")]
    pub publications: Vec<PublicationSection>,
}

fn default_publications() -> Vec<PublicationSection> {
    vec![PublicationSection::default_open_all()]
}

impl Default for PublicationsFile {
    fn default() -> Self {
        Self { publications: default_publications() }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublicationSection {
    /// Built-in field ids to include in this publication's openPayload.
    #[serde(default)]
    pub items: Vec<String>,

    /// Optional X25519 observer public key (64 hex chars). Reserved for encrypted
    /// publications; not implemented yet — the section is skipped with a warning if set.
    #[serde(default)]
    pub observer_public_key: Option<String>,
}

impl PublicationSection {
    fn default_open_all() -> Self {
        Self {
            items: FieldId::ALL.iter().map(|f| f.as_str().to_string()).collect(),
            observer_public_key: None,
        }
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
        Self {
            version,
            major,
            minor,
            patch,
            git_revision: version::git_commit_hash_short().unwrap_or("unknown"),
        }
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

/// Load config (optional path / env), install the shared cache, and return a handle for the refresher.
///
/// Never fails the node: unreadable/invalid files and unknown field ids become warnings and
/// fall back to remaining known fields or the default all-fields publication.
pub fn install_for_node(config_path: Option<&Path>) -> PublicationsCacheHandle {
    let path = resolve_config_path(config_path);
    let file = match path.as_ref() {
        Some(p) => match load_file(p) {
            Ok(file) => file,
            Err(err) => {
                warn!(
                    setup::observability::PUBLICATIONS_CONFIG,
                    reason = "load_failed",
                    detail = format!("{}: {err:#}", p.display()),
                );
                PublicationsFile::default()
            }
        },
        None => PublicationsFile::default(),
    };
    let resolved = resolve_config(&file);
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
            self.cache.replace(build_message(
                &self.config,
                &self.identity,
                snapshot,
                &self.peer_stats.snapshot(),
            ));
        }
        snapshot
    }

    /// Spawn a background task that refreshes the cache on each new 600-slot window.
    pub fn spawn_refresher(
        &self,
        tip_slot: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> JoinHandle<()> {
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
                Publication::Open { snapshot_slot, .. } | Publication::Encrypted { snapshot_slot, .. } => *snapshot_slot,
            })
        }),
        Message::GetPublications => None,
    }
}

fn resolve_config_path(cli: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = cli {
        return Some(p.to_path_buf());
    }
    std::env::var_os(OBSERVABILITY_CONFIG_ENV).map(PathBuf::from)
}

fn load_file(path: &Path) -> anyhow::Result<PublicationsFile> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("parse TOML {}", path.display()))
}

fn resolve_config(file: &PublicationsFile) -> ResolvedConfig {
    let mut sections = file.publications.as_slice();
    if sections.len() > MAX_PUBLICATIONS {
        warn!(
            setup::observability::PUBLICATIONS_CONFIG,
            reason = "too_many_publications",
            detail = format!(
                "config has {} publications; using the first {MAX_PUBLICATIONS}",
                sections.len()
            ),
        );
        sections = &sections[..MAX_PUBLICATIONS];
    }

    let mut publications = Vec::with_capacity(sections.len());
    for (index, section) in sections.iter().enumerate() {
        let label = format!("publication[{index}]");

        if section.observer_public_key.is_some() {
            warn!(
                setup::observability::PUBLICATIONS_CONFIG,
                reason = "encrypted_not_implemented",
                detail = format!("{label}: observer_public_key set; skipping this bag until sealed-box lands"),
            );
            continue;
        }

        if section.items.is_empty() {
            warn!(
                setup::observability::PUBLICATIONS_CONFIG,
                reason = "empty_items",
                detail = format!("{label}: items is empty; skipping"),
            );
            continue;
        }

        let mut fields = Vec::with_capacity(section.items.len());
        let mut seen = BTreeMap::new();
        for item in &section.items {
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
            continue;
        }

        publications.push(ResolvedPublication { fields });
    }

    if publications.is_empty() {
        warn!(
            setup::observability::PUBLICATIONS_CONFIG,
            reason = "no_valid_publications",
            detail = "no usable [[publication]] sections; falling back to default all-fields bag".to_string(),
        );
        let fallback = PublicationSection::default_open_all();
        let fields: Vec<_> = fallback.items.iter().filter_map(|s| FieldId::from_str(s).ok()).collect();
        publications.push(ResolvedPublication { fields });
    }

    ResolvedConfig { publications }
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
        .map(|section| {
            // Encrypted bags are skipped at resolve time until sealed-box lands.
            Publication::Open {
                version: PUBLICATION_VERSION,
                snapshot_slot,
                payload: build_payload(&section.fields, identity, &live),
            }
        })
        .collect();
    // Pre-encode once per snapshot window; observe serves these CBOR bytes verbatim.
    Message::cache_publications(pubs)
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
    let mut payload = OpenPayload { node_name: None, node_version_major: None, experimental: BTreeMap::new() };

    for field in fields {
        match field {
            FieldId::NodeName => {
                payload.node_name = Some(NODE_NAME.to_string());
            }
            FieldId::NodeVersionMajor => {
                payload.node_version_major = Some(identity.major);
            }
            FieldId::Version => {
                payload
                    .experimental
                    .insert("amaru.version".into(), ExperimentalValue::Text(identity.version.to_string()));
            }
            FieldId::VersionMinor => {
                payload
                    .experimental
                    .insert("amaru.version_minor".into(), ExperimentalValue::Uint(u64::from(identity.minor)));
            }
            FieldId::VersionPatch => {
                payload
                    .experimental
                    .insert("amaru.version_patch".into(), ExperimentalValue::Uint(u64::from(identity.patch)));
            }
            FieldId::GitRevision => {
                payload.experimental.insert(
                    "amaru.git_revision".into(),
                    ExperimentalValue::Text(identity.git_revision.to_string()),
                );
            }
            FieldId::CpuCores => {
                payload
                    .experimental
                    .insert("amaru.cpu_cores".into(), ExperimentalValue::Uint(live.cpu_cores));
            }
            FieldId::ProcessRssBytes => {
                if let Some(rss) = live.process_rss_bytes {
                    payload
                        .experimental
                        .insert("amaru.process_rss_bytes".into(), ExperimentalValue::Uint(rss));
                }
            }
            FieldId::PeersInbound => {
                payload
                    .experimental
                    .insert("amaru.peers_inbound".into(), ExperimentalValue::Uint(live.peers.inbound));
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
                payload
                    .experimental
                    .insert("amaru.peers_using".into(), ExperimentalValue::Uint(live.peers.using));
            }
            FieldId::PeersTargetUpstream => {
                payload.experimental.insert(
                    "amaru.peers_target_upstream".into(),
                    ExperimentalValue::Uint(live.peers.target_upstream),
                );
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
        if let Some(rss) = read_proc_self_vm_rss() {
            return Some(rss);
        }
    }
    sample_rss_via_sysinfo()
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
    fn default_file_builds_one_open_publication_with_all_fields() {
        let resolved = resolve_config(&PublicationsFile::default());
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
        assert!(payload.experimental.contains_key("amaru.version"));
        assert!(payload.experimental.contains_key("amaru.git_revision"));
        assert!(payload.experimental.contains_key("amaru.cpu_cores"));
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
        let toml = r#"
            [[publication]]
            items = ["node_name", "node_version_major", "amaru.version"]

            [[publication]]
            items = ["node_name", "amaru.cpu_cores", "amaru.process_rss_bytes"]
        "#;
        let file: PublicationsFile = toml::from_str(toml).unwrap();
        let resolved = resolve_config(&file);
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
        let toml = r#"
            [[publication]]
            items = ["node_name", "fake_slot", "amaru.version"]
        "#;
        let file: PublicationsFile = toml::from_str(toml).unwrap();
        let resolved = resolve_config(&file);
        assert_eq!(resolved.publications.len(), 1);
        assert_eq!(
            resolved.publications[0].fields,
            vec![FieldId::NodeName, FieldId::Version]
        );
    }

    #[test]
    fn skips_encrypted_publication_until_implemented() {
        let toml = r#"
            [[publication]]
            observer_public_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            items = ["node_name", "amaru.cpu_cores"]

            [[publication]]
            items = ["node_name"]
        "#;
        let file: PublicationsFile = toml::from_str(toml).unwrap();
        let resolved = resolve_config(&file);
        assert_eq!(resolved.publications.len(), 1);
        assert_eq!(resolved.publications[0].fields, vec![FieldId::NodeName]);
    }

    #[test]
    fn ignores_duplicate_field_keeping_first() {
        let toml = r#"
            [[publication]]
            items = ["node_name", "node_name", "amaru.version"]
        "#;
        let file: PublicationsFile = toml::from_str(toml).unwrap();
        let resolved = resolve_config(&file);
        assert_eq!(
            resolved.publications[0].fields,
            vec![FieldId::NodeName, FieldId::Version]
        );
    }

    #[test]
    fn falls_back_to_default_when_all_items_unknown() {
        let toml = r#"
            [[publication]]
            items = ["not_a_real_field"]
        "#;
        let file: PublicationsFile = toml::from_str(toml).unwrap();
        let resolved = resolve_config(&file);
        assert_eq!(resolved.publications.len(), 1);
        assert_eq!(resolved.publications[0].fields.len(), FieldId::ALL.len());
    }

    #[test]
    fn ignores_unknown_toml_keys() {
        let toml = r#"
            [[publication]]
            future_option = true
            items = ["node_name"]
        "#;
        let file: PublicationsFile = toml::from_str(toml).unwrap();
        let resolved = resolve_config(&file);
        assert_eq!(resolved.publications[0].fields, vec![FieldId::NodeName]);
    }

    #[test]
    fn node_name_is_always_amaru_even_if_only_that_field_is_selected() {
        let toml = r#"
            [[publication]]
            items = ["node_name"]
        "#;
        let file: PublicationsFile = toml::from_str(toml).unwrap();
        let resolved = resolve_config(&file);
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
        let toml = r#"
            [[publication]]
            items = ["amaru.git_revision"]
        "#;
        let file: PublicationsFile = toml::from_str(toml).unwrap();
        let id = identity();
        let resolved = resolve_config(&file);
        let msg = build_message(&resolved, &id, 0, &PeerConnectionSnapshot::default());
        let pubs = msg.logical_publications().unwrap();
        let Publication::Open { payload, .. } = &pubs[0] else {
            panic!("expected open");
        };
        assert_eq!(
            payload.experimental.get("amaru.git_revision"),
            Some(&ExperimentalValue::Text(id.git_revision.to_string()))
        );
    }
}

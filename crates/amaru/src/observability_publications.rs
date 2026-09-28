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
//! Multiple `[[publication]]` tables are supported so the same field can appear in
//! several bags (e.g. a public open set and a future encrypted observer set).

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use amaru_protocols::observability::{
    ExperimentalValue, MAX_PUBLICATIONS, Message, OBSERVER_PUBLIC_KEY_LEN, OpenPayload, PUBLICATION_VERSION,
    Publication, set_publications_provider,
};
use anyhow::{Context, bail};
use serde::Deserialize;

use crate::version;

/// Default path env for the publications config.
pub const OBSERVABILITY_CONFIG_ENV: &str = "AMARU_OBSERVABILITY_CONFIG";

/// Hardcoded standard openPayload node_name (key 1). Not configurable.
const NODE_NAME: &str = "amaru";

/// Catalogue of built-in fields operators may enable. Values are never taken from config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldId {
    /// Standard openPayload key 1 (`"amaru"`).
    NodeName,
    /// Standard openPayload key 2 (package major).
    NodeVersionMajor,
    /// Experimental `amaru.version`.
    Version,
    /// Experimental `amaru.version_minor`.
    VersionMinor,
    /// Experimental `amaru.version_patch`.
    VersionPatch,
    /// Experimental `amaru.git_revision`.
    GitRevision,
    /// Experimental `amaru.cpu_cores`.
    CpuCores,
    /// Experimental `amaru.process_rss_bytes`.
    ProcessRssBytes,
}

impl FieldId {
    const ALL: [FieldId; 8] = [
        Self::NodeName,
        Self::NodeVersionMajor,
        Self::Version,
        Self::VersionMinor,
        Self::VersionPatch,
        Self::GitRevision,
        Self::CpuCores,
        Self::ProcessRssBytes,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::NodeName => "node_name",
            Self::NodeVersionMajor => "node_version_major",
            Self::Version => "version",
            Self::VersionMinor => "version_minor",
            Self::VersionPatch => "version_patch",
            Self::GitRevision => "git_revision",
            Self::CpuCores => "cpu_cores",
            Self::ProcessRssBytes => "process_rss_bytes",
        }
    }
}

impl FromStr for FieldId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "node_name" => Self::NodeName,
            "node_version_major" => Self::NodeVersionMajor,
            "version" => Self::Version,
            "version_minor" => Self::VersionMinor,
            "version_patch" => Self::VersionPatch,
            "git_revision" => Self::GitRevision,
            "cpu_cores" => Self::CpuCores,
            "process_rss_bytes" => Self::ProcessRssBytes,
            other => bail!(
                "unknown field '{other}'; known fields: {}",
                FieldId::ALL.iter().map(|f| f.as_str()).collect::<Vec<_>>().join(", ")
            ),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct PublicationSection {
    /// Built-in field ids to include in this publication's openPayload.
    pub items: Vec<String>,

    /// Optional X25519 observer public key (64 hex chars). Reserved for encrypted
    /// publications; not implemented yet — config load fails if set.
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

#[derive(Debug, Clone, Copy)]
struct NodeIdentity {
    version: &'static str,
    major: u16,
    minor: u16,
    patch: u16,
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

/// Load config (optional path / env) and install the publications provider.
pub fn install_for_node(config_path: Option<&Path>) -> anyhow::Result<()> {
    let path = resolve_config_path(config_path);
    let file = match path.as_ref() {
        Some(p) => load_file(p).with_context(|| format!("load observability publications config {}", p.display()))?,
        None => PublicationsFile::default(),
    };
    let resolved = resolve_config(&file)?;
    install_provider(resolved, NodeIdentity::from_build());
    Ok(())
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

fn resolve_config(file: &PublicationsFile) -> anyhow::Result<ResolvedConfig> {
    if file.publications.is_empty() {
        bail!("observability config must declare at least one [[publication]]");
    }
    if file.publications.len() > MAX_PUBLICATIONS {
        bail!(
            "observability config has {} publications; maximum is {MAX_PUBLICATIONS}",
            file.publications.len()
        );
    }

    let mut publications = Vec::with_capacity(file.publications.len());
    for (index, section) in file.publications.iter().enumerate() {
        let label = format!("publication[{index}]");
        if section.items.is_empty() {
            bail!("{label}: items must not be empty");
        }

        let mut fields = Vec::with_capacity(section.items.len());
        let mut seen = BTreeMap::new();
        for item in &section.items {
            let field = FieldId::from_str(item).with_context(|| format!("{label}: items"))?;
            if seen.insert(field.as_str(), ()).is_some() {
                bail!("{label}: duplicate field '{}'", field.as_str());
            }
            fields.push(field);
        }

        match section.observer_public_key.as_deref() {
            None => {}
            Some(hex_key) => {
                // Validate shape now so operators get a clear hex error; refuse until sealed-box lands.
                let _key = parse_observer_public_key(hex_key)
                    .with_context(|| format!("{label}: observer_public_key"))?;
                bail!(
                    "{label}: observer_public_key is set, but encrypted publications are not implemented yet; \
                     omit the key to publish this bag in the clear, or wait for sealed-box support"
                );
            }
        }

        publications.push(ResolvedPublication { fields });
    }

    Ok(ResolvedConfig { publications })
}

fn parse_observer_public_key(hex_key: &str) -> anyhow::Result<[u8; OBSERVER_PUBLIC_KEY_LEN]> {
    let hex_key = hex_key.trim();
    let bytes = hex::decode(hex_key).context("expected hex-encoded X25519 public key")?;
    if bytes.len() != OBSERVER_PUBLIC_KEY_LEN {
        bail!(
            "expected {OBSERVER_PUBLIC_KEY_LEN} bytes ({} hex chars), got {} bytes",
            OBSERVER_PUBLIC_KEY_LEN * 2,
            bytes.len()
        );
    }
    let mut key = [0u8; OBSERVER_PUBLIC_KEY_LEN];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn install_provider(config: ResolvedConfig, identity: NodeIdentity) {
    set_publications_provider(Arc::new(move || build_message(&config, identity)));
}

fn build_message(config: &ResolvedConfig, identity: NodeIdentity) -> Message {
    let live = LiveSamples::capture();
    let pubs: Vec<Publication> = config
        .publications
        .iter()
        .map(|section| {
            // Encrypted publications: observer_public_key is rejected at resolve time until sealed-box lands.
            Publication::Open {
                version: PUBLICATION_VERSION,
                snapshot_slot: 0,
                payload: build_payload(&section.fields, identity, &live),
            }
        })
        .collect();
    Message::Publications(pubs)
}

struct LiveSamples {
    cpu_cores: u64,
    process_rss_bytes: Option<u64>,
}

impl LiveSamples {
    fn capture() -> Self {
        Self {
            cpu_cores: std::thread::available_parallelism().map(|n| n.get() as u64).unwrap_or(0),
            process_rss_bytes: sample_process_rss_bytes(),
        }
    }
}

fn build_payload(fields: &[FieldId], identity: NodeIdentity, live: &LiveSamples) -> OpenPayload {
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
        let resolved = resolve_config(&PublicationsFile::default()).unwrap();
        let msg = build_message(&resolved, identity());
        let Message::Publications(pubs) = msg else {
            panic!("expected Publications");
        };
        assert_eq!(pubs.len(), 1);
        let Publication::Open { payload, .. } = &pubs[0] else {
            panic!("expected open publication");
        };
        assert_eq!(payload.node_name.as_deref(), Some("amaru"));
        assert_eq!(payload.node_version_major, Some(identity().major));
        assert!(payload.experimental.contains_key("amaru.version"));
        assert!(payload.experimental.contains_key("amaru.cpu_cores"));
    }

    #[test]
    fn multiple_publications_can_share_fields() {
        let toml = r#"
            [[publication]]
            items = ["node_name", "node_version_major", "version"]

            [[publication]]
            items = ["node_name", "cpu_cores", "process_rss_bytes"]
        "#;
        let file: PublicationsFile = toml::from_str(toml).unwrap();
        let resolved = resolve_config(&file).unwrap();
        let msg = build_message(&resolved, identity());
        let Message::Publications(pubs) = msg else {
            panic!("expected Publications");
        };
        assert_eq!(pubs.len(), 2);

        let Publication::Open { payload: first, .. } = &pubs[0] else {
            panic!("expected open");
        };
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
    fn rejects_unknown_field_id() {
        let toml = r#"
            [[publication]]
            items = ["node_name", "fake_slot"]
        "#;
        let file: PublicationsFile = toml::from_str(toml).unwrap();
        let err = format!("{:#}", resolve_config(&file).unwrap_err());
        assert!(err.contains("unknown field"), "{err}");
    }

    #[test]
    fn rejects_observer_public_key_until_encryption_exists() {
        let toml = r#"
            [[publication]]
            observer_public_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            items = ["node_name", "cpu_cores"]
        "#;
        let file: PublicationsFile = toml::from_str(toml).unwrap();
        let err = resolve_config(&file).unwrap_err().to_string();
        assert!(err.contains("encrypted publications are not implemented"), "{err}");
    }

    #[test]
    fn rejects_duplicate_field_in_one_publication() {
        let toml = r#"
            [[publication]]
            items = ["node_name", "node_name"]
        "#;
        let file: PublicationsFile = toml::from_str(toml).unwrap();
        let err = resolve_config(&file).unwrap_err().to_string();
        assert!(err.contains("duplicate field"), "{err}");
    }

    #[test]
    fn node_name_is_always_amaru_even_if_only_that_field_is_selected() {
        let toml = r#"
            [[publication]]
            items = ["node_name"]
        "#;
        let file: PublicationsFile = toml::from_str(toml).unwrap();
        let resolved = resolve_config(&file).unwrap();
        let msg = build_message(&resolved, identity());
        let Message::Publications(pubs) = msg else {
            panic!("expected Publications");
        };
        let Publication::Open { payload, .. } = &pubs[0] else {
            panic!("expected open");
        };
        assert_eq!(payload.node_name.as_deref(), Some("amaru"));
        assert!(payload.node_version_major.is_none());
        assert!(payload.experimental.is_empty());
    }
}

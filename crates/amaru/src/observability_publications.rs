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
//! Used when `AMARU_OBSERVABILITY` is set. Without a config file, a sensible auto
//! publication is installed (node name, version parts, git revision, CPU cores,
//! process RSS). Dynamic fields are sampled when each inbound connection registers
//! the responder (one-shot per connection).

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use amaru_protocols::observability::{
    ExperimentalValue, Message, OpenPayload, PUBLICATION_VERSION, Publication, set_publications_provider,
};
use anyhow::{Context, bail};
use serde::Deserialize;

use crate::version;

/// Default path env for the publications config.
pub const OBSERVABILITY_CONFIG_ENV: &str = "AMARU_OBSERVABILITY_CONFIG";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationsFile {
    /// Standard openPayload key 1. Defaults to `"amaru"`.
    #[serde(default = "default_node_name")]
    pub node_name: String,

    /// Standard openPayload key 2. When omitted, uses the package major version.
    #[serde(default)]
    pub node_version_major: Option<u16>,

    /// Publication snapshot slot label (not chain tip). Defaults to 0.
    #[serde(default)]
    pub snapshot_slot: u64,

    /// Static experimental fields (`amaru.*` / other namespaced keys).
    #[serde(default)]
    pub experimental: BTreeMap<String, TomlExperimentalValue>,

    /// Which built-in node fields to attach as experimental keys.
    #[serde(default = "AutoFields::all_enabled")]
    pub auto: AutoFields,
}

fn default_node_name() -> String {
    "amaru".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoFields {
    /// `amaru.version` (full package version string).
    #[serde(default = "default_true")]
    pub version: bool,
    /// `amaru.version_minor` (uint).
    #[serde(default = "default_true")]
    pub version_minor: bool,
    /// `amaru.version_patch` (uint).
    #[serde(default = "default_true")]
    pub version_patch: bool,
    /// `amaru.git_revision` (short hash, or `"unknown"`).
    #[serde(default = "default_true")]
    pub git_revision: bool,
    /// `amaru.cpu_cores` via `available_parallelism`.
    #[serde(default = "default_true")]
    pub cpu_cores: bool,
    /// `amaru.process_rss_bytes` (best-effort; Linux `/proc`, else sysinfo).
    #[serde(default = "default_true")]
    pub process_rss_bytes: bool,
}

impl AutoFields {
    fn all_enabled() -> Self {
        Self {
            version: true,
            version_minor: true,
            version_patch: true,
            git_revision: true,
            cpu_cores: true,
            process_rss_bytes: true,
        }
    }
}

fn default_true() -> bool {
    true
}

impl Default for PublicationsFile {
    fn default() -> Self {
        Self {
            node_name: default_node_name(),
            node_version_major: None,
            snapshot_slot: 0,
            experimental: BTreeMap::new(),
            auto: AutoFields::all_enabled(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum TomlExperimentalValue {
    Text(String),
    Bool(bool),
    Uint(u64),
    Int(i64),
}

impl TomlExperimentalValue {
    fn into_experimental(self) -> anyhow::Result<ExperimentalValue> {
        Ok(match self {
            Self::Text(s) => ExperimentalValue::Text(s),
            Self::Bool(b) => ExperimentalValue::Bool(b),
            Self::Uint(n) => ExperimentalValue::Uint(n),
            Self::Int(n) => {
                if n < 0 {
                    bail!("experimental integer fields must be non-negative (got {n})");
                }
                ExperimentalValue::Uint(n as u64)
            }
        })
    }
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
    install_provider(file, NodeIdentity::from_build());
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
    let file: PublicationsFile = toml::from_str(&raw).with_context(|| format!("parse TOML {}", path.display()))?;
    for (key, value) in &file.experimental {
        validate_experimental_key(key)?;
        value.clone().into_experimental().with_context(|| format!("experimental field '{key}'"))?;
    }
    Ok(file)
}

fn validate_experimental_key(key: &str) -> anyhow::Result<()> {
    if !key.contains('.') {
        bail!("experimental key '{key}' must be namespaced (e.g. amaru.site)");
    }
    Ok(())
}

fn install_provider(file: PublicationsFile, identity: NodeIdentity) {
    set_publications_provider(Arc::new(move || build_message(&file, identity)));
}

fn build_message(file: &PublicationsFile, identity: NodeIdentity) -> Message {
    let mut experimental = BTreeMap::new();
    for (k, v) in &file.experimental {
        if let Ok(val) = v.clone().into_experimental() {
            experimental.insert(k.clone(), val);
        }
    }

    if file.auto.version {
        experimental.insert("amaru.version".into(), ExperimentalValue::Text(identity.version.to_string()));
    }
    if file.auto.version_minor {
        experimental.insert("amaru.version_minor".into(), ExperimentalValue::Uint(u64::from(identity.minor)));
    }
    if file.auto.version_patch {
        experimental.insert("amaru.version_patch".into(), ExperimentalValue::Uint(u64::from(identity.patch)));
    }
    if file.auto.git_revision {
        experimental
            .insert("amaru.git_revision".into(), ExperimentalValue::Text(identity.git_revision.to_string()));
    }
    if file.auto.cpu_cores {
        let cores = std::thread::available_parallelism().map(|n| n.get() as u64).unwrap_or(0);
        experimental.insert("amaru.cpu_cores".into(), ExperimentalValue::Uint(cores));
    }
    if file.auto.process_rss_bytes {
        if let Some(rss) = sample_process_rss_bytes() {
            experimental.insert("amaru.process_rss_bytes".into(), ExperimentalValue::Uint(rss));
        }
    }

    let major = file.node_version_major.unwrap_or(identity.major);
    Message::Publications(vec![Publication::Open {
        version: PUBLICATION_VERSION,
        snapshot_slot: file.snapshot_slot,
        payload: OpenPayload {
            node_name: Some(file.node_name.clone()),
            node_version_major: Some(major),
            experimental,
        },
    }])
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

    #[test]
    fn default_file_builds_open_publication() {
        let msg = build_message(&PublicationsFile::default(), NodeIdentity::from_build());
        let Message::Publications(pubs) = msg else {
            panic!("expected Publications");
        };
        assert_eq!(pubs.len(), 1);
        let Publication::Open { payload, .. } = &pubs[0] else {
            panic!("expected open publication");
        };
        assert_eq!(payload.node_name.as_deref(), Some("amaru"));
        assert!(payload.node_version_major.is_some());
        assert!(payload.experimental.contains_key("amaru.version"));
        assert!(payload.experimental.contains_key("amaru.cpu_cores"));
    }

    #[test]
    fn rejects_unnamespaced_experimental_key() {
        let toml = r#"
            [experimental]
            site = "lab"
        "#;
        let file: PublicationsFile = toml::from_str(toml).unwrap();
        assert!(validate_experimental_key(file.experimental.keys().next().unwrap()).is_err());
    }

    #[test]
    fn parses_static_experimental_types() {
        let toml = r#"
            node_name = "lab-node"
            [experimental]
            "amaru.site" = "cn014"
            "amaru.flag" = true
            "amaru.n" = 42
            [auto]
            version = false
            version_minor = false
            version_patch = false
            git_revision = false
            cpu_cores = false
            process_rss_bytes = false
        "#;
        let file: PublicationsFile = toml::from_str(toml).unwrap();
        let msg = build_message(&file, NodeIdentity::from_build());
        let Message::Publications(pubs) = msg else {
            panic!("expected Publications");
        };
        let Publication::Open { payload, .. } = &pubs[0] else {
            panic!("expected open");
        };
        assert_eq!(payload.node_name.as_deref(), Some("lab-node"));
        assert_eq!(payload.experimental.get("amaru.site"), Some(&ExperimentalValue::Text("cn014".into())));
        assert_eq!(payload.experimental.get("amaru.flag"), Some(&ExperimentalValue::Bool(true)));
        assert_eq!(payload.experimental.get("amaru.n"), Some(&ExperimentalValue::Uint(42)));
        assert!(!payload.experimental.contains_key("amaru.version"));
    }
}

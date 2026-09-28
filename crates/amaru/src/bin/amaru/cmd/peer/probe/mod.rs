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

//! One-shot N2N probe against a live peer (experimental observability CIP support).

mod session;

use std::{
    io::{self, IsTerminal},
    str::FromStr,
    time::Duration,
};

use amaru::{
    lifecycle::{Runnable, RuntimeKind},
    observability::Color,
};
use amaru_kernel::{NetworkName, Peer};
use anyhow::{Context, bail};
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Args {
    /// Remote node address (`IP:PORT`).
    #[arg(value_name = amaru::value_names::HOST_PORT)]
    address: String,

    /// Cardano network (selects handshake network magic).
    #[arg(
        long,
        value_name = amaru::value_names::NETWORK,
        env = amaru::env_vars::NETWORK,
        default_value = "mainnet"
    )]
    network: NetworkName,

    /// TCP connect timeout in milliseconds.
    #[arg(
        long = "connect-timeout",
        value_name = "MS",
        env = amaru::env_vars::PROBE_CONNECT_TIMEOUT,
        default_value = "5000"
    )]
    connect_timeout_ms: u64,

    /// Handshake mini-protocol timeout in milliseconds.
    #[arg(
        long = "handshake-timeout",
        value_name = "MS",
        env = amaru::env_vars::PROBE_HANDSHAKE_TIMEOUT,
        default_value = "10000"
    )]
    handshake_timeout_ms: u64,

    /// Timeout for chainsync / peer-share / observability replies in milliseconds.
    #[arg(
        long = "protocol-timeout",
        value_name = "MS",
        env = amaru::env_vars::PROBE_PROTOCOL_TIMEOUT,
        default_value = "15000"
    )]
    protocol_timeout_ms: u64,

    /// Measure TCP connect RTT.
    ///
    /// Optional value: `COUNT` (1..=86400, one ping per second) or `COUNT:INTERVAL_MS`
    /// (e.g. `20:5000` = 20 pings, 5000 ms apart). Bare `--ping` runs once.
    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "1",
        value_name = "COUNT|COUNT:INTERVAL_MS"
    )]
    ping: Option<PingSpec>,

    /// Show negotiated handshake version and VersionData.
    #[arg(long)]
    handshake: bool,

    /// Request up to 10 peer-share addresses.
    #[arg(long)]
    peershare: bool,

    /// After peer-share, TCP-ping (and observe) each returned peer.
    #[arg(long)]
    pscheck: bool,

    /// Query tip via chain-sync FindIntersect(Origin).
    #[arg(long)]
    tip: bool,

    /// Query the experimental observability mini-protocol (mux 11).
    #[arg(long)]
    observe: bool,

    /// Run ping, handshake, tip, peershare, and observe (then pscheck if peers are returned).
    #[arg(long)]
    all: bool,

    /// Emit machine-readable JSON instead of color human output.
    #[arg(long)]
    json: bool,
}

/// How many TCP pings to run and the gap between them.
#[derive(Debug, Clone, Copy)]
struct PingSpec {
    count: u32,
    interval: Duration,
}

impl FromStr for PingSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const MAX_COUNT: u32 = 86400;

        let (count_str, interval) = if let Some((count_str, interval_str)) = s.split_once(':') {
            let interval_ms: u64 = interval_str
                .parse()
                .map_err(|_| format!("invalid ping interval '{interval_str}' (expected milliseconds)"))?;
            if interval_ms == 0 {
                return Err("ping interval must be >= 1 ms".to_string());
            }
            (count_str, Duration::from_millis(interval_ms))
        } else {
            (s, Duration::from_secs(1))
        };

        let count: u32 = count_str
            .parse()
            .map_err(|_| format!("invalid ping count '{count_str}' (expected integer 1..={MAX_COUNT})"))?;
        if !(1..=MAX_COUNT).contains(&count) {
            return Err(format!("ping count must be between 1 and {MAX_COUNT}"));
        }

        Ok(Self { count, interval })
    }
}

#[derive(Debug, Clone, Copy)]
struct Actions {
    ping: Option<PingSpec>,
    handshake: bool,
    peershare: bool,
    pscheck: bool,
    tip: bool,
    observe: bool,
}

impl Actions {
    fn from_args(args: &Args) -> Self {
        if args.all {
            return Self {
                ping: Some(PingSpec { count: 1, interval: Duration::from_secs(1) }),
                handshake: true,
                peershare: true,
                pscheck: true,
                tip: true,
                observe: true,
            };
        }
        let mut actions = Self {
            ping: args.ping,
            handshake: args.handshake,
            peershare: args.peershare || args.pscheck,
            pscheck: args.pscheck,
            tip: args.tip,
            observe: args.observe,
        };
        if actions.ping.is_none()
            && !(actions.handshake || actions.peershare || actions.pscheck || actions.tip || actions.observe)
        {
            // Default: full probe when no action flag is given.
            actions = Self {
                ping: Some(PingSpec { count: 1, interval: Duration::from_secs(1) }),
                handshake: true,
                peershare: true,
                pscheck: false,
                tip: true,
                observe: true,
            };
        }
        actions
    }

    fn needs_session(self) -> bool {
        self.handshake || self.peershare || self.tip || self.observe
    }
}

pub(crate) fn runnable(args: Args) -> Runnable {
    Runnable::exit_on_signal(RuntimeKind::Io, move || run(args))
}

async fn run(args: Args) -> anyhow::Result<()> {
    let actions = Actions::from_args(&args);
    let peer: Peer = args.address.parse().context("invalid IP:PORT address")?;
    let connect_timeout = Duration::from_millis(args.connect_timeout_ms);
    let handshake_timeout = Duration::from_millis(args.handshake_timeout_ms);
    let protocol_timeout = Duration::from_millis(args.protocol_timeout_ms);
    let color = color_enabled();

    let mut report = session::ProbeReport {
        address: args.address.clone(),
        network: args.network.to_string(),
        ping_rtts_ms: Vec::new(),
        ping_interval_ms: None,
        handshake: None,
        peers: None,
        tip: None,
        publications: None,
        peer_checks: Vec::new(),
        errors: Vec::new(),
    };

    if let Some(spec) = actions.ping {
        report.ping_interval_ms = Some(spec.interval.as_millis() as u64);
        match run_pings(peer, connect_timeout, spec).await {
            Ok(samples) => report.ping_rtts_ms = samples,
            Err(err) => {
                report.errors.push(format!("connect: {err:#}"));
                emit(&report, args.json, color)?;
                bail!("TCP connect failed");
            }
        }
    }

    if actions.needs_session() {
        match session::run_session(session::SessionRequest {
            peer,
            network: args.network,
            connect_timeout,
            handshake_timeout,
            protocol_timeout,
            want_handshake: actions.handshake || actions.needs_session(),
            want_peershare: actions.peershare,
            want_tip: actions.tip,
            want_observe: actions.observe,
            peer_share_amount: 10,
        })
        .await
        {
            Ok(partial) => {
                report.handshake = partial.handshake;
                report.peers = partial.peers;
                report.tip = partial.tip;
                report.publications = partial.publications;
                report.errors.extend(partial.errors);
            }
            Err(err) => report.errors.push(format!("session: {err:#}")),
        }
    }

    if actions.pscheck {
        let peers = report.peers.clone().unwrap_or_default();
        for addr in peers {
            let Ok(peer) = addr.parse::<Peer>() else {
                report.peer_checks.push(session::PeerCheck {
                    address: addr,
                    ok: false,
                    detail: "invalid peer address from share".to_string(),
                    ping_rtt_ms: None,
                    publications: None,
                });
                continue;
            };

            let ping_rtt_ms = match session::tcp_ping(peer, connect_timeout).await {
                Ok(rtt) => Some(rtt.as_millis() as u64),
                Err(err) => {
                    report.peer_checks.push(session::PeerCheck {
                        address: addr.clone(),
                        ok: false,
                        detail: format!("ping failed: {err:#}"),
                        ping_rtt_ms: None,
                        publications: None,
                    });
                    continue;
                }
            };

            match session::run_session(session::SessionRequest {
                peer,
                network: args.network,
                connect_timeout,
                handshake_timeout,
                protocol_timeout,
                want_handshake: true,
                want_peershare: false,
                want_tip: false,
                want_observe: true,
                peer_share_amount: 10,
            })
            .await
            {
                Ok(partial) => {
                    let ok = partial.publications.is_some() && partial.errors.is_empty();
                    let detail = if ok {
                        "observe ok".to_string()
                    } else if let Some(err) = partial.errors.first() {
                        err.clone()
                    } else {
                        "no publications".to_string()
                    };
                    report.peer_checks.push(session::PeerCheck {
                        address: addr,
                        ok,
                        detail,
                        ping_rtt_ms,
                        publications: partial.publications,
                    });
                }
                Err(err) => report.peer_checks.push(session::PeerCheck {
                    address: addr,
                    ok: false,
                    detail: format!("{err:#}"),
                    ping_rtt_ms,
                    publications: None,
                }),
            }
        }
    }

    emit(&report, args.json, color)?;
    if !report.errors.is_empty() {
        bail!("probe completed with errors");
    }
    Ok(())
}

async fn run_pings(peer: Peer, connect_timeout: Duration, spec: PingSpec) -> anyhow::Result<Vec<u64>> {
    let mut samples = Vec::with_capacity(spec.count as usize);
    for i in 0..spec.count {
        let rtt = session::tcp_ping(peer, connect_timeout).await?;
        samples.push(rtt.as_millis() as u64);
        if i + 1 < spec.count {
            tokio::time::sleep(spec.interval).await;
        }
    }
    Ok(samples)
}

fn emit(report: &session::ProbeReport, json: bool, color: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        print_human(report, color);
    }
    Ok(())
}

fn print_human(report: &session::ProbeReport, color: bool) {
    let (ok, warn, err, cyan, bold, reset) = if color {
        ("\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[36m", "\x1b[1m", "\x1b[0m")
    } else {
        ("", "", "", "", "", "")
    };

    println!("{bold}probe{reset} {cyan}{}{reset} ({})", report.address, report.network);

    if !report.ping_rtts_ms.is_empty() {
        print_ping_section(report, ok, reset);
    }
    if let Some(hs) = &report.handshake {
        println!("  {ok}handshake{reset}");
        println!("    version:          {}", hs.version);
        println!("    network_magic:    {}", hs.network_magic);
        println!("    peer_sharing:     {}", hs.peer_sharing);
        println!("    initiator_only:   {}", hs.initiator_only);
        println!("    query:            {}", hs.query);
        println!("    peras_support:    {}", hs.peras_support);
    }
    if let Some(tip) = &report.tip {
        println!("  {ok}tip{reset}");
        println!("    slot:             {}", tip.slot);
        println!("    block_height:     {}", tip.block_height);
        println!("    hash:             {}", tip.hash);
    }
    if let Some(peers) = &report.peers {
        println!("  {ok}peershare{reset}  {} peer(s)", peers.len());
        for p in peers {
            if let Some(check) = report.peer_checks.iter().find(|c| c.address == *p) {
                let ping = match check.ping_rtt_ms {
                    Some(ms) => format!("{ms} ms"),
                    None => "ping failed".to_string(),
                };
                let tag = if check.ok { ok } else { warn };
                println!("    {p}  {ping}  {tag}{}{reset}", check.detail);
            } else {
                println!("    {p}");
            }
        }
    }
    if let Some(pubs) = &report.publications {
        println!("  {ok}observe{reset}");
        print_publications_human(pubs, "    ");
    }
    for check in &report.peer_checks {
        // Details already shown on peershare lines when address matches; only dump extras
        // for checks without a peershare row (should not happen) or open publications.
        if report.peers.as_ref().is_some_and(|ps| ps.iter().any(|p| p == &check.address)) {
            if let Some(pubs) = &check.publications {
                println!("      observe {}", check.address);
                print_publications_human(pubs, "        ");
            }
            continue;
        }
        let tag = if check.ok { ok } else { warn };
        let ping = check.ping_rtt_ms.map(|ms| format!("{ms} ms")).unwrap_or_else(|| "-".to_string());
        println!("  {tag}pscheck{reset}  {}  ping {ping}  {}", check.address, check.detail);
        if let Some(pubs) = &check.publications {
            print_publications_human(pubs, "           ");
        }
    }
    for e in &report.errors {
        println!("  {err}error{reset}   {e}");
    }
}

fn print_ping_section(report: &session::ProbeReport, ok: &str, reset: &str) {
    let samples = &report.ping_rtts_ms;
    println!("  {ok}ping{reset}");
    if samples.len() == 1 {
        println!("    rtt:              {} ms", samples[0]);
        return;
    }
    let min = samples.iter().copied().min().unwrap_or(0);
    let max = samples.iter().copied().max().unwrap_or(0);
    let avg = samples.iter().sum::<u64>() / samples.len() as u64;
    println!("    count:            {}", samples.len());
    if let Some(interval) = report.ping_interval_ms {
        println!("    interval:         {interval} ms");
    }
    for (i, ms) in samples.iter().enumerate() {
        println!("    {:<18} {} ms", format!("{}:", i + 1), ms);
    }
    println!("    min:              {min} ms");
    println!("    avg:              {avg} ms");
    println!("    max:              {max} ms");
}

fn print_publications_human(value: &serde_json::Value, indent: &str) {
    match value {
        serde_json::Value::Object(map) => {
            let ty = map.get("type").and_then(|v| v.as_str()).unwrap_or("unknown");
            println!("{indent}type:             {ty}");
            if let Some(items) = map.get("items").and_then(|v| v.as_array()) {
                println!("{indent}publications:     {}", items.len());
                for (i, item) in items.iter().enumerate() {
                    println!("{indent}[{i}]");
                    print_publication_item(item, &format!("{indent}  "));
                }
            }
        }
        other => {
            for line in serde_json::to_string_pretty(other).unwrap_or_else(|_| other.to_string()).lines() {
                println!("{indent}{line}");
            }
        }
    }
}

fn print_publication_item(item: &serde_json::Value, indent: &str) {
    let Some(obj) = item.as_object() else {
        println!("{indent}{item}");
        return;
    };
    let keys = [
        "kind",
        "version",
        "snapshot_slot",
        "node_name",
        "node_version_major",
        "observer_public_key",
        "ciphertext_len",
    ];
    for key in keys {
        if let Some(v) = obj.get(key) {
            let rendered = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => "null".to_string(),
                other => other.to_string(),
            };
            println!("{indent}{key:<18} {rendered}");
        }
    }
    if let Some(exp) = obj.get("experimental").and_then(|v| v.as_object()) {
        if exp.is_empty() {
            println!("{indent}{:<18} {{}}", "experimental");
        } else {
            println!("{indent}experimental:");
            for (k, v) in exp {
                let rendered = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                println!("{indent}  {k}: {rendered}");
            }
        }
    }
}

fn color_enabled() -> bool {
    let mode = std::env::var("AMARU_COLOR")
        .ok()
        .as_deref()
        .and_then(|s| Color::from_str(s).ok())
        .unwrap_or(Color::Auto);
    match mode {
        Color::Never => false,
        Color::Always => true,
        Color::Auto => {
            if std::env::var("NO_COLOR").iter().any(|s| !s.is_empty()) {
                false
            } else {
                io::stdout().is_terminal()
            }
        }
    }
}

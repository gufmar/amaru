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
        default_value = "preprod"
    )]
    network: NetworkName,

    /// TCP connect timeout in seconds.
    #[arg(
        long = "connect-timeout",
        value_name = "SECS",
        env = amaru::env_vars::PROBE_CONNECT_TIMEOUT,
        default_value = "5"
    )]
    connect_timeout_secs: u64,

    /// Handshake mini-protocol timeout in seconds.
    #[arg(
        long = "handshake-timeout",
        value_name = "SECS",
        env = amaru::env_vars::PROBE_HANDSHAKE_TIMEOUT,
        default_value = "10"
    )]
    handshake_timeout_secs: u64,

    /// Timeout for chainsync / peer-share / observability replies in seconds.
    #[arg(
        long = "protocol-timeout",
        value_name = "SECS",
        env = amaru::env_vars::PROBE_PROTOCOL_TIMEOUT,
        default_value = "15"
    )]
    protocol_timeout_secs: u64,

    /// Measure TCP connect RTT only (or as part of a larger probe).
    #[arg(long)]
    ping: bool,

    /// Show negotiated handshake version and VersionData.
    #[arg(long)]
    handshake: bool,

    /// Request up to 10 peer-share addresses.
    #[arg(long)]
    peershare: bool,

    /// After peer-share, run `--observe` against each returned peer.
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

#[derive(Debug, Clone, Copy)]
struct Actions {
    ping: bool,
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
                ping: true,
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
        if !(actions.ping
            || actions.handshake
            || actions.peershare
            || actions.pscheck
            || actions.tip
            || actions.observe)
        {
            // Default: full probe when no action flag is given.
            actions = Self {
                ping: true,
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
    let connect_timeout = Duration::from_secs(args.connect_timeout_secs);
    let handshake_timeout = Duration::from_secs(args.handshake_timeout_secs);
    let protocol_timeout = Duration::from_secs(args.protocol_timeout_secs);
    let color = color_enabled();

    let mut report = session::ProbeReport {
        address: args.address.clone(),
        network: args.network.to_string(),
        ping_rtt_ms: None,
        handshake: None,
        peers: None,
        tip: None,
        publications: None,
        peer_checks: Vec::new(),
        errors: Vec::new(),
    };

    if actions.ping {
        match session::tcp_ping(peer, connect_timeout).await {
            Ok(rtt) => {
                report.ping_rtt_ms = Some(rtt.as_millis() as u64);
            }
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
                    publications: None,
                });
                continue;
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
                        publications: partial.publications,
                    });
                }
                Err(err) => report.peer_checks.push(session::PeerCheck {
                    address: addr,
                    ok: false,
                    detail: format!("{err:#}"),
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

    if let Some(ms) = report.ping_rtt_ms {
        println!("  {ok}ping{reset}     {ms} ms");
    }
    if let Some(hs) = &report.handshake {
        println!(
            "  {ok}handshake{reset} version={} peer_sharing={} initiator_only={} query={} peras={}",
            hs.version, hs.peer_sharing, hs.initiator_only, hs.query, hs.peras_support
        );
    }
    if let Some(tip) = &report.tip {
        println!("  {ok}tip{reset}      {tip}");
    }
    if let Some(peers) = &report.peers {
        println!("  {ok}peershare{reset} {} peer(s)", peers.len());
        for p in peers {
            println!("           - {p}");
        }
    }
    if let Some(pubs) = &report.publications {
        println!("  {ok}observe{reset}");
        println!("{}", indent_json(pubs, "           "));
    }
    for check in &report.peer_checks {
        let tag = if check.ok { ok } else { warn };
        println!("  {tag}pscheck{reset}  {} — {}", check.address, check.detail);
        if let Some(pubs) = &check.publications {
            println!("{}", indent_json(pubs, "           "));
        }
    }
    for e in &report.errors {
        println!("  {err}error{reset}   {e}");
    }
}

fn indent_json(value: &serde_json::Value, prefix: &str) -> String {
    let text = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
    text.lines().map(|line| format!("{prefix}{line}")).collect::<Vec<_>>().join("\n")
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

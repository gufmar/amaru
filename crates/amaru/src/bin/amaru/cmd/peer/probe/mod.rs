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
    time::{Duration, Instant},
};

use amaru::{
    lifecycle::{Runnable, RuntimeKind},
    observability::Color,
};
use amaru_kernel::{NetworkName, Peer};
use amaru_protocols::protocol_messages::version_number::VersionNumber;
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

    /// Measure keep-alive mini-protocol RTT after TCP connect + N2N handshake.
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

    /// Query remote offered N2N versions (`MsgQueryReply`) and print them.
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

    /// Record per-step wall timestamps, deltas, elapsed-from-start, and TCP bytes.
    #[arg(long)]
    timetrack: bool,

    /// Extra attempts after a failed handshake-query or session step.
    ///
    /// Optional value: `COUNT` (1..=32 retries, 500 ms apart) or `COUNT:INTERVAL_MS`
    /// (e.g. `2:500` = retry twice, 500 ms between attempts). Bare `--retry` retries once
    /// after 500 ms. Does not multiply `--ping` samples.
    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "1:500",
        value_name = "COUNT|COUNT:INTERVAL_MS",
        env = amaru::env_vars::PROBE_RETRY
    )]
    retry: Option<RetrySpec>,

    /// Highest N2N version to offer in the handshake (default: highest Amaru can speak).
    ///
    /// Proposes every Amaru-supported version from 11 through this value. Must be a
    /// version Amaru implements (today: 11..=16). Alias: `--requestedVersion`.
    #[arg(
        long = "requested-version",
        visible_alias = "requestedVersion",
        value_name = "N",
        default_value_t = amaru_protocols::protocol_messages::version_number::VersionNumber::HIGHEST.as_u64()
    )]
    requested_version: u64,

    /// Emit machine-readable JSON instead of color human output.
    #[arg(long)]
    json: bool,
}

/// How many keep-alive pings to run and the gap between them.
#[derive(Debug, Clone, Copy)]
struct PingSpec {
    count: u32,
    interval: Duration,
}

impl FromStr for PingSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (count, interval) = parse_count_interval(s, Duration::from_secs(1), "ping", 1, 86400)?;
        Ok(Self { count, interval })
    }
}

/// Extra attempts after the first failure, and the delay between attempts.
#[derive(Debug, Clone, Copy)]
struct RetrySpec {
    /// Number of retries after the initial attempt (total attempts = `count + 1`).
    count: u32,
    interval: Duration,
}

impl FromStr for RetrySpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (count, interval) = parse_count_interval(s, Duration::from_millis(500), "retry", 1, 32)?;
        Ok(Self { count, interval })
    }
}

fn parse_count_interval(
    s: &str,
    default_interval: Duration,
    kind: &str,
    min_count: u32,
    max_count: u32,
) -> Result<(u32, Duration), String> {
    let (count_str, interval) = if let Some((count_str, interval_str)) = s.split_once(':') {
        let interval_ms: u64 = interval_str
            .parse()
            .map_err(|_| format!("invalid {kind} interval '{interval_str}' (expected milliseconds)"))?;
        if interval_ms == 0 {
            return Err(format!("{kind} interval must be >= 1 ms"));
        }
        (count_str, Duration::from_millis(interval_ms))
    } else {
        (s, default_interval)
    };

    let count: u32 = count_str
        .parse()
        .map_err(|_| format!("invalid {kind} count '{count_str}' (expected integer {min_count}..={max_count})"))?;
    if !(min_count..=max_count).contains(&count) {
        return Err(format!("{kind} count must be between {min_count} and {max_count}"));
    }

    Ok((count, interval))
}

/// Run `op` once, then up to `retry.count` more times after `retry.interval` on failure.
async fn with_retries<T, E, F, Fut>(retry: Option<RetrySpec>, mut op: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let (extra, delay) = match retry {
        Some(spec) => (spec.count, spec.interval),
        None => (0, Duration::ZERO),
    };
    let mut attempt = 0u32;
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(_err) if attempt < extra => {
                attempt += 1;
                tokio::time::sleep(delay).await;
            }
            Err(err) => return Err(err),
        }
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
        self.ping.is_some() || self.peershare || self.tip || self.observe
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
    let max_n2n_version = resolve_requested_version(args.requested_version)?;
    let color = color_enabled();
    // Stream long-running human steps as they complete; JSON stays one final document.
    let stream = !args.json;

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
        timetrack: Vec::new(),
        errors: Vec::new(),
    };

    // Shared timeline clock across query + session when `--timetrack` is set.
    let mut track_clock: Option<(Instant, Instant)> = None;
    if args.timetrack {
        let started = Instant::now();
        track_clock = Some((started, started));
    }

    if stream {
        print_probe_header(&report, color);
    }

    // --handshake: dedicated query connection listing every remote-offered N2N version.
    if actions.handshake {
        match with_retries(args.retry, || {
            session::run_version_query(
                peer,
                args.network,
                connect_timeout,
                handshake_timeout,
                max_n2n_version,
                args.timetrack,
                track_clock,
            )
        })
        .await
        {
            Ok((offered, steps)) => {
                report.handshake = Some(session::HandshakeInfo {
                    offered_versions: offered,
                    ..session::HandshakeInfo::default()
                });
                if args.timetrack {
                    report.timetrack.extend(steps);
                    if let Some((_, last)) = track_clock.as_mut() {
                        *last = Instant::now();
                    }
                }
            }
            Err(err) => report.errors.push(format!("handshake query: {err:#}")),
        }
        if stream && !actions.needs_session() {
            if let Some(hs) = &report.handshake {
                print_handshake_section(hs, color);
            }
            print_errors(&report.errors, color);
        }
    }

    if let Some(spec) = actions.ping {
        report.ping_interval_ms = Some(spec.interval.as_millis() as u64);
    }

    if actions.needs_session() {
        match with_retries(args.retry, || {
            session::run_session(session::SessionRequest {
                peer,
                network: args.network,
                connect_timeout,
                handshake_timeout,
                protocol_timeout,
                want_peershare: actions.peershare,
                want_tip: actions.tip,
                want_observe: actions.observe,
                want_ping: actions.ping.map(|s| (s.count, s.interval)),
                want_timetrack: args.timetrack,
                timetrack_continue: track_clock,
                max_n2n_version,
                peer_share_amount: 10,
            })
        })
        .await
        {
            Ok(partial) => {
                report.ping_rtts_ms = partial.ping_rtts_ms;
                // Merge Accept negotiated fields onto any prior query offered_versions.
                match (report.handshake.take(), partial.handshake) {
                    (Some(mut hs), Some(accepted)) => {
                        hs.version = accepted.version;
                        hs.network_magic = accepted.network_magic;
                        hs.initiator_only = accepted.initiator_only;
                        hs.peer_sharing = accepted.peer_sharing;
                        hs.query = accepted.query;
                        hs.peras_support = accepted.peras_support;
                        if hs.offered_versions.is_empty() {
                            hs.offered_versions = accepted.offered_versions;
                        }
                        report.handshake = Some(hs);
                    }
                    (None, accepted) => report.handshake = accepted,
                    (prior, None) => report.handshake = prior,
                }
                report.peers = partial.peers;
                report.tip = partial.tip;
                report.publications = partial.publications;
                report.errors.extend(partial.errors);
                if args.timetrack {
                    report.timetrack.extend(partial.timetrack);
                }
            }
            Err(err) => report.errors.push(format!("session: {err:#}")),
        }
        if stream {
            if let Some(hs) = &report.handshake {
                print_handshake_section(hs, color);
            }
            if !report.ping_rtts_ms.is_empty() {
                print_ping_section_buffered(&report, color);
            }
            print_session_sections(
                &report,
                color,
                /*include_pscheck*/ false,
                /*skip_handshake*/ true,
            );
        }
    } else if stream && actions.handshake {
        // handshake-only already streamed above
    }

    if stream && args.timetrack && !report.timetrack.is_empty() {
        print_timetrack_section(&report.timetrack, color);
    }

    if actions.pscheck {
        let peers = report.peers.clone().unwrap_or_default();
        let mut pscheck_header = stream && !peers.is_empty();
        for addr in peers {
            let check = run_pscheck_one(
                &addr,
                args.network,
                connect_timeout,
                handshake_timeout,
                protocol_timeout,
                max_n2n_version,
            )
            .await;
            if stream {
                if pscheck_header {
                    let (ok, _, _, _, _, reset) = color_palette(color);
                    println!("  {ok}pscheck{reset}");
                    flush_stdout();
                    pscheck_header = false;
                }
                print_pscheck_progress(&check, color);
            }
            report.peer_checks.push(check);
        }
    }

    if args.json {
        emit(&report, true, color)?;
    } else if !stream {
        // Should not happen: stream is `!json`. Kept for clarity.
        emit(&report, false, color)?;
    }
    // Human streaming already printed each section as it completed.

    if !report.errors.is_empty() {
        bail!("probe completed with errors");
    }
    Ok(())
}

async fn run_pscheck_one(
    addr: &str,
    network: NetworkName,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    protocol_timeout: Duration,
    max_n2n_version: VersionNumber,
) -> session::PeerCheck {
    let Ok(peer) = addr.parse::<Peer>() else {
        return session::PeerCheck {
            address: addr.to_string(),
            ok: false,
            detail: "invalid peer address from share".to_string(),
            ping_rtt_ms: None,
            publications: None,
        };
    };

    let ping_rtt_ms = match session::tcp_ping(peer, connect_timeout).await {
        Ok(rtt) => Some(rtt.as_millis() as u64),
        Err(err) => {
            return session::PeerCheck {
                address: addr.to_string(),
                ok: false,
                detail: format!("ping failed: {err:#}"),
                ping_rtt_ms: None,
                publications: None,
            };
        }
    };

    match session::run_session(session::SessionRequest {
        peer,
        network,
        connect_timeout,
        handshake_timeout,
        protocol_timeout,
        want_peershare: false,
        want_tip: false,
        want_observe: true,
        want_ping: None,
        want_timetrack: false,
        timetrack_continue: None,
        max_n2n_version,
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
            session::PeerCheck {
                address: addr.to_string(),
                ok,
                detail,
                ping_rtt_ms,
                publications: partial.publications,
            }
        }
        Err(err) => session::PeerCheck {
            address: addr.to_string(),
            ok: false,
            detail: format!("{err:#}"),
            ping_rtt_ms,
            publications: None,
        },
    }
}

fn emit(report: &session::ProbeReport, json: bool, color: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        print_probe_header(report, color);
        if let Some(hs) = &report.handshake {
            print_handshake_section(hs, color);
        }
        if !report.ping_rtts_ms.is_empty() {
            print_ping_section_buffered(report, color);
        }
        print_session_sections(report, color, /*include_pscheck*/ true, /*skip_handshake*/ true);
        if !report.timetrack.is_empty() {
            print_timetrack_section(&report.timetrack, color);
        }
    }
    Ok(())
}

type Palette = (&'static str, &'static str, &'static str, &'static str, &'static str, &'static str);

fn color_palette(color: bool) -> Palette {
    if color {
        ("\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[36m", "\x1b[1m", "\x1b[0m")
    } else {
        ("", "", "", "", "", "")
    }
}

fn flush_stdout() {
    let _ = io::Write::flush(&mut io::stdout());
}

fn print_probe_header(report: &session::ProbeReport, color: bool) {
    let (_, _, _, cyan, bold, reset) = color_palette(color);
    println!("{bold}probe{reset} {cyan}{}{reset} ({})", report.address, report.network);
    flush_stdout();
}

fn print_handshake_section(hs: &session::HandshakeInfo, color: bool) {
    let (ok, _, _, _, _, reset) = color_palette(color);
    println!("  {ok}handshake{reset}");
    if !hs.offered_versions.is_empty() {
        let list = hs
            .offered_versions
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!("    offered_versions: [{list}]");
    }
    if let Some(v) = hs.version {
        println!("    version:          {v}");
    }
    if let Some(m) = hs.network_magic {
        println!("    network_magic:    {m}");
    }
    if let Some(ps) = hs.peer_sharing {
        println!("    peer_sharing:     {ps}");
    }
    if let Some(io) = hs.initiator_only {
        println!("    initiator_only:   {io}");
    }
    if let Some(q) = hs.query {
        println!("    query:            {q}");
    }
    if let Some(p) = hs.peras_support {
        println!("    peras_support:    {p}");
    }
    flush_stdout();
}

/// Tip / peershare / observe (and optionally already-collected pscheck rows).
fn print_session_sections(
    report: &session::ProbeReport,
    color: bool,
    include_pscheck: bool,
    skip_handshake: bool,
) {
    let (ok, warn, _err, _, _, reset) = color_palette(color);

    if !skip_handshake
        && let Some(hs) = &report.handshake
    {
        print_handshake_section(hs, color);
    }
    if let Some(tip) = &report.tip {
        println!("  {ok}tip{reset}");
        println!("    slot:             {}", tip.slot);
        println!("    block_height:     {}", tip.block_height);
        println!("    hash:             {}", tip.hash);
    }
    if let Some(peers) = &report.peers {
        if peers.is_empty() {
            println!("  {warn}peershare{reset}  skipped (not negotiated)");
        } else {
            println!("  {ok}peershare{reset}  {} peer(s)", peers.len());
            for p in peers {
                if include_pscheck {
                    if let Some(check) = report.peer_checks.iter().find(|c| c.address == *p) {
                        print_peershare_check_line(p, check, ok, warn, reset);
                        continue;
                    }
                }
                println!("    {p}");
            }
        }
    }
    if let Some(pubs) = &report.publications {
        println!("  {ok}observe{reset}");
        print_publications_human(pubs, "    ");
    }
    if include_pscheck {
        for check in &report.peer_checks {
            if report.peers.as_ref().is_some_and(|ps| ps.iter().any(|p| p == &check.address)) {
                if let Some(pubs) = &check.publications {
                    println!("      observe {}", check.address);
                    print_publications_human(pubs, "        ");
                }
                continue;
            }
            print_orphan_pscheck(check, ok, warn, reset);
        }
    }
    print_errors(&report.errors, color);
    flush_stdout();
}

fn print_peershare_check_line(
    addr: &str,
    check: &session::PeerCheck,
    ok: &str,
    warn: &str,
    reset: &str,
) {
    let ping = match check.ping_rtt_ms {
        Some(ms) => format!("{ms} ms"),
        None => "ping failed".to_string(),
    };
    let tag = if check.ok { ok } else { warn };
    println!("    {addr}  {ping}  {tag}{}{reset}", check.detail);
    if let Some(pubs) = &check.publications {
        println!("      observe {addr}");
        print_publications_human(pubs, "        ");
    }
}

fn print_orphan_pscheck(check: &session::PeerCheck, ok: &str, warn: &str, reset: &str) {
    let tag = if check.ok { ok } else { warn };
    let ping = check.ping_rtt_ms.map(|ms| format!("{ms} ms")).unwrap_or_else(|| "-".to_string());
    println!("  {tag}pscheck{reset}  {}  ping {ping}  {}", check.address, check.detail);
    if let Some(pubs) = &check.publications {
        print_publications_human(pubs, "           ");
    }
}

/// Live line for one finished pscheck (human streaming mode).
fn print_pscheck_progress(check: &session::PeerCheck, color: bool) {
    let (ok, warn, _, _, _, reset) = color_palette(color);
    let tag = if check.ok { ok } else { warn };
    let ping = check.ping_rtt_ms.map(|ms| format!("{ms} ms")).unwrap_or_else(|| "-".to_string());
    println!("    {}  ping {ping}  {tag}{}{reset}", check.address, check.detail);
    if let Some(pubs) = &check.publications {
        print_publications_human(pubs, "      ");
    }
    flush_stdout();
}

fn print_errors(errors: &[String], color: bool) {
    if errors.is_empty() {
        return;
    }
    let (_, _, err, _, _, reset) = color_palette(color);
    for e in errors {
        println!("  {err}error{reset}   {e}");
    }
    flush_stdout();
}

fn print_timetrack_section(steps: &[session::TimeTrackStep], color: bool) {
    let (ok, _, _, _, _, reset) = color_palette(color);
    println!("  {ok}timetrack{reset}");
    println!(
        "    {:<22} {:>10} {:>10} {:>10} {:>10}  {}",
        "step", "delta_ms", "elapsed_ms", "sent", "recv", "at"
    );
    for s in steps {
        println!(
            "    {:<22} {:>10} {:>10} {:>10} {:>10}  {}",
            s.step, s.delta_ms, s.elapsed_ms, s.bytes_sent, s.bytes_recv, s.at
        );
    }
    if let Some(last) = steps.last() {
        println!(
            "    total_elapsed_ms:  {}  bytes_sent: {}  bytes_recv: {}",
            last.elapsed_ms, last.bytes_sent, last.bytes_recv
        );
    }
    flush_stdout();
}

fn format_rtt_ms(ms: f64) -> String {
    if ms >= 10.0 {
        format!("{ms:.1}")
    } else if ms >= 1.0 {
        format!("{ms:.2}")
    } else {
        format!("{ms:.3}")
    }
}

fn print_ping_section_buffered(report: &session::ProbeReport, color: bool) {
    let (ok, _, _, _, _, reset) = color_palette(color);
    let samples = &report.ping_rtts_ms;
    println!("  {ok}ping{reset}");
    if samples.len() == 1 {
        println!("    rtt:              {} ms", format_rtt_ms(samples[0]));
        return;
    }
    let min = samples.iter().copied().fold(f64::INFINITY, f64::min);
    let max = samples.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let avg = samples.iter().sum::<f64>() / samples.len() as f64;
    println!("    count:            {}", samples.len());
    if let Some(interval) = report.ping_interval_ms {
        println!("    interval:         {interval} ms");
    }
    for (i, ms) in samples.iter().enumerate() {
        println!("    {:<18} {} ms", format!("{}:", i + 1), format_rtt_ms(*ms));
    }
    println!("    min:              {} ms", format_rtt_ms(min));
    println!("    avg:              {} ms", format_rtt_ms(avg));
    println!("    max:              {} ms", format_rtt_ms(max));
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
        "node_version_minor",
        "node_version_patch",
        "node_type",
        "git_revision",
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

fn resolve_requested_version(raw: u64) -> anyhow::Result<VersionNumber> {
    let version = VersionNumber::new(raw);
    if version.is_supported() {
        return Ok(version);
    }
    let supported = VersionNumber::SUPPORTED
        .iter()
        .map(|v| v.as_u64().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    bail!(
        "unsupported --requested-version {raw}; Amaru speaks N2N versions [{supported}] (default {})",
        VersionNumber::HIGHEST.as_u64()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_spec_parses_count_and_interval() {
        let spec: RetrySpec = "2:500".parse().unwrap();
        assert_eq!(spec.count, 2);
        assert_eq!(spec.interval, Duration::from_millis(500));
    }

    #[test]
    fn retry_spec_bare_count_defaults_to_500ms() {
        let spec: RetrySpec = "3".parse().unwrap();
        assert_eq!(spec.count, 3);
        assert_eq!(spec.interval, Duration::from_millis(500));
    }

    #[test]
    fn ping_spec_bare_count_defaults_to_1s() {
        let spec: PingSpec = "5".parse().unwrap();
        assert_eq!(spec.count, 5);
        assert_eq!(spec.interval, Duration::from_secs(1));
    }

    #[tokio::test]
    async fn with_retries_succeeds_on_later_attempt() {
        let mut tries = 0u32;
        let result = with_retries(Some(RetrySpec { count: 2, interval: Duration::from_millis(1) }), || {
            tries += 1;
            async move {
                if tries < 3 {
                    Err("transient")
                } else {
                    Ok(42)
                }
            }
        })
        .await;
        assert_eq!(result, Ok(42));
        assert_eq!(tries, 3);
    }

    #[tokio::test]
    async fn with_retries_none_is_single_attempt() {
        let mut tries = 0u32;
        let result: Result<(), &str> = with_retries(None, || {
            tries += 1;
            async { Err("fail") }
        })
        .await;
        assert_eq!(result, Err("fail"));
        assert_eq!(tries, 1);
    }
}

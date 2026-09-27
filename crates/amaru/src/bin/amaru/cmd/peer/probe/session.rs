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

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use amaru_kernel::{NetworkName, Peer, Point};
use amaru_network::connection::TokioConnections;
use amaru_ouroboros::{ConnectionProvider, ConnectionsResource, in_memory_chain_store::InMemoryChainStore};
use amaru_protocols::{
    chainsync::{self, ChainSyncInitiatorMsg, InitiatorMessage as CsLocal, InitiatorResult as CsResult},
    deserializers,
    handshake::{self, HandshakeResult, RefuseReason},
    mux::{self, MuxMessage},
    observability::{
        self, InitiatorMessage as ObsLocal, InitiatorResult as ObsResult, Publication, register_observability_initiator,
    },
    peer_sharing::{PeerSharingMessage, ShareResult, register_peer_sharing_initiator},
    protocol::{Inputs, PROTO_HANDSHAKE, Role},
    protocol_messages::{version_data::PeerSharing, version_number::VersionNumber, version_table::VersionTable},
    store_effects::ResourceHeaderStore,
};
use amaru_pure_stage::{Effects, StageGraph, StageRef, Void, tokio::TokioBuilder};
use anyhow::{Context, bail};
use futures_util::StreamExt;
use serde::Serialize;
use tokio::runtime::Handle;

#[derive(Debug, Clone)]
pub struct SessionRequest {
    pub peer: Peer,
    pub network: NetworkName,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub protocol_timeout: Duration,
    pub want_handshake: bool,
    pub want_peershare: bool,
    pub want_tip: bool,
    pub want_observe: bool,
    pub peer_share_amount: u8,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HandshakeInfo {
    pub version: u64,
    pub network_magic: u64,
    pub initiator_only: bool,
    pub peer_sharing: bool,
    pub query: bool,
    pub peras_support: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ProbeReport {
    pub address: String,
    pub network: String,
    pub ping_rtt_ms: Option<u64>,
    pub handshake: Option<HandshakeInfo>,
    pub peers: Option<Vec<String>>,
    pub tip: Option<String>,
    pub publications: Option<serde_json::Value>,
    pub peer_checks: Vec<PeerCheck>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerCheck {
    pub address: String,
    pub ok: bool,
    pub detail: String,
    pub publications: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Default)]
pub struct SessionPartial {
    pub handshake: Option<HandshakeInfo>,
    pub peers: Option<Vec<String>>,
    pub tip: Option<String>,
    pub publications: Option<serde_json::Value>,
    pub errors: Vec<String>,
}

pub async fn tcp_ping(peer: Peer, timeout: Duration) -> anyhow::Result<Duration> {
    let connections = Arc::new(TokioConnections::new(65535));
    let started = Instant::now();
    let conn_id = connections.connect(peer, timeout).await.context("TCP connect")?;
    let rtt = started.elapsed();
    let _ = connections.close(conn_id).await;
    Ok(rtt)
}

pub async fn run_session(req: SessionRequest) -> anyhow::Result<SessionPartial> {
    let _guards = deserializers::register_deserializers();
    let connections = Arc::new(TokioConnections::new(65535));
    let conn_id = connections
        .connect(req.peer, req.connect_timeout)
        .await
        .context("TCP connect for session")?;

    let mut network = TokioBuilder::default();
    network.resources().put::<ConnectionsResource>(connections.clone());
    network
        .resources()
        .put::<ResourceHeaderStore>(Arc::new(InMemoryChainStore::new()) as ResourceHeaderStore);

    let (report_out, mut report_rx) = network.output::<SessionPartial>("probe_report", 4);
    let driver = network.stage("probe_driver", driver_stage);
    let driver = network.wire_up(
        driver,
        Driver {
            peer: req.peer,
            conn_id,
            magic: req.network.to_network_magic(),
            want_peershare: req.want_peershare,
            want_tip: req.want_tip,
            want_observe: req.want_observe,
            peer_share_amount: req.peer_share_amount,
            protocol_timeout: req.protocol_timeout,
            handshake_timeout: req.handshake_timeout,
            report_to: report_out,
            muxer: None,
            phase: Phase::Start,
            partial: SessionPartial::default(),
        },
    );

    if network.preload(&driver, [DriverMsg::Start]).is_err() {
        bail!("preload Start failed");
    }

    let handle = Handle::current();
    let running = network.run(handle);
    let overall = req.handshake_timeout
        + req.protocol_timeout
            * (u32::from(req.want_tip) + u32::from(req.want_peershare) + u32::from(req.want_observe)).max(1);

    let partial = match tokio::time::timeout(overall + Duration::from_secs(5), report_rx.next()).await {
        Ok(Some(report)) => report,
        Ok(None) => {
            running.abort();
            bail!("probe session ended without a report (graph shut down before result delivery)")
        }
        Err(_) => {
            running.abort();
            bail!("probe session timed out")
        }
    };

    running.abort();
    let _ = connections.close(conn_id).await;
    let _ = req.want_handshake;
    Ok(partial)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum Phase {
    Start,
    Handshaking,
    Tip,
    PeerShare,
    Observe,
    Done,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
struct Driver {
    peer: Peer,
    conn_id: amaru_ouroboros::ConnectionId,
    magic: amaru_kernel::NetworkMagic,
    want_peershare: bool,
    want_tip: bool,
    want_observe: bool,
    peer_share_amount: u8,
    protocol_timeout: Duration,
    handshake_timeout: Duration,
    report_to: StageRef<SessionPartial>,
    muxer: Option<StageRef<MuxMessage>>,
    phase: Phase,
    partial: SessionPartial,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
enum DriverMsg {
    Start,
    Handshake(HandshakeResult),
    Tip(ChainSyncInitiatorMsg),
    Share(ShareResult),
    Observe(ObsResult),
    /// Mini-protocol child exited (often expected after Done).
    ChildDied,
    /// Mux exited: connection closed, decode failure, or unknown protocol.
    MuxDied,
    StepTimeout,
}

async fn driver_stage(mut state: Driver, msg: DriverMsg, eff: Effects<DriverMsg>) -> Driver {
    // After the report is sent, ignore further mailbox traffic until the outer session aborts.
    if state.phase == Phase::Done {
        return state;
    }

    match msg {
        DriverMsg::Start => {
            let muxer = eff.stage("mux", mux::stage).await;
            let muxer = eff.supervise(muxer, DriverMsg::MuxDied);
            let muxer = eff
                .wire_up(
                    muxer,
                    mux::State::new(state.conn_id, &[(PROTO_HANDSHAKE.erase(), 5760)], Role::Initiator, state.peer),
                )
                .await;

            let hs_reply = eff.me_ref().contramap(DriverMsg::Handshake);
            let hs = eff.stage("handshake", handshake::initiator()).await;
            let hs = eff.supervise(hs, DriverMsg::ChildDied);
            let hs = eff
                .wire_up(
                    hs,
                    handshake::HandshakeInitiator::new(
                        muxer.clone(),
                        hs_reply,
                        VersionTable::v11_through(VersionNumber::V16, state.magic, true, true),
                    ),
                )
                .await;

            eff.send(
                &muxer,
                MuxMessage::Register {
                    protocol: PROTO_HANDSHAKE.erase(),
                    frame: mux::Frame::OneCborItem,
                    handler: hs.contramap(Inputs::<Void>::Network),
                    max_buffer: 5760,
                },
            )
            .await;

            state.muxer = Some(muxer);
            state.phase = Phase::Handshaking;
            eff.set_timeout_at(1, state.handshake_timeout, DriverMsg::StepTimeout).await;
            state
        }
        DriverMsg::Handshake(result) => {
            eff.clear_timeout_at(1).await;
            match result {
                HandshakeResult::Accepted(version, data) => {
                    state.partial.handshake = Some(HandshakeInfo {
                        version: version.as_u64(),
                        network_magic: data.network_magic().as_u64(),
                        initiator_only: data.initiator_only_diffusion_mode(),
                        peer_sharing: bool::from(data.peer_sharing()),
                        query: data.query(),
                        peras_support: data.peras_support(),
                    });
                    return advance_after_handshake(state, version, data.peer_sharing(), &eff).await;
                }
                HandshakeResult::Refused(reason) => {
                    state.partial.errors.push(format!("handshake refused: {}", format_refuse(&reason)));
                    return finish(state, &eff).await;
                }
                HandshakeResult::Query(table) => {
                    state.partial.errors.push(format!("handshake query (unexpected): {table}"));
                    return finish(state, &eff).await;
                }
            }
        }
        DriverMsg::Tip(msg) => {
            match msg.msg {
                CsResult::Initialize => state,
                CsResult::IntersectFound(_, tip) | CsResult::IntersectNotFound(tip) => {
                    state.partial.tip = Some(format_point(tip));
                    eff.clear_timeout_at(2).await;
                    eff.send(&msg.handler, CsLocal::Done).await;
                    advance_after_tip(state, &eff).await
                }
                CsResult::RollForward(_, tip) | CsResult::RollBackward(_, tip) => {
                    // Prefer intersect tip; keep last tip if somehow still streaming.
                    if state.partial.tip.is_none() {
                        state.partial.tip = Some(format_point(tip));
                    }
                    state
                }
                CsResult::Terminated => {
                    if state.partial.tip.is_none() {
                        state.partial.errors.push("chainsync terminated before tip".to_string());
                    }
                    eff.clear_timeout_at(2).await;
                    advance_after_tip(state, &eff).await
                }
            }
        }
        DriverMsg::Share(share) => {
            eff.clear_timeout_at(3).await;
            state.partial.peers = Some(share.peers.iter().map(|a| a.to_string()).collect());
            advance_after_peershare(state, &eff).await
        }
        DriverMsg::Observe(ObsResult::Publications(message)) => {
            eff.clear_timeout_at(4).await;
            state.partial.publications = Some(publications_json(&message));
            finish(state, &eff).await
        }
        DriverMsg::ChildDied => state,
        DriverMsg::MuxDied => {
            let hint = match state.phase {
                Phase::Observe => {
                    "mux exited during observe (connection closed, or peer has no observability on mux 11; set AMARU_OBSERVABILITY=1 on Amaru)"
                }
                Phase::Handshaking => "mux exited during handshake",
                Phase::Tip => "mux exited during tip",
                Phase::PeerShare => "mux exited during peershare",
                Phase::Start | Phase::Done => "mux exited",
            };
            state.partial.errors.push(hint.to_string());
            finish(state, &eff).await
        }
        DriverMsg::StepTimeout => {
            let label = match state.phase {
                Phase::Start => "start",
                Phase::Handshaking => "handshake",
                Phase::Tip => "tip",
                Phase::PeerShare => "peershare",
                Phase::Observe => {
                    "observe (no MsgPublications; peer may lack AMARU_OBSERVABILITY / mux 11)"
                }
                Phase::Done => "done",
            };
            state.partial.errors.push(format!("{label} timed out"));
            finish(state, &eff).await
        }
    }
}

async fn advance_after_handshake(
    mut state: Driver,
    version: VersionNumber,
    peer_sharing: PeerSharing,
    eff: &Effects<DriverMsg>,
) -> Driver {
    let Some(muxer) = state.muxer.clone() else {
        state.partial.errors.push("internal: muxer missing after handshake".to_string());
        return finish(state, eff).await;
    };

    if state.want_tip {
        state.phase = Phase::Tip;
        let pipeline = eff.me_ref().contramap(DriverMsg::Tip);
        let _ = chainsync::register_chainsync_initiator(
            &muxer,
            state.peer,
            state.conn_id,
            pipeline,
            eff,
            DriverMsg::ChildDied,
        )
        .await;
        eff.set_timeout_at(2, state.protocol_timeout, DriverMsg::StepTimeout).await;
        return state;
    }

    if state.want_peershare {
        return start_peershare(state, muxer, peer_sharing, eff).await;
    }

    if state.want_observe {
        return start_observe(state, muxer, version, eff).await;
    }

    finish(state, eff).await
}

async fn advance_after_tip(state: Driver, eff: &Effects<DriverMsg>) -> Driver {
    let Some(muxer) = state.muxer.clone() else {
        return finish(state, eff).await;
    };
    let peer_sharing = state
        .partial
        .handshake
        .as_ref()
        .map(|h| if h.peer_sharing { PeerSharing::Enabled } else { PeerSharing::Disabled })
        .unwrap_or(PeerSharing::Disabled);
    let version = state
        .partial
        .handshake
        .as_ref()
        .map(|h| VersionNumber::new(h.version))
        .unwrap_or(VersionNumber::CURRENT);

    if state.want_peershare {
        return start_peershare(state, muxer, peer_sharing, eff).await;
    }
    if state.want_observe {
        return start_observe(state, muxer, version, eff).await;
    }
    finish(state, eff).await
}

async fn advance_after_peershare(state: Driver, eff: &Effects<DriverMsg>) -> Driver {
    let Some(muxer) = state.muxer.clone() else {
        return finish(state, eff).await;
    };
    let version = state
        .partial
        .handshake
        .as_ref()
        .map(|h| VersionNumber::new(h.version))
        .unwrap_or(VersionNumber::CURRENT);
    if state.want_observe {
        return start_observe(state, muxer, version, eff).await;
    }
    finish(state, eff).await
}

async fn start_peershare(
    mut state: Driver,
    muxer: StageRef<MuxMessage>,
    peer_sharing: PeerSharing,
    eff: &Effects<DriverMsg>,
) -> Driver {
    if peer_sharing != PeerSharing::Enabled {
        state.partial.errors.push("peer-sharing not negotiated".to_string());
        let version = state
            .partial
            .handshake
            .as_ref()
            .map(|h| VersionNumber::new(h.version))
            .unwrap_or(VersionNumber::CURRENT);
        if state.want_observe {
            return start_observe(state, muxer, version, eff).await;
        }
        return finish(state, eff).await;
    }

    state.phase = Phase::PeerShare;
    let reply_to = eff.me_ref().contramap(DriverMsg::Share);
    let ps = register_peer_sharing_initiator(&muxer, state.peer, state.conn_id, eff, DriverMsg::ChildDied).await;
    eff.send(
        &ps,
        PeerSharingMessage::Start {
            amount: state.peer_share_amount,
            initial_delay: Duration::ZERO,
            interval: Duration::from_secs(3600),
            reply_to,
        },
    )
    .await;
    eff.set_timeout_at(3, state.protocol_timeout, DriverMsg::StepTimeout).await;
    state
}

async fn start_observe(
    mut state: Driver,
    muxer: StageRef<MuxMessage>,
    version: VersionNumber,
    eff: &Effects<DriverMsg>,
) -> Driver {
    if version < VersionNumber::V16 {
        state
            .partial
            .errors
            .push(format!("observability requires N2N V16+ (negotiated {})", version.as_u64()));
        return finish(state, eff).await;
    }

    state.phase = Phase::Observe;
    let reply_to = eff.me_ref().contramap(DriverMsg::Observe);
    let obs = register_observability_initiator(
        &muxer,
        state.peer,
        state.conn_id,
        Some(reply_to),
        eff,
        DriverMsg::ChildDied,
    )
    .await;
    eff.send(&obs, ObsLocal::GetPublications).await;
    eff.set_timeout_at(4, state.protocol_timeout, DriverMsg::StepTimeout).await;
    state
}

async fn finish(mut state: Driver, eff: &Effects<DriverMsg>) -> Driver {
    if state.phase == Phase::Done {
        return state;
    }
    state.phase = Phase::Done;
    // Deliver the report, then stay alive. Terminating the root stage signals graph-wide
    // abort and can kill the output stage before it forwards the report to the CLI.
    eff.send(&state.report_to, state.partial.clone()).await;
    state
}

fn format_refuse(reason: &RefuseReason) -> String {
    format!("{reason:?}")
}

fn format_point(point: Point) -> String {
    point.to_string()
}

fn publications_json(message: &observability::Message) -> serde_json::Value {
    match message {
        observability::Message::GetPublications => serde_json::json!({"type": "GetPublications"}),
        observability::Message::Publications(pubs) => {
            let items: Vec<_> = pubs.iter().map(publication_json).collect();
            serde_json::json!({"type": "Publications", "items": items})
        }
    }
}

fn publication_json(pub_: &Publication) -> serde_json::Value {
    match pub_ {
        Publication::Open { version, snapshot_slot, payload } => serde_json::json!({
            "kind": "open",
            "version": version,
            "snapshot_slot": snapshot_slot,
            "node_name": payload.node_name,
            "node_version_major": payload.node_version_major,
            "experimental": payload.experimental.iter().map(|(k, v)| {
                (k.clone(), experimental_json(v))
            }).collect::<serde_json::Map<_, _>>(),
        }),
        Publication::Encrypted {
            version,
            snapshot_slot,
            observer_public_key,
            ciphertext,
        } => serde_json::json!({
            "kind": "encrypted",
            "version": version,
            "snapshot_slot": snapshot_slot,
            "observer_public_key": hex::encode(observer_public_key),
            "ciphertext_len": ciphertext.len(),
        }),
    }
}

fn experimental_json(value: &observability::ExperimentalValue) -> serde_json::Value {
    match value {
        observability::ExperimentalValue::Text(s) => serde_json::json!(s),
        observability::ExperimentalValue::Uint(n) => serde_json::json!(n),
        observability::ExperimentalValue::Bool(b) => serde_json::json!(b),
        observability::ExperimentalValue::Bytes(b) => serde_json::json!(hex::encode(b)),
        observability::ExperimentalValue::UintArray(xs) => serde_json::json!(xs),
    }
}

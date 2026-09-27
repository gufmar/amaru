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

//! Observability mini-protocol (experimental mux id 11; draft observability-CIP).
//!
//! One-shot: `MsgGetPublications` → `MsgPublications` → Done (no Done wire message).

mod initiator;
mod messages;
mod responder;

use amaru_kernel::Peer;
use amaru_ouroboros::ConnectionId;
use amaru_pure_stage::{DeserializerGuards, Effects, StageRef};
pub use initiator::{InitiatorMessage, InitiatorResult, ObservabilityInitiator, initiator};
pub use messages::{
    ExperimentalValue, MAX_CIPHERTEXT_BYTES, MAX_MESSAGE_BYTES, MAX_PUBLICATIONS, Message, OBSERVER_PUBLIC_KEY_LEN,
    OpenPayload, PUBLICATION_VERSION, Publication,
};
pub use responder::{ObservabilityResponder, ResponderAction, ResponderResult, register_observability_responder, responder};

use crate::{
    mux::{Frame, MuxMessage},
    protocol::{PROTO_N2N_OBSERVABILITY, ProtoSpec, ProtocolState, RoleT},
};

pub fn register_deserializers() -> DeserializerGuards {
    vec![initiator::register_deserializers(), responder::register_deserializers()].into_iter().flatten().collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum State {
    Idle,
    Busy,
    Done,
}

pub fn spec<R: RoleT>() -> ProtoSpec<State, Message, R>
where
    State: ProtocolState<R, WireMsg = Message>,
{
    let mut spec = ProtoSpec::default();
    let get = || Message::GetPublications;
    let pubs = || Message::Publications(Vec::new());

    spec.init(State::Idle, get(), State::Busy);
    spec.resp(State::Busy, pubs(), State::Done);

    spec
}

/// Register the observability **initiator** (client / monitor) on the mux.
pub async fn register_observability_initiator<M: amaru_pure_stage::SendData>(
    muxer: &StageRef<MuxMessage>,
    peer: Peer,
    conn_id: ConnectionId,
    reply_to: Option<StageRef<InitiatorResult>>,
    eff: &Effects<M>,
    tombstone: M,
) -> StageRef<InitiatorMessage> {
    use crate::protocol::Inputs;

    let (state, stage) = ObservabilityInitiator::new(muxer.clone(), peer, conn_id, reply_to);
    let obs = eff.stage("observability", initiator()).await;
    let obs = eff.supervise(obs, tombstone);
    let obs = eff.wire_up(obs, (state, stage)).await;
    eff.send(
        muxer,
        MuxMessage::Register {
            protocol: PROTO_N2N_OBSERVABILITY.erase(),
            frame: Frame::OneCborItem,
            handler: obs.contramap(Inputs::<InitiatorMessage>::Network),
            max_buffer: MAX_MESSAGE_BYTES,
        },
    )
    .await;
    obs.contramap(Inputs::<InitiatorMessage>::Local)
}

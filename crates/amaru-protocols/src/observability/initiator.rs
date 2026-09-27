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

use amaru_kernel::Peer;
use amaru_ouroboros::ConnectionId;
use amaru_pure_stage::{DeserializerGuards, Effects, StageRef, Void};

use crate::{
    mux::MuxMessage,
    observability::{State, messages::Message},
    protocol::{
        Inputs, Miniprotocol, Outcome, PROTO_N2N_OBSERVABILITY, ProtocolState, Initiator, StageState, miniprotocol,
        outcome,
    },
};

pub fn register_deserializers() -> DeserializerGuards {
    vec![
        amaru_pure_stage::register_data_deserializer::<ObservabilityInitiator>().boxed(),
        amaru_pure_stage::register_data_deserializer::<(State, ObservabilityInitiator)>().boxed(),
        amaru_pure_stage::register_data_deserializer::<InitiatorMessage>().boxed(),
        amaru_pure_stage::register_data_deserializer::<InitiatorResult>().boxed(),
    ]
}

pub fn initiator() -> Miniprotocol<State, ObservabilityInitiator, Initiator> {
    miniprotocol(PROTO_N2N_OBSERVABILITY)
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InitiatorMessage {
    /// Fetch the peer's current cached publications once.
    GetPublications,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InitiatorResult {
    Publications(Message),
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ObservabilityInitiator {
    muxer: StageRef<MuxMessage>,
    #[allow(dead_code)]
    peer: Peer,
    #[allow(dead_code)]
    conn_id: ConnectionId,
    /// Optional destination for [`InitiatorResult`] (e.g. CLI probe output).
    reply_to: Option<StageRef<InitiatorResult>>,
}

impl ObservabilityInitiator {
    pub fn new(
        muxer: StageRef<MuxMessage>,
        peer: Peer,
        conn_id: ConnectionId,
        reply_to: Option<StageRef<InitiatorResult>>,
    ) -> (State, Self) {
        (State::Idle, Self { muxer, peer, conn_id, reply_to })
    }
}

impl StageState<State, Initiator> for ObservabilityInitiator {
    type LocalIn = InitiatorMessage;

    async fn local(
        self,
        proto: &State,
        input: Self::LocalIn,
        _eff: &Effects<Inputs<Self::LocalIn>>,
    ) -> anyhow::Result<(Option<InitiatorAction>, Self)> {
        match (proto, input) {
            (State::Idle, InitiatorMessage::GetPublications) => {
                Ok((Some(InitiatorAction::GetPublications), self))
            }
            (state, input) => anyhow::bail!("observability initiator local: {state:?} <- {input:?}"),
        }
    }

    async fn network(
        self,
        _proto: &State,
        input: InitiatorResult,
        eff: &Effects<Inputs<Self::LocalIn>>,
    ) -> anyhow::Result<(Option<InitiatorAction>, Self)> {
        if let Some(reply_to) = &self.reply_to {
            eff.send(reply_to, input).await;
        }
        Ok((None, self))
    }

    fn muxer(&self) -> &StageRef<MuxMessage> {
        &self.muxer
    }
}

impl ProtocolState<Initiator> for State {
    type WireMsg = Message;
    type Action = InitiatorAction;
    type Out = InitiatorResult;
    type Error = Void;

    fn init(&self) -> anyhow::Result<(Outcome<Self::WireMsg, Self::Out, Self::Error>, Self)> {
        Ok((outcome(), *self))
    }

    fn network(&self, input: Self::WireMsg) -> anyhow::Result<(Outcome<Self::WireMsg, Self::Out, Self::Error>, Self)> {
        Ok(match (self, input) {
            (State::Busy, msg @ Message::Publications(_)) => {
                (outcome().result(InitiatorResult::Publications(msg)), State::Done)
            }
            (this, input) => anyhow::bail!("observability initiator network: {this:?} <- {input:?}"),
        })
    }

    fn local(&self, input: Self::Action) -> anyhow::Result<(Outcome<Self::WireMsg, Void, Self::Error>, Self)> {
        Ok(match (self, input) {
            (State::Idle, InitiatorAction::GetPublications) => {
                (outcome().send(Message::GetPublications).want_next(), State::Busy)
            }
            (this, input) => anyhow::bail!("observability initiator action: {this:?} <- {input:?}"),
        })
    }
}

#[derive(Debug)]
pub enum InitiatorAction {
    GetPublications,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Initiator;

    #[test]
    fn test_initiator_protocol() {
        crate::observability::spec::<Initiator>().check(State::Idle, |msg| match msg {
            Message::GetPublications => Some(InitiatorAction::GetPublications),
            Message::Publications(_) => None,
        });
    }
}

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

use amaru_pure_stage::{DeserializerGuards, Effects, StageRef, Void};

use crate::{
    mux::{Frame, MuxMessage},
    observability::{State, messages::Message},
    protocol::{
        Inputs, Miniprotocol, Outcome, PROTO_N2N_OBSERVABILITY, ProtocolState, Responder, StageState, miniprotocol,
        outcome,
    },
};

pub fn register_deserializers() -> DeserializerGuards {
    vec![
        amaru_pure_stage::register_data_deserializer::<ObservabilityResponder>().boxed(),
        amaru_pure_stage::register_data_deserializer::<(State, ObservabilityResponder)>().boxed(),
        amaru_pure_stage::register_data_deserializer::<ResponderResult>().boxed(),
    ]
}

pub fn responder() -> Miniprotocol<State, ObservabilityResponder, Responder> {
    miniprotocol(PROTO_N2N_OBSERVABILITY.responder())
}

/// Register the observability **responder** (server) with a pre-built cached reply.
pub async fn register_observability_responder<M: amaru_pure_stage::SendData>(
    muxer: &StageRef<MuxMessage>,
    cached: Message,
    eff: &Effects<M>,
    tombstone: M,
) {
    use crate::protocol::Inputs;

    let (state, stage) = ObservabilityResponder::new(muxer.clone(), cached);
    let obs = eff.stage("observability-responder", responder()).await;
    let obs = eff.supervise(obs, tombstone);
    let obs = eff.wire_up(obs, (state, stage)).await;
    eff.send(
        muxer,
        MuxMessage::Register {
            protocol: PROTO_N2N_OBSERVABILITY.responder().erase(),
            frame: Frame::OneCborItem,
            handler: obs.contramap(Inputs::<Void>::Network),
            max_buffer: crate::observability::MAX_MESSAGE_BYTES,
        },
    )
    .await;
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObservabilityResponder {
    muxer: StageRef<MuxMessage>,
    /// Pre-encoded MsgPublications CBOR bytes (served verbatim on each GetPublications).
    cached: Message,
}

impl ObservabilityResponder {
    pub fn new(muxer: StageRef<MuxMessage>, cached: Message) -> (State, Self) {
        (State::Idle, Self { muxer, cached })
    }
}

impl StageState<State, Responder> for ObservabilityResponder {
    type LocalIn = Void;

    async fn local(
        self,
        _proto: &State,
        input: Self::LocalIn,
        _eff: &Effects<Inputs<Self::LocalIn>>,
    ) -> anyhow::Result<(Option<ResponderAction>, Self)> {
        match input {}
    }

    async fn network(
        self,
        _proto: &State,
        input: ResponderResult,
        _eff: &Effects<Inputs<Self::LocalIn>>,
    ) -> anyhow::Result<(Option<ResponderAction>, Self)> {
        match input {
            ResponderResult::GetPublications => {
                Ok((Some(ResponderAction::SendPublications(self.cached.clone())), self))
            }
        }
    }

    fn muxer(&self) -> &StageRef<MuxMessage> {
        &self.muxer
    }
}

impl ProtocolState<Responder> for State {
    type WireMsg = Message;
    type Action = ResponderAction;
    type Out = ResponderResult;
    type Error = Void;

    fn init(&self) -> anyhow::Result<(Outcome<Self::WireMsg, Self::Out, Self::Error>, Self)> {
        Ok((outcome().want_next(), *self))
    }

    fn network(&self, input: Self::WireMsg) -> anyhow::Result<(Outcome<Self::WireMsg, Self::Out, Self::Error>, Self)> {
        Ok(match (self, input) {
            (State::Idle, Message::GetPublications) => {
                (outcome().result(ResponderResult::GetPublications), State::Busy)
            }
            (this, input) => anyhow::bail!("observability responder network: {this:?} <- {input:?}"),
        })
    }

    fn local(&self, input: Self::Action) -> anyhow::Result<(Outcome<Self::WireMsg, Void, Self::Error>, Self)> {
        Ok(match (self, input) {
            (State::Busy, ResponderAction::SendPublications(msg)) => match msg {
                Message::Publications(_) | Message::CachedPublications(_) => (outcome().send(msg), State::Done),
                other => anyhow::bail!("observability responder expected Publications cache, got {other:?}"),
            },
            (this, input) => anyhow::bail!("observability responder action: {this:?} <- {input:?}"),
        })
    }
}

#[derive(Debug)]
pub enum ResponderAction {
    SendPublications(Message),
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ResponderResult {
    GetPublications,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Responder;

    #[test]
    fn test_responder_protocol() {
        crate::observability::spec::<Responder>().check(State::Idle, |msg| match msg {
            Message::Publications(pubs) => Some(ResponderAction::SendPublications(Message::Publications(pubs.clone()))),
            Message::CachedPublications(bytes) => {
                Some(ResponderAction::SendPublications(Message::CachedPublications(bytes.clone())))
            }
            Message::GetPublications => None,
        });
    }
}

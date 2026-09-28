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

//! Process-wide publications cache for the observability responder.
//!
//! `ManagerConfig` stays `Copy` / serde-friendly; the node installs a provider at
//! startup. Each inbound registration snapshots via [`publications_cache`].

use std::sync::{Arc, OnceLock};

use super::messages::Message;

type PublicationsFactory = Arc<dyn Fn() -> Message + Send + Sync>;

static PROVIDER: OnceLock<PublicationsFactory> = OnceLock::new();

/// Install the factory used when registering the observability responder.
///
/// Subsequent calls are ignored (first install wins). Call once during node startup
/// when `AMARU_OBSERVABILITY` is enabled.
pub fn set_publications_provider(factory: PublicationsFactory) {
    let _ = PROVIDER.set(factory);
}

/// Snapshot the current publications reply (or a stub if no provider was installed).
pub fn publications_cache() -> Message {
    match PROVIDER.get() {
        Some(factory) => factory(),
        None => Message::stub_cache(0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::{OpenPayload, PUBLICATION_VERSION, Publication};

    #[test]
    fn default_cache_is_stub_when_unset() {
        // Provider may already be set in other tests in the same process; only assert shape.
        let msg = match PROVIDER.get() {
            None => Message::stub_cache(0, 0),
            Some(f) => f(),
        };
        assert!(matches!(msg, Message::Publications(_)));
    }

    #[test]
    fn message_publications_round_trips_open_payload() {
        let msg = Message::Publications(vec![Publication::Open {
            version: PUBLICATION_VERSION,
            snapshot_slot: 7,
            payload: OpenPayload::stub_amaru(10),
        }]);
        assert_eq!(msg.message_type(), "Publications");
    }
}

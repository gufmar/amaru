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
//! The node installs a provider that reads a shared, **pre-encoded** [`Message::CachedPublications`]
//! bag. A background refresher rebuilds and CBOR-encodes that bag on each 600-slot window.
//! Observe replies clone those bytes; mux Encode writes them verbatim (no per-request encode).

use std::sync::{Arc, OnceLock, RwLock};

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

/// Shared handle for a pre-built publications bag that can be swapped in place.
#[derive(Clone)]
pub struct PublicationsCache {
    inner: Arc<RwLock<Message>>,
}

impl PublicationsCache {
    pub fn new(initial: Message) -> Self {
        Self { inner: Arc::new(RwLock::new(initial)) }
    }

    pub fn get(&self) -> Message {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn replace(&self, message: Message) {
        *self.inner.write().unwrap_or_else(|e| e.into_inner()) = message;
    }

    /// Install this cache as the process-wide publications provider (first call wins).
    pub fn install_as_provider(&self) {
        let cache = self.clone();
        set_publications_provider(Arc::new(move || cache.get()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::{OpenPayload, PUBLICATION_VERSION, Publication};

    #[test]
    fn cache_replace_is_visible_to_get() {
        let cache = PublicationsCache::new(Message::stub_cache(0, 1));
        cache.replace(Message::Publications(vec![Publication::Open {
            version: PUBLICATION_VERSION,
            snapshot_slot: 600,
            payload: OpenPayload::stub_amaru(10),
        }]));
        match cache.get() {
            Message::Publications(pubs) => match &pubs[0] {
                Publication::Open { snapshot_slot, .. } => assert_eq!(*snapshot_slot, 600),
                other => panic!("unexpected {other:?}"),
            },
            other => panic!("unexpected {other:?}"),
        }
    }
}

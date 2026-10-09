// Copyright (C) 2026 Daniil Korzh
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see https://www.gnu.org/licenses/.

//! Replacement and expiration policies for [`crate::store::MemoryCache`].
//!
//! Replacement picks a live key to drop when a shard is over its key or byte
//! cap. Expiration decides whether a key is already dead. They compose: GET
//! expires first, then records a hit; PUT inserts, then asks replacement for
//! victims while over limit.
//!
//! Add a policy by implementing the trait and a new arm on the matching
//! runtime enum. HTTP and CKV do not need to change.

use std::fmt;
use std::time::{Duration, Instant};

use crate::store::Key;

/// Process-start choice for [`ReplacementPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReplacementKind {
    #[default]
    None,
    Lru,
}

impl ReplacementKind {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "none" => Some(Self::None),
            "lru" => Some(Self::Lru),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Lru => "lru",
        }
    }

    pub fn needs_hit(self) -> bool {
        matches!(self, Self::Lru)
    }
}

impl fmt::Display for ReplacementKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Process-start choice for [`ExpirationPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExpirationKind {
    #[default]
    None,
}

impl ExpirationKind {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
        }
    }

    pub fn may_expire(self) -> bool {
        false
    }
}

impl fmt::Display for ExpirationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-entry bookkeeping for the selected expiration policy.
#[derive(Clone, Copy, Default)]
pub enum ExpirationMeta {
    #[default]
    None,
}

/// Sentinel link id: the entry is not on an LRU list.
pub const NIL_LINK: u32 = u32::MAX;

/// Which live key to drop when a shard is over its cap.
///
/// `on_insert` returns a link id stored on the map entry. Hits and removals
/// use that id, so a policy must not look the key up again.
pub trait Replacement {
    fn on_insert(&mut self, key: Key) -> u32;
    fn on_hit(&mut self, link: u32);
    fn on_remove(&mut self, link: u32);
    fn victim(&mut self) -> Option<Key>;
}

/// Whether a stored key is already dead.
pub trait Expiration {
    type Meta: Default + Copy;
    fn on_put(&mut self, meta: &mut Self::Meta, ttl: Option<Duration>, now: Instant);
    fn is_expired(&self, meta: &Self::Meta, now: Instant) -> bool;
}

pub struct NoneReplacement;

impl Replacement for NoneReplacement {
    fn on_insert(&mut self, _key: Key) -> u32 {
        NIL_LINK
    }
    fn on_hit(&mut self, _link: u32) {}
    fn on_remove(&mut self, _link: u32) {}
    fn victim(&mut self) -> Option<Key> {
        None
    }
}

pub struct NoneExpiration;

impl Expiration for NoneExpiration {
    type Meta = ();

    fn on_put(&mut self, _meta: &mut (), _ttl: Option<Duration>, _now: Instant) {}

    fn is_expired(&self, _meta: &(), _now: Instant) -> bool {
        false
    }
}

struct LruNode {
    key: Key,
    prev: u32,
    next: u32,
}

/// Intrusive list, MRU at `head`, LRU at `tail`.
///
/// Nodes live in a dense `Vec`. The map entry stores the index, so a hit is
/// a few writes and not a second hash lookup.
pub struct LruReplacement {
    nodes: Vec<LruNode>,
    free: Vec<u32>,
    head: u32,
    tail: u32,
}

impl LruReplacement {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            nodes: Vec::with_capacity(capacity),
            free: Vec::new(),
            head: NIL_LINK,
            tail: NIL_LINK,
        }
    }

    fn detach(&mut self, idx: u32) {
        let node = &self.nodes[idx as usize];
        let prev = node.prev;
        let next = node.next;
        if prev == NIL_LINK {
            self.head = next;
        } else {
            self.nodes[prev as usize].next = next;
        }
        if next == NIL_LINK {
            self.tail = prev;
        } else {
            self.nodes[next as usize].prev = prev;
        }
    }

    fn attach_mru(&mut self, idx: u32) {
        let old_head = self.head;
        {
            let node = &mut self.nodes[idx as usize];
            node.prev = NIL_LINK;
            node.next = old_head;
        }
        if old_head == NIL_LINK {
            self.tail = idx;
        } else {
            self.nodes[old_head as usize].prev = idx;
        }
        self.head = idx;
    }
}

impl Default for LruReplacement {
    fn default() -> Self {
        Self::with_capacity(0)
    }
}

impl Replacement for LruReplacement {
    fn on_insert(&mut self, key: Key) -> u32 {
        let idx = if let Some(idx) = self.free.pop() {
            self.nodes[idx as usize].key = key;
            idx
        } else {
            let idx = u32::try_from(self.nodes.len()).expect("lru node count");
            self.nodes.push(LruNode {
                key,
                prev: NIL_LINK,
                next: NIL_LINK,
            });
            idx
        };
        self.attach_mru(idx);
        idx
    }

    fn on_hit(&mut self, link: u32) {
        if link == NIL_LINK || link == self.head {
            return;
        }
        self.detach(link);
        self.attach_mru(link);
    }

    fn on_remove(&mut self, link: u32) {
        if link == NIL_LINK {
            return;
        }
        self.detach(link);
        self.free.push(link);
    }

    fn victim(&mut self) -> Option<Key> {
        if self.tail == NIL_LINK {
            None
        } else {
            Some(self.nodes[self.tail as usize].key)
        }
    }
}

/// Runtime replacement selected at process start. Not a `dyn` object.
pub enum ReplacementPolicy {
    None(NoneReplacement),
    Lru(LruReplacement),
}

impl ReplacementPolicy {
    pub fn new(kind: ReplacementKind, capacity: usize) -> Self {
        match kind {
            ReplacementKind::None => Self::None(NoneReplacement),
            ReplacementKind::Lru => Self::Lru(LruReplacement::with_capacity(capacity)),
        }
    }
}

impl Replacement for ReplacementPolicy {
    fn on_insert(&mut self, key: Key) -> u32 {
        match self {
            Self::None(policy) => policy.on_insert(key),
            Self::Lru(policy) => policy.on_insert(key),
        }
    }

    fn on_hit(&mut self, link: u32) {
        match self {
            Self::None(policy) => policy.on_hit(link),
            Self::Lru(policy) => policy.on_hit(link),
        }
    }

    fn on_remove(&mut self, link: u32) {
        match self {
            Self::None(policy) => policy.on_remove(link),
            Self::Lru(policy) => policy.on_remove(link),
        }
    }

    fn victim(&mut self) -> Option<Key> {
        match self {
            Self::None(policy) => policy.victim(),
            Self::Lru(policy) => policy.victim(),
        }
    }
}

/// Runtime expiration selected at process start. Not a `dyn` object.
pub enum ExpirationPolicy {
    None(NoneExpiration),
}

impl ExpirationPolicy {
    pub fn new(kind: ExpirationKind) -> Self {
        match kind {
            ExpirationKind::None => Self::None(NoneExpiration),
        }
    }

    pub fn new_meta(&self) -> ExpirationMeta {
        match self {
            Self::None(_) => ExpirationMeta::None,
        }
    }

    pub fn may_expire(&self) -> bool {
        match self {
            Self::None(_) => ExpirationKind::None.may_expire(),
        }
    }

    pub fn on_put(&mut self, meta: &mut ExpirationMeta, ttl: Option<Duration>, now: Instant) {
        match (self, meta) {
            (Self::None(policy), ExpirationMeta::None) => {
                let mut unit = ();
                policy.on_put(&mut unit, ttl, now);
            }
        }
    }

    pub fn is_expired(&self, meta: &ExpirationMeta, now: Instant) -> bool {
        match (self, meta) {
            (Self::None(policy), ExpirationMeta::None) => policy.is_expired(&(), now),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Key;

    fn key(raw: &str) -> Key {
        Key::parse(raw).unwrap()
    }

    #[test]
    fn kinds_parse_and_reject_unknown() {
        assert_eq!(ReplacementKind::parse("none"), Some(ReplacementKind::None));
        assert_eq!(ReplacementKind::parse("lru"), Some(ReplacementKind::Lru));
        assert_eq!(ReplacementKind::parse("lfu"), None);
        assert_eq!(ExpirationKind::parse("none"), Some(ExpirationKind::None));
        assert_eq!(ExpirationKind::parse("ttl"), None);
    }

    #[test]
    fn none_replacement_never_picks_a_victim() {
        let mut policy = NoneReplacement;
        let link = policy.on_insert(key("a"));
        policy.on_hit(link);
        policy.on_remove(link);
        assert!(policy.victim().is_none());
    }

    #[test]
    fn none_expiration_ignores_ttl() {
        let mut policy = NoneExpiration;
        let mut meta = ();
        policy.on_put(&mut meta, Some(Duration::from_secs(1)), Instant::now());
        assert!(!policy.is_expired(&meta, Instant::now()));
    }

    #[test]
    fn lru_evicts_oldest_untouched_key() {
        let mut lru = LruReplacement::with_capacity(4);
        let a = lru.on_insert(key("a"));
        let b = lru.on_insert(key("b"));
        let _c = lru.on_insert(key("c"));
        assert_eq!(lru.victim(), Some(key("a")));
        lru.on_hit(a);
        assert_eq!(lru.victim(), Some(key("b")));
        lru.on_remove(b);
        assert_eq!(lru.victim(), Some(key("c")));
    }

    #[test]
    fn lru_hit_on_mru_is_a_noop() {
        let mut lru = LruReplacement::with_capacity(2);
        let _a = lru.on_insert(key("a"));
        let b = lru.on_insert(key("b"));
        lru.on_hit(b);
        assert_eq!(lru.victim(), Some(key("a")));
    }

    #[test]
    fn lru_overwrite_moves_to_mru() {
        let mut lru = LruReplacement::with_capacity(2);
        let a = lru.on_insert(key("a"));
        let _b = lru.on_insert(key("b"));
        lru.on_hit(a);
        assert_eq!(lru.victim(), Some(key("b")));
    }
}

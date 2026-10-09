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

//! Process-local RAM key-value store.
//!
//! Values are opaque bytes: callers serialize and deserialize. Keys are strings
//! measured in bytes, not characters, and are stored inline (no heap allocation
//! for the key).

use std::alloc::{Layout, alloc, dealloc, handle_alloc_error};
use std::cell::Cell;
use std::ffi::c_void;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use ahash::RandomState;
use hashbrown::HashMap;
use hashbrown::hash_map::RawEntryMut;
use parking_lot::{Mutex, RwLock};

use crate::policy::{
    ExpirationKind, ExpirationMeta, ExpirationPolicy, Replacement, ReplacementKind,
    ReplacementPolicy,
};

/// Architecture limit: keys are at most 40 bytes.
pub const MAX_KEY_BYTES: usize = 40;

/// Architecture limit: values are at most 5 MiB.
pub const MAX_VALUE_BYTES: usize = 5 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    EmptyKey,
    KeyTooLong,
    ValueTooLarge,
}

/// Fixed-size cache key. Validated once at the HTTP edge, then passed by value.
#[derive(Clone, Copy, Debug)]
pub struct Key {
    len: u8,
    data: [u8; MAX_KEY_BYTES],
}

impl Key {
    pub fn parse(raw: &str) -> Result<Self, StoreError> {
        Self::from_bytes(raw.as_bytes())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.is_empty() {
            return Err(StoreError::EmptyKey);
        }
        if bytes.len() > MAX_KEY_BYTES {
            return Err(StoreError::KeyTooLong);
        }
        let mut data = [0u8; MAX_KEY_BYTES];
        data[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            len: bytes.len() as u8,
            data,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..usize::from(self.len)]
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Key {}

impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

const PAGE_SIZE: usize = 1024 * 1024;
const HEADER_LEN: usize = 8;
const DEDICATED_CLASS: u8 = 255;
/// Chunk sizes. 16-byte steps for tiny values, then ~1.25× so a payload is not
/// rounded up a full power of two. A 128-byte value plus the 8-byte header
/// still lands in a 144-byte chunk.
const CLASS_SIZES: [usize; 51] = [
    16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256, 288, 320, 384, 448,
    512, 640, 768, 896, 1024, 1280, 1536, 1792, 2048, 2560, 3072, 3584, 4096, 5120, 6144, 7168,
    8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131_072, 196_608, 262_144, 393_216,
    524_288, 786_432, 1_048_576,
];

const _: () = {
    assert!(CLASS_SIZES.len() < DEDICATED_CLASS as usize);
    assert!(CLASS_SIZES[0] >= HEADER_LEN);
    assert!(CLASS_SIZES[CLASS_SIZES.len() - 1] == PAGE_SIZE);
    let mut i = 1;
    while i < CLASS_SIZES.len() {
        assert!(CLASS_SIZES[i] > CLASS_SIZES[i - 1]);
        assert!(CLASS_SIZES[i] <= PAGE_SIZE);
        i += 1;
    }
};

#[derive(Clone, Copy)]
struct ChunkId {
    header: NonNull<AtomicU32>,
    class: u8,
    index: u32,
}

unsafe impl Send for ChunkId {}
unsafe impl Sync for ChunkId {}

struct ClassState {
    chunk_size: usize,
    chunks_per_page: usize,
    pages: Vec<NonNull<u8>>,
    free: Vec<u32>,
    bump: u32,
}

struct DedicatedSlot {
    ptr: NonNull<u8>,
    layout: Layout,
}

struct Dedicated {
    slots: Vec<Option<DedicatedSlot>>,
    free: Vec<u32>,
}

struct SlabAlloc {
    classes: [Mutex<ClassState>; CLASS_SIZES.len()],
    dedicated: Mutex<Dedicated>,
}

// Page bytes are owned here. The mutex is the only way to reach them.
unsafe impl Send for ClassState {}
unsafe impl Sync for ClassState {}
unsafe impl Send for Dedicated {}
unsafe impl Sync for Dedicated {}

struct Entry {
    id: ChunkId,
    charge: u32,
    exp: ExpirationMeta,
    link: u32,
}

struct ShardInner {
    map: HashMap<Key, Entry, RandomState>,
    /// Same seed as [`MemoryCache::hasher`], so a lookup hashes the key once.
    hasher: RandomState,
    replacement: ReplacementPolicy,
    expiration: ExpirationPolicy,
    len: usize,
    bytes: usize,
    max_keys: usize,
    max_bytes: usize,
}

impl ShardInner {
    fn hash_of(&self, key: &Key) -> u64 {
        self.hasher.hash_one(key)
    }

    fn lookup(&self, hash: u64, key: &Key) -> Option<&Entry> {
        self.map
            .raw_entry()
            .from_key_hashed_nocheck(hash, key)
            .map(|(_, entry)| entry)
    }

    fn take(&mut self, hash: u64, key: &Key) -> Option<Entry> {
        match self.map.raw_entry_mut().from_key_hashed_nocheck(hash, key) {
            RawEntryMut::Occupied(entry) => Some(entry.remove_entry().1),
            RawEntryMut::Vacant(_) => None,
        }
    }

    fn over_limit(&self) -> bool {
        (self.max_keys > 0 && self.len > self.max_keys)
            || (self.max_bytes > 0 && self.bytes > self.max_bytes)
    }
}

struct Shard {
    inner: RwLock<ShardInner>,
}

impl Shard {
    fn with_ref<R>(&self, f: impl FnOnce(&ShardInner) -> R) -> R {
        f(&self.inner.read())
    }

    fn with_mut<R>(&self, f: impl FnOnce(&mut ShardInner) -> R) -> R {
        f(&mut self.inner.write())
    }
}

/// GETs that update LRU. `1` updates every GET.
pub const LRU_HIT_SAMPLE: u32 = 32;

thread_local! {
    static HIT_TICK: Cell<u32> = const { Cell::new(0) };
}

/// How to construct [`MemoryCache`].
pub struct StoreOptions {
    pub max_value_bytes: usize,
    /// HashMap pre-size. Not a max.
    pub capacity: usize,
    pub max_keys: usize,
    pub max_bytes: usize,
    pub replacement: ReplacementKind,
    pub expiration: ExpirationKind,
    /// `None` picks a power of two from CPU count. Tests pass `Some(1)`.
    pub shards: Option<usize>,
    /// Update replacement on 1 of every this many GETs. `1` updates every GET.
    pub hit_sample: u32,
}

/// Optional fields for [`MemoryCache::put_with`]. HTTP and CKV leave this default.
#[derive(Clone, Copy, Default)]
pub struct PutOptions {
    pub ttl: Option<Duration>,
}

pub struct MemoryCache {
    shards: Box<[Shard]>,
    slabs: SlabAlloc,
    mask: usize,
    hasher: RandomState,
    max_value_bytes: usize,
    max_bytes: usize,
    shard_max_bytes: usize,
    touch_on_get: bool,
    expire_on_get: bool,
    hit_sample: u32,
}

/// Slab chunk that is not yet in the map. Drop releases it unless [`commit`](Self::commit).
struct Uncommitted<'a> {
    slabs: &'a SlabAlloc,
    id: ChunkId,
    committed: bool,
}

impl<'a> Uncommitted<'a> {
    fn new(slabs: &'a SlabAlloc, id: ChunkId) -> Self {
        Self {
            slabs,
            id,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }

    fn revoke(&mut self) {
        self.committed = false;
    }
}

impl Drop for Uncommitted<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.slabs.release(self.id);
        }
    }
}

/// Evicted or overwritten chunks. Drop always returns them to the slab.
struct ToRelease<'a> {
    slabs: &'a SlabAlloc,
    ids: Vec<ChunkId>,
}

impl Drop for ToRelease<'_> {
    fn drop(&mut self) {
        for id in self.ids.drain(..) {
            self.slabs.release(id);
        }
    }
}

/// Borrow of a stored value. Dropping it releases one slab reference.
///
/// The guard borrows the cache, so it cannot outlive [`MemoryCache`].
pub struct ValueGuard<'a> {
    data: NonNull<u8>,
    len: u32,
    id: ChunkId,
    slabs: &'a SlabAlloc,
}

impl Deref for ValueGuard<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.data.as_ptr(), self.len as usize) }
    }
}

impl Drop for ValueGuard<'_> {
    fn drop(&mut self) {
        self.slabs.release(self.id);
    }
}

unsafe impl Send for ValueGuard<'_> {}

impl MemoryCache {
    pub fn new(max_value_bytes: usize) -> Self {
        Self::with_capacity(max_value_bytes, 0)
    }

    pub fn with_capacity(max_value_bytes: usize, capacity: usize) -> Self {
        Self::open(StoreOptions {
            max_value_bytes,
            capacity,
            max_keys: 0,
            max_bytes: 0,
            replacement: ReplacementKind::None,
            expiration: ExpirationKind::None,
            shards: None,
            hit_sample: 1,
        })
    }

    pub fn open(opts: StoreOptions) -> Self {
        assert!(
            (1..=MAX_VALUE_BYTES).contains(&opts.max_value_bytes),
            "value limit must be between 1 and {MAX_VALUE_BYTES} bytes"
        );
        let n = match opts.shards {
            Some(n) => n.max(1).next_power_of_two(),
            None => shard_count(),
        };
        let per_shard = if opts.capacity == 0 {
            0
        } else {
            opts.capacity.div_ceil(n)
        };
        let max_keys = if opts.max_keys == 0 {
            0
        } else {
            opts.max_keys.div_ceil(n)
        };
        let shard_max_bytes = if opts.max_bytes == 0 {
            0
        } else {
            opts.max_bytes.div_ceil(n)
        };
        let replacement = opts.replacement;
        let expiration = opts.expiration;
        let expire_on_get = expiration.may_expire();
        let touch_on_get = replacement.needs_hit() || expire_on_get;
        let hasher = RandomState::new();
        let shards = (0..n)
            .map(|_| {
                let shard_hasher = hasher.clone();
                let map = if per_shard == 0 {
                    HashMap::with_hasher(shard_hasher.clone())
                } else {
                    HashMap::with_capacity_and_hasher(per_shard, shard_hasher.clone())
                };
                Shard {
                    inner: RwLock::new(ShardInner {
                        map,
                        hasher: shard_hasher,
                        replacement: ReplacementPolicy::new(replacement, per_shard),
                        expiration: ExpirationPolicy::new(expiration),
                        len: 0,
                        bytes: 0,
                        max_keys,
                        max_bytes: shard_max_bytes,
                    }),
                }
            })
            .collect();
        let hit_sample = if touch_on_get {
            opts.hit_sample.max(1)
        } else {
            1
        };
        Self {
            shards,
            slabs: SlabAlloc::new(),
            mask: n - 1,
            hasher,
            max_value_bytes: opts.max_value_bytes,
            max_bytes: opts.max_bytes,
            shard_max_bytes,
            touch_on_get,
            expire_on_get,
            hit_sample,
        }
    }

    fn locate(&self, key: &Key) -> (u64, &Shard) {
        let hash = self.hasher.hash_one(key);
        (hash, &self.shards[(hash as usize) & self.mask])
    }

    pub fn get(&self, key: Key) -> Option<ValueGuard<'_>> {
        if self.expire_on_get || (self.touch_on_get && self.sampled_hit()) {
            self.get_touch(key)
        } else {
            self.get_fast(key)
        }
    }

    fn sampled_hit(&self) -> bool {
        if self.hit_sample <= 1 {
            return true;
        }
        HIT_TICK.with(|tick| {
            let n = tick.get().wrapping_add(1);
            tick.set(n);
            n % self.hit_sample == 0
        })
    }

    fn get_fast(&self, key: Key) -> Option<ValueGuard<'_>> {
        let (hash, shard) = self.locate(&key);
        let viewed = shard.with_ref(|inner| {
            let id = inner.lookup(hash, &key)?.id;
            Some(view(id))
        })?;
        Some(self.guard(viewed))
    }

    fn get_touch(&self, key: Key) -> Option<ValueGuard<'_>> {
        enum Touch {
            Hit(View),
            Expired(ChunkId),
            Miss,
        }
        let (hash, shard) = self.locate(&key);
        let touch = shard.with_mut(|inner| {
            let (id, exp, link) = {
                let Some(entry) = inner.lookup(hash, &key) else {
                    return Touch::Miss;
                };
                (entry.id, entry.exp, entry.link)
            };
            if inner.expiration.may_expire() && inner.expiration.is_expired(&exp, Instant::now()) {
                let entry = inner.take(hash, &key).expect("key was present");
                inner.replacement.on_remove(entry.link);
                inner.len -= 1;
                inner.bytes -= entry.charge as usize;
                return Touch::Expired(entry.id);
            }
            inner.replacement.on_hit(link);
            Touch::Hit(view(id))
        });
        match touch {
            Touch::Hit(viewed) => Some(self.guard(viewed)),
            Touch::Expired(id) => {
                self.slabs.release(id);
                None
            }
            Touch::Miss => None,
        }
    }

    fn guard<'a>(&'a self, viewed: View) -> ValueGuard<'a> {
        ValueGuard {
            data: viewed.data,
            len: viewed.len,
            id: viewed.id,
            slabs: &self.slabs,
        }
    }

    pub fn put(&self, key: Key, value: &[u8]) -> Result<(), StoreError> {
        self.put_with(key, value, PutOptions::default())
    }

    pub fn put_with(&self, key: Key, value: &[u8], opts: PutOptions) -> Result<(), StoreError> {
        if value.len() > self.max_value_bytes {
            return Err(StoreError::ValueTooLarge);
        }
        let charge = charge_bytes(value.len());
        if self.max_bytes > 0 && charge > self.max_bytes {
            return Err(StoreError::ValueTooLarge);
        }
        if self.shard_max_bytes > 0 && charge > self.shard_max_bytes {
            return Err(StoreError::ValueTooLarge);
        }
        let mut pending = Uncommitted::new(&self.slabs, self.slabs.insert(value));
        let mut released = ToRelease {
            slabs: &self.slabs,
            ids: Vec::new(),
        };
        let mut accepted = false;
        let (hash, shard) = self.locate(&key);
        shard.with_mut(|inner| {
            let mut exp = inner.expiration.new_meta();
            if inner.expiration.may_expire() {
                inner.expiration.on_put(&mut exp, opts.ttl, Instant::now());
            }
            struct Overwrite {
                old_id: ChunkId,
                old_charge: u32,
                old_exp: ExpirationMeta,
            }
            let overwritten = match inner
                .map
                .raw_entry_mut()
                .from_key_hashed_nocheck(hash, &key)
            {
                RawEntryMut::Occupied(entry) => {
                    let existing = entry.into_mut();
                    let old = Overwrite {
                        old_id: existing.id,
                        old_charge: existing.charge,
                        old_exp: existing.exp,
                    };
                    let link = existing.link;
                    existing.id = pending.id;
                    existing.charge = charge as u32;
                    existing.exp = exp;
                    inner.bytes = inner.bytes - old.old_charge as usize + charge;
                    inner.replacement.on_hit(link);
                    released.ids.push(old.old_id);
                    pending.commit();
                    Some(old)
                }
                RawEntryMut::Vacant(entry) => {
                    let link = inner.replacement.on_insert(key);
                    entry.insert_hashed_nocheck(
                        hash,
                        key,
                        Entry {
                            id: pending.id,
                            charge: charge as u32,
                            exp,
                            link,
                        },
                    );
                    inner.len += 1;
                    inner.bytes += charge;
                    pending.commit();
                    None
                }
            };
            let mut rollback = false;
            while inner.over_limit() {
                let Some(victim) = inner.replacement.victim() else {
                    rollback = true;
                    break;
                };
                if victim == key {
                    rollback = true;
                    break;
                }
                let vhash = inner.hash_of(&victim);
                let Some(old) = inner.take(vhash, &victim) else {
                    rollback = true;
                    break;
                };
                inner.replacement.on_remove(old.link);
                inner.len -= 1;
                inner.bytes -= old.charge as usize;
                released.ids.push(old.id);
            }
            if rollback {
                pending.revoke();
                if let Some(old) = overwritten {
                    let existing = match inner
                        .map
                        .raw_entry_mut()
                        .from_key_hashed_nocheck(hash, &key)
                    {
                        RawEntryMut::Occupied(entry) => entry.into_mut(),
                        RawEntryMut::Vacant(_) => panic!("overwritten key stays in the map"),
                    };
                    existing.id = old.old_id;
                    existing.charge = old.old_charge;
                    existing.exp = old.old_exp;
                    inner.bytes = inner.bytes - charge + old.old_charge as usize;
                    released
                        .ids
                        .retain(|id| id.header.as_ptr() != old.old_id.header.as_ptr());
                } else if let Some(entry) = inner.take(hash, &key) {
                    inner.replacement.on_remove(entry.link);
                    inner.len -= 1;
                    inner.bytes -= charge;
                }
            } else {
                accepted = true;
            }
        });
        drop(released);
        if accepted {
            Ok(())
        } else {
            Err(StoreError::ValueTooLarge)
        }
    }

    pub fn delete(&self, key: Key) -> bool {
        let (hash, shard) = self.locate(&key);
        let old = shard.with_mut(|inner| {
            let old = inner.take(hash, &key);
            if let Some(old) = &old {
                inner.replacement.on_remove(old.link);
                inner.len -= 1;
                inner.bytes -= old.charge as usize;
            }
            old
        });
        if let Some(old) = old {
            self.slabs.release(old.id);
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    fn slab_page_count(&self) -> usize {
        self.slabs.page_count()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.with_ref(|inner| inner.len))
            .sum()
    }
}

struct View {
    data: NonNull<u8>,
    len: u32,
    id: ChunkId,
}

/// Bump the slab refcount. Call while the map still owns `id`.
fn view(id: ChunkId) -> View {
    let prev = unsafe { id.header.as_ref().fetch_add(1, Ordering::Relaxed) };
    if prev == 0 || prev == u32::MAX {
        std::process::abort();
    }
    let base = id.header.cast::<u8>().as_ptr();
    let len = unsafe { base.add(4).cast::<u32>().read() };
    let data = unsafe { NonNull::new_unchecked(base.add(HEADER_LEN)) };
    View { data, len, id }
}

impl SlabAlloc {
    fn new() -> Self {
        Self {
            classes: std::array::from_fn(|class| {
                let chunk_size = CLASS_SIZES[class];
                Mutex::new(ClassState {
                    chunk_size,
                    chunks_per_page: PAGE_SIZE / chunk_size,
                    pages: Vec::new(),
                    free: Vec::new(),
                    bump: 0,
                })
            }),
            dedicated: Mutex::new(Dedicated {
                slots: Vec::new(),
                free: Vec::new(),
            }),
        }
    }

    fn insert(&self, value: &[u8]) -> ChunkId {
        match class_index(value.len()) {
            Some(class) => self.insert_class(class, value),
            None => self.insert_dedicated(value),
        }
    }

    fn insert_class(&self, class: usize, value: &[u8]) -> ChunkId {
        let (index, ptr) = {
            let mut state = self.classes[class].lock();
            let index = state.alloc_index();
            let ptr = state.chunk_ptr(index);
            (index, ptr)
        };
        unsafe { write_chunk(ptr, value) };
        ChunkId {
            header: ptr.cast(),
            class: class as u8,
            index,
        }
    }

    fn insert_dedicated(&self, value: &[u8]) -> ChunkId {
        let layout = Layout::from_size_align(HEADER_LEN + value.len(), 8)
            .expect("value length fits a layout");
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            handle_alloc_error(layout);
        }
        let ptr = unsafe { NonNull::new_unchecked(ptr) };
        unsafe { write_chunk(ptr, value) };
        let mut dedicated = self.dedicated.lock();
        let index = if let Some(index) = dedicated.free.pop() {
            dedicated.slots[index as usize] = Some(DedicatedSlot { ptr, layout });
            index
        } else {
            let index = u32::try_from(dedicated.slots.len()).expect("dedicated slot count");
            dedicated.slots.push(Some(DedicatedSlot { ptr, layout }));
            index
        };
        ChunkId {
            header: ptr.cast(),
            class: DEDICATED_CLASS,
            index,
        }
    }

    fn release(&self, id: ChunkId) {
        let prev = unsafe { id.header.as_ref().fetch_sub(1, Ordering::AcqRel) };
        if prev == 0 {
            std::process::abort();
        }
        if prev != 1 {
            return;
        }
        if id.class == DEDICATED_CLASS {
            let mut dedicated = self.dedicated.lock();
            if let Some(slot) = dedicated.slots[id.index as usize].take() {
                unsafe { dealloc(slot.ptr.as_ptr(), slot.layout) };
            }
            dedicated.free.push(id.index);
        } else {
            self.classes[id.class as usize].lock().free.push(id.index);
        }
    }

    #[cfg(test)]
    fn page_count(&self) -> usize {
        self.classes
            .iter()
            .map(|class| class.lock().pages.len())
            .sum()
    }
}

impl ClassState {
    fn alloc_index(&mut self) -> u32 {
        if let Some(index) = self.free.pop() {
            return index;
        }
        if self.bump as usize == self.pages.len() * self.chunks_per_page {
            self.add_page();
        }
        let index = self.bump;
        self.bump += 1;
        index
    }

    fn add_page(&mut self) {
        let ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                PAGE_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            )
        };
        if ptr.is_null() || ptr == !0usize as *mut c_void {
            handle_alloc_error(page_layout());
        }
        self.pages
            .push(unsafe { NonNull::new_unchecked(ptr.cast()) });
    }

    fn chunk_ptr(&self, index: u32) -> NonNull<u8> {
        let index = index as usize;
        let page = index / self.chunks_per_page;
        let slot = index % self.chunks_per_page;
        unsafe { NonNull::new_unchecked(self.pages[page].as_ptr().add(slot * self.chunk_size)) }
    }
}

impl Drop for SlabAlloc {
    fn drop(&mut self) {
        for class in &mut self.classes {
            for page in class.get_mut().pages.drain(..) {
                unsafe {
                    munmap(page.as_ptr().cast(), PAGE_SIZE);
                }
            }
        }
        for slot in self.dedicated.get_mut().slots.drain(..).flatten() {
            unsafe { dealloc(slot.ptr.as_ptr(), slot.layout) };
        }
    }
}

fn class_index(value_len: usize) -> Option<usize> {
    let need = HEADER_LEN + value_len;
    if need > PAGE_SIZE {
        return None;
    }
    CLASS_SIZES.iter().position(|size| *size >= need)
}

fn charge_bytes(value_len: usize) -> usize {
    match class_index(value_len) {
        Some(class) => CLASS_SIZES[class],
        None => Layout::from_size_align(HEADER_LEN + value_len, 8)
            .expect("value length fits a layout")
            .size(),
    }
}

fn page_layout() -> Layout {
    Layout::from_size_align(PAGE_SIZE, 8).expect("page layout")
}

const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const MAP_PRIVATE: i32 = 0x02;
#[cfg(target_os = "macos")]
const MAP_ANON: i32 = 0x1000;
#[cfg(not(target_os = "macos"))]
const MAP_ANON: i32 = 0x20;

unsafe extern "C" {
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
}

/// # Safety
/// `ptr` must point at a writable chunk of at least `HEADER_LEN + value.len()` bytes.
unsafe fn write_chunk(ptr: NonNull<u8>, value: &[u8]) {
    unsafe {
        ptr.cast::<AtomicU32>().write(AtomicU32::new(1));
        ptr.as_ptr().add(4).cast::<u32>().write(value.len() as u32);
        if !value.is_empty() {
            std::ptr::copy_nonoverlapping(
                value.as_ptr(),
                ptr.as_ptr().add(HEADER_LEN),
                value.len(),
            );
        }
    }
}

fn shard_count() -> usize {
    64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(max_value_bytes: usize) -> MemoryCache {
        MemoryCache::new(max_value_bytes)
    }

    fn key(raw: &str) -> Key {
        Key::parse(raw).unwrap()
    }

    #[test]
    fn put_get_overwrite_and_delete() {
        let cache = cache(32);
        assert!(cache.get(key("user")).is_none());
        cache.put(key("user"), b"one").unwrap();
        assert_eq!(cache.get(key("user")).unwrap().as_ref(), b"one");
        let held = cache.get(key("user")).unwrap();
        cache.put(key("user"), b"two").unwrap();
        assert_eq!(held.as_ref(), b"one");
        assert_eq!(cache.get(key("user")).unwrap().as_ref(), b"two");
        drop(held);
        assert!(cache.delete(key("user")));
        assert!(cache.get(key("user")).is_none());
        assert!(!cache.delete(key("user")));
    }

    #[test]
    fn empty_value_is_stored() {
        let cache = cache(8);
        cache.put(key("k"), b"").unwrap();
        assert_eq!(cache.get(key("k")).unwrap().len(), 0);
    }

    #[test]
    fn rejects_empty_and_overlong_keys() {
        assert_eq!(Key::parse(""), Err(StoreError::EmptyKey));
        let valid = "a".repeat(MAX_KEY_BYTES);
        assert!(Key::parse(&valid).is_ok());
        let too_long = "a".repeat(MAX_KEY_BYTES + 1);
        assert_eq!(Key::parse(&too_long), Err(StoreError::KeyTooLong));
    }

    #[test]
    fn key_limit_is_bytes_not_chars() {
        let cache = cache(8);
        let raw = "é".repeat(20);
        assert_eq!(raw.len(), 40);
        cache.put(key(&raw), b"v").unwrap();
        let too_long = "é".repeat(21);
        assert!(too_long.len() > MAX_KEY_BYTES);
        assert_eq!(Key::parse(&too_long), Err(StoreError::KeyTooLong));
    }

    #[test]
    fn rejects_values_over_the_configured_limit() {
        let cache = cache(4);
        cache.put(key("k"), b"1234").unwrap();
        assert_eq!(
            cache.put(key("k"), b"12345"),
            Err(StoreError::ValueTooLarge)
        );
        assert_eq!(cache.get(key("k")).unwrap().as_ref(), b"1234");
    }

    #[test]
    fn accepts_value_at_the_architecture_ceiling() {
        let cache = cache(MAX_VALUE_BYTES);
        let value = vec![7u8; MAX_VALUE_BYTES];
        cache.put(key("k"), &value).unwrap();
        assert_eq!(cache.get(key("k")).unwrap().len(), MAX_VALUE_BYTES);
        assert_eq!(
            cache.put(key("k"), &vec![7u8; MAX_VALUE_BYTES + 1]),
            Err(StoreError::ValueTooLarge)
        );
    }

    #[test]
    fn many_keys_roundtrip_across_shards() {
        let cache = MemoryCache::with_capacity(32, 256);
        for i in 0..256 {
            let k = key(&format!("k{i:08}"));
            cache.put(k, i.to_string().as_bytes()).unwrap();
        }
        for i in 0..256 {
            let k = key(&format!("k{i:08}"));
            assert_eq!(cache.get(k).unwrap().as_ref(), i.to_string().as_bytes());
        }
    }

    #[test]
    fn overwrite_reuses_slab_pages() {
        let cache = MemoryCache::with_capacity(128, 100);
        let payload = vec![b'x'; 128];
        for i in 0..100 {
            cache.put(key(&format!("k{i:08}")), &payload).unwrap();
        }
        let pages = cache.slab_page_count();
        assert!(pages >= 1, "{pages}");
        for _ in 0..10 {
            for i in 0..100 {
                cache.put(key(&format!("k{i:08}")), &payload).unwrap();
            }
        }
        assert_eq!(cache.slab_page_count(), pages);
    }

    fn lru_cache(max_value_bytes: usize, max_keys: usize, max_bytes: usize) -> MemoryCache {
        MemoryCache::open(StoreOptions {
            max_value_bytes,
            capacity: 0,
            max_keys,
            max_bytes,
            replacement: ReplacementKind::Lru,
            expiration: ExpirationKind::None,
            shards: Some(1),
            hit_sample: 1,
        })
    }

    #[test]
    fn lru_evicts_oldest_key_over_cap() {
        let cache = lru_cache(32, 2, 0);
        cache.put(key("a"), b"1").unwrap();
        cache.put(key("b"), b"2").unwrap();
        cache.put(key("c"), b"3").unwrap();
        assert_eq!(cache.len(), 2);
        assert!(cache.get(key("a")).is_none());
        assert_eq!(cache.get(key("b")).unwrap().as_ref(), b"2");
        assert_eq!(cache.get(key("c")).unwrap().as_ref(), b"3");
    }

    #[test]
    fn lru_get_refreshes_recency() {
        let cache = lru_cache(32, 3, 0);
        cache.put(key("a"), b"1").unwrap();
        cache.put(key("b"), b"2").unwrap();
        cache.put(key("c"), b"3").unwrap();
        assert!(cache.get(key("a")).is_some());
        cache.put(key("d"), b"4").unwrap();
        assert_eq!(cache.len(), 3);
        assert!(cache.get(key("a")).is_some());
        assert!(cache.get(key("b")).is_none());
        assert!(cache.get(key("c")).is_some());
        assert!(cache.get(key("d")).is_some());
    }

    #[test]
    fn lru_evicts_to_byte_cap() {
        let charge = charge_bytes(0);
        let cache = lru_cache(32, 0, charge * 2);
        cache.put(key("a"), b"").unwrap();
        cache.put(key("b"), b"").unwrap();
        cache.put(key("c"), b"").unwrap();
        assert_eq!(cache.len(), 2);
        assert!(cache.get(key("a")).is_none());
        assert!(cache.get(key("b")).is_some());
        assert!(cache.get(key("c")).is_some());
    }

    #[test]
    fn lru_overwrite_does_not_grow_len() {
        let cache = lru_cache(32, 2, 0);
        cache.put(key("a"), b"1").unwrap();
        cache.put(key("b"), b"2").unwrap();
        cache.put(key("a"), b"one").unwrap();
        cache.put(key("c"), b"3").unwrap();
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(key("a")).unwrap().as_ref(), b"one");
        assert!(cache.get(key("b")).is_none());
        assert!(cache.get(key("c")).is_some());
    }

    #[test]
    fn lru_delete_unlinks_from_recency() {
        let cache = lru_cache(32, 2, 0);
        cache.put(key("a"), b"1").unwrap();
        cache.put(key("b"), b"2").unwrap();
        assert!(cache.delete(key("a")));
        cache.put(key("c"), b"3").unwrap();
        cache.put(key("d"), b"4").unwrap();
        assert_eq!(cache.len(), 2);
        assert!(cache.get(key("a")).is_none());
        assert!(cache.get(key("b")).is_none());
        assert!(cache.get(key("c")).is_some());
        assert!(cache.get(key("d")).is_some());
    }

    #[test]
    fn unbounded_never_evicts() {
        let cache = cache(32);
        for i in 0..64 {
            cache.put(key(&format!("k{i:08}")), b"v").unwrap();
        }
        assert_eq!(cache.len(), 64);
    }

    #[test]
    fn expiration_none_ignores_ttl() {
        let cache = cache(32);
        cache
            .put_with(
                key("a"),
                b"v",
                PutOptions {
                    ttl: Some(Duration::from_secs(0)),
                },
            )
            .unwrap();
        assert_eq!(cache.get(key("a")).unwrap().as_ref(), b"v");
    }

    #[test]
    fn rejects_value_whose_slab_charge_exceeds_max_bytes() {
        let cache = lru_cache(256, 0, 64);
        let payload = vec![7u8; 72];
        assert!(charge_bytes(payload.len()) > 64);
        assert_eq!(
            cache.put(key("a"), &payload),
            Err(StoreError::ValueTooLarge)
        );
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn empty_value_uses_the_smallest_class() {
        assert_eq!(charge_bytes(0), 16);
        assert_eq!(charge_bytes(1), 16);
        assert_eq!(charge_bytes(128), 144);
        assert_eq!(charge_bytes(248), 256);
        assert_eq!(charge_bytes(249), 288);
    }

    #[test]
    fn rejects_value_over_a_shard_byte_share() {
        let cache = MemoryCache::open(StoreOptions {
            max_value_bytes: 256,
            capacity: 0,
            max_keys: 0,
            max_bytes: 256,
            replacement: ReplacementKind::Lru,
            expiration: ExpirationKind::None,
            shards: Some(4),
            hit_sample: 1,
        });
        let payload = vec![7u8; 72];
        assert!(charge_bytes(payload.len()) > 256 / 4);
        assert_eq!(
            cache.put(key("a"), &payload),
            Err(StoreError::ValueTooLarge)
        );
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn oversized_put_does_not_land_then_vanish() {
        let cache = lru_cache(256, 0, 64);
        let payload = vec![7u8; 72];
        assert_eq!(
            cache.put(key("big"), &payload),
            Err(StoreError::ValueTooLarge)
        );
        cache.put(key("small"), b"").unwrap();
        assert!(cache.get(key("big")).is_none());
        assert_eq!(cache.get(key("small")).unwrap().as_ref(), b"");
    }

    #[test]
    fn overwrite_over_shard_bytes_keeps_the_old_value() {
        let cache = lru_cache(256, 0, 64);
        cache.put(key("a"), b"ok").unwrap();
        let payload = vec![7u8; 72];
        assert_eq!(
            cache.put(key("a"), &payload),
            Err(StoreError::ValueTooLarge)
        );
        assert_eq!(cache.get(key("a")).unwrap().as_ref(), b"ok");
    }

    #[test]
    fn none_replacement_rolls_back_when_over_byte_cap() {
        let charge = charge_bytes(0);
        let cache = MemoryCache::open(StoreOptions {
            max_value_bytes: 32,
            capacity: 0,
            max_keys: 0,
            max_bytes: charge,
            replacement: ReplacementKind::None,
            expiration: ExpirationKind::None,
            shards: Some(1),
            hit_sample: 1,
        });
        cache.put(key("a"), b"").unwrap();
        assert_eq!(cache.put(key("b"), b""), Err(StoreError::ValueTooLarge));
        assert_eq!(cache.len(), 1);
        assert!(cache.get(key("a")).is_some());
        assert!(cache.get(key("b")).is_none());
    }
}

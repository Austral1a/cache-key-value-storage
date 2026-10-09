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

//! Process allocator with a freelist per size class.
//!
//! Temporary buffers (HTTP read buffers, response bodies) return to the freelist
//! instead of leaving dirty pages in the system malloc zone. Allocations bigger
//! than 64 KiB are separate anonymous mappings and are unmapped on free.

use std::alloc::{GlobalAlloc, Layout};
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};

const CLASS_COUNT: usize = 13;
const MIN_CHUNK: usize = 16;
const MAX_CHUNK: usize = 64 * 1024;
#[cfg(target_os = "macos")]
const OS_PAGE: usize = 16 * 1024;
#[cfg(not(target_os = "macos"))]
const OS_PAGE: usize = 4 * 1024;

struct Node {
    next: Option<NonNull<Node>>,
}

struct Class {
    chunk: usize,
    lock: AtomicBool,
    free: Option<NonNull<Node>>,
    page: *mut u8,
    off: usize,
    page_len: usize,
}

impl Class {
    const fn new(chunk: usize) -> Self {
        Self {
            chunk,
            lock: AtomicBool::new(false),
            free: None,
            page: std::ptr::null_mut(),
            off: 0,
            page_len: 0,
        }
    }
}

pub struct PoolAlloc {
    classes: [UnsafeCell<Class>; CLASS_COUNT],
}

unsafe impl Sync for PoolAlloc {}

impl PoolAlloc {
    pub const fn new() -> Self {
        Self {
            classes: [
                UnsafeCell::new(Class::new(16)),
                UnsafeCell::new(Class::new(32)),
                UnsafeCell::new(Class::new(64)),
                UnsafeCell::new(Class::new(128)),
                UnsafeCell::new(Class::new(256)),
                UnsafeCell::new(Class::new(512)),
                UnsafeCell::new(Class::new(1024)),
                UnsafeCell::new(Class::new(2048)),
                UnsafeCell::new(Class::new(4096)),
                UnsafeCell::new(Class::new(8192)),
                UnsafeCell::new(Class::new(16384)),
                UnsafeCell::new(Class::new(32768)),
                UnsafeCell::new(Class::new(MAX_CHUNK)),
            ],
        }
    }
}

unsafe impl GlobalAlloc for PoolAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == 0 {
            return layout.align() as *mut u8;
        }
        let Some(index) = class_index(layout) else {
            return map_region(layout);
        };
        unsafe { self.alloc_class(index) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() == 0 || ptr.is_null() {
            return;
        }
        let Some(index) = class_index(layout) else {
            unsafe { unmap_region(ptr, layout) };
            return;
        };
        let class = unsafe { &mut *self.classes[index].get() };
        let _guard = Lock::new(&class.lock);
        let node = ptr.cast::<Node>();
        unsafe {
            (*node).next = class.free;
        }
        class.free = NonNull::new(node);
    }
}

impl PoolAlloc {
    unsafe fn alloc_class(&self, index: usize) -> *mut u8 {
        let class = unsafe { &mut *self.classes[index].get() };
        let _guard = Lock::new(&class.lock);
        if let Some(node) = class.free {
            class.free = unsafe { (*node.as_ptr()).next };
            return node.as_ptr().cast();
        }
        if class.page.is_null() || class.off + class.chunk > class.page_len {
            let page_len = OS_PAGE.max(class.chunk);
            let page = map_bytes(page_len);
            if page.is_null() {
                return std::ptr::null_mut();
            }
            class.page = page;
            class.off = 0;
            class.page_len = page_len;
        }
        let ptr = unsafe { class.page.add(class.off) };
        class.off += class.chunk;
        ptr
    }
}

fn class_index(layout: Layout) -> Option<usize> {
    let need = layout.size().max(layout.align()).max(MIN_CHUNK);
    if need > MAX_CHUNK {
        return None;
    }
    let class = need.next_power_of_two();
    Some(class.trailing_zeros() as usize - MIN_CHUNK.trailing_zeros() as usize)
}

fn map_region(layout: Layout) -> *mut u8 {
    let len = map_len(layout);
    let ptr = map_bytes(len);
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    let addr = ptr as usize;
    if layout.align() <= OS_PAGE && addr.is_multiple_of(layout.align()) {
        return ptr;
    }
    unsafe { munmap(ptr.cast(), len) };
    std::ptr::null_mut()
}

fn map_len(layout: Layout) -> usize {
    layout.size().div_ceil(OS_PAGE) * OS_PAGE
}

unsafe fn unmap_region(ptr: *mut u8, layout: Layout) {
    unsafe { munmap(ptr.cast(), map_len(layout)) };
}

fn map_bytes(len: usize) -> *mut u8 {
    let ptr = unsafe {
        mmap(
            std::ptr::null_mut(),
            len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANON,
            -1,
            0,
        )
    };
    if ptr.is_null() || ptr == !0usize as *mut c_void {
        std::ptr::null_mut()
    } else {
        ptr.cast()
    }
}

struct Lock<'a>(&'a AtomicBool);

impl<'a> Lock<'a> {
    fn new(flag: &'a AtomicBool) -> Self {
        while flag
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::hint::spin_loop();
        }
        Self(flag)
    }
}

impl Drop for Lock<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
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

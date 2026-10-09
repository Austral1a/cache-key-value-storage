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

//! CKV connections on per-CPU threads.
//!
//! Tokio accepts (or a unix listener hands off) and the socket stays on one
//! mio thread for life. A ready socket is a nonblocking read, a lookup, and
//! one write of every complete frame already in the buffer.

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

use mio::net::{TcpStream, UnixStream};
use mio::{Events, Interest, Poll, Token, Waker};
use tokio::sync::OwnedSemaphorePermit;

use crate::api::AppState;
use crate::auth::token_accepted;
use crate::ckv::{
    AUTH_MAX_FAILURES, HEADER_LEN, INLINE_BODY, OP_AUTH, OP_DELETE, OP_GET, OP_HEAD, OP_PING,
    OP_SET, PIPELINE_BATCH, REPLY_HEADER_LEN, ST_BAD_KEY, ST_NOT_FOUND, ST_OK, ST_TOO_LARGE,
    ST_UNAUTHORIZED, oversize_status, pack_reply, parse_key, value_budget,
};

const WAKE: Token = Token(0);
const STACK_BYTES: usize = 1024 * 1024;
const READ_CHUNK: usize = 8 * 1024;

enum Handoff {
    Tcp(std::net::TcpStream, OwnedSemaphorePermit),
    Unix(std::os::unix::net::UnixStream, OwnedSemaphorePermit),
}

enum Sock {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Sock {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Sock::Tcp(stream) => stream.read(buf),
            Sock::Unix(stream) => stream.read(buf),
        }
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Sock::Tcp(stream) => stream.write(buf),
            Sock::Unix(stream) => stream.write(buf),
        }
    }

    fn register(&mut self, poll: &Poll, token: Token) -> io::Result<()> {
        let interest = Interest::READABLE | Interest::WRITABLE;
        match self {
            Sock::Tcp(stream) => poll.registry().register(stream, token, interest),
            Sock::Unix(stream) => poll.registry().register(stream, token, interest),
        }
    }

    fn deregister(&mut self, poll: &Poll) -> io::Result<()> {
        match self {
            Sock::Tcp(stream) => poll.registry().deregister(stream),
            Sock::Unix(stream) => poll.registry().deregister(stream),
        }
    }
}

struct Conn {
    stream: Sock,
    permit: OwnedSemaphorePermit,
    inbound: Vec<u8>,
    in_pos: usize,
    out: Vec<u8>,
    out_pos: usize,
    authed: bool,
    auth_failures: u8,
    last: Instant,
    close: bool,
}

pub struct Pool {
    txs: Vec<SyncSender<Handoff>>,
    wakers: Vec<Waker>,
    next: AtomicUsize,
}

impl Pool {
    pub fn start(state: Arc<AppState>, idle: Duration) -> Arc<Self> {
        let n = io_threads();
        let mut txs = Vec::with_capacity(n);
        let mut wakers = Vec::with_capacity(n);
        for i in 0..n {
            let (tx, rx) = mpsc::sync_channel(1024);
            let (wake_tx, wake_rx) = mpsc::sync_channel(1);
            let state = Arc::clone(&state);
            thread::Builder::new()
                .name(format!("ckv-io-{i}"))
                .stack_size(STACK_BYTES)
                .spawn(move || worker(rx, wake_tx, state, idle))
                .expect("ckv io thread");
            wakers.push(wake_rx.recv().expect("ckv io waker"));
            txs.push(tx);
        }
        Arc::new(Self {
            txs,
            wakers,
            next: AtomicUsize::new(0),
        })
    }

    pub fn submit_tcp(&self, stream: std::net::TcpStream, permit: OwnedSemaphorePermit) {
        self.submit(Handoff::Tcp(stream, permit));
    }

    pub fn submit_unix(
        &self,
        stream: std::os::unix::net::UnixStream,
        permit: OwnedSemaphorePermit,
    ) {
        self.submit(Handoff::Unix(stream, permit));
    }

    fn submit(&self, handoff: Handoff) {
        let i = self.next.fetch_add(1, Ordering::Relaxed) % self.txs.len();
        if self.txs[i].send(handoff).is_ok() {
            let _ = self.wakers[i].wake();
        }
    }
}

fn io_threads() -> usize {
    if let Ok(raw) = std::env::var("CACHE_CKV_THREADS")
        && let Ok(n) = raw.parse::<usize>()
    {
        return n.clamp(1, 64);
    }
    // 4 beat 8 on the no-pipeline TCP stress (higher 64-worker ops, lower RSS).
    // CACHE_CKV_THREADS overrides this.
    4
}

fn worker(rx: Receiver<Handoff>, wake_tx: SyncSender<Waker>, state: Arc<AppState>, idle: Duration) {
    let mut poll = Poll::new().expect("ckv poll");
    let waker = Waker::new(poll.registry(), WAKE).expect("ckv waker");
    let _ = wake_tx.send(waker);
    let mut events = Events::with_capacity(1024);
    let mut conns: Vec<Option<Conn>> = Vec::new();
    let mut free: Vec<usize> = Vec::new();
    loop {
        let timeout = if idle.is_zero() { None } else { Some(idle) };
        if let Err(err) = poll.poll(&mut events, timeout) {
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            tracing::debug!(%err, "ckv poll");
            continue;
        }
        accept_ready(
            &rx,
            &mut poll,
            &mut conns,
            &mut free,
            &state,
            Instant::now(),
        );
        let mut closed = Vec::new();
        for event in events.iter() {
            if event.token() == WAKE {
                continue;
            }
            let idx = event.token().0 - 1;
            let Some(conn) = conns.get_mut(idx).and_then(|slot| slot.as_mut()) else {
                continue;
            };
            let readable = event.is_readable() || event.is_read_closed();
            let writable = event.is_writable();
            if let Err(err) = drive(conn, &state, readable, writable) {
                tracing::debug!(%err, "ckv connection ended");
                conn.close = true;
            }
            if conn.close {
                closed.push(idx);
            }
        }
        for idx in closed {
            release_conn(&mut poll, &mut conns, &mut free, idx);
        }
        if !idle.is_zero() {
            let now = Instant::now();
            let expired: Vec<usize> = conns
                .iter()
                .enumerate()
                .filter_map(|(idx, slot)| {
                    slot.as_ref().and_then(|conn| {
                        (now.saturating_duration_since(conn.last) >= idle).then_some(idx)
                    })
                })
                .collect();
            for idx in expired {
                release_conn(&mut poll, &mut conns, &mut free, idx);
            }
        }
    }
}

fn release_conn(poll: &mut Poll, conns: &mut [Option<Conn>], free: &mut Vec<usize>, idx: usize) {
    let Some(mut conn) = conns.get_mut(idx).and_then(|slot| slot.take()) else {
        return;
    };
    let _ = conn.stream.deregister(poll);
    drop(conn.permit);
    free.push(idx);
}

fn accept_ready(
    rx: &Receiver<Handoff>,
    poll: &mut Poll,
    conns: &mut Vec<Option<Conn>>,
    free: &mut Vec<usize>,
    state: &AppState,
    now: Instant,
) {
    while let Ok(handoff) = rx.try_recv() {
        let stream = match handoff {
            Handoff::Tcp(stream, permit) => {
                if stream.set_nonblocking(true).is_err() {
                    continue;
                }
                (Sock::Tcp(TcpStream::from_std(stream)), permit)
            }
            Handoff::Unix(stream, permit) => {
                if stream.set_nonblocking(true).is_err() {
                    continue;
                }
                (Sock::Unix(UnixStream::from_std(stream)), permit)
            }
        };
        let (mut stream, permit) = stream;
        let idx = free.pop().unwrap_or_else(|| {
            conns.push(None);
            conns.len() - 1
        });
        if stream.register(poll, Token(idx + 1)).is_err() {
            free.push(idx);
            continue;
        }
        conns[idx] = Some(Conn {
            stream,
            permit,
            inbound: Vec::with_capacity(256),
            in_pos: 0,
            out: Vec::with_capacity(512),
            out_pos: 0,
            authed: false,
            auth_failures: 0,
            last: now,
            close: false,
        });
        let Some(conn) = conns[idx].as_mut() else {
            continue;
        };
        // Data may already be buffered. kqueue is edge-triggered, so read now.
        if drive(conn, state, true, true).is_err() || conn.close {
            release_conn(poll, conns, free, idx);
        }
    }
}

fn drive(conn: &mut Conn, state: &AppState, readable: bool, writable: bool) -> io::Result<()> {
    if readable {
        conn.last = Instant::now();
        if read_ready(conn)? {
            conn.close = true;
            return Ok(());
        }
    }
    loop {
        let mut n = 0;
        while n < PIPELINE_BATCH {
            if !take_frame(conn, state)? {
                break;
            }
            n += 1;
        }
        flush_out(conn)?;
        if n < PIPELINE_BATCH || !header_ready(conn) {
            break;
        }
    }
    if writable {
        flush_out(conn)?;
    }
    compact_in(conn);
    Ok(())
}

fn read_ready(conn: &mut Conn) -> io::Result<bool> {
    let mut tmp = [0u8; READ_CHUNK];
    loop {
        if conn.inbound.len().saturating_sub(conn.in_pos) > 1024 * 1024 && header_ready(conn) {
            return Ok(false);
        }
        match conn.stream.read(&mut tmp) {
            Ok(0) => return Ok(true),
            Ok(n) => conn.inbound.extend_from_slice(&tmp[..n]),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}

fn header_ready(conn: &Conn) -> bool {
    conn.inbound.len() - conn.in_pos >= HEADER_LEN
}

fn take_frame(conn: &mut Conn, state: &AppState) -> io::Result<bool> {
    let available = conn.inbound.len() - conn.in_pos;
    if available < HEADER_LEN {
        return Ok(false);
    }
    let start = conn.in_pos;
    let header = &conn.inbound[start..start + HEADER_LEN];
    let opcode = header[0];
    let key_len = usize::from(header[1]);
    let value_len = u32::from_le_bytes(header[2..6].try_into().expect("4 bytes")) as usize;
    if value_len > crate::store::MAX_VALUE_BYTES
        || value_len > value_budget(opcode, state.max_value_bytes)
    {
        push_status(conn, oversize_status(opcode));
        conn.close = true;
        conn.in_pos = conn.inbound.len();
        return Ok(false);
    }
    let frame_len = HEADER_LEN + key_len + value_len;
    if available < frame_len {
        return Ok(false);
    }
    let key_off = start + HEADER_LEN;
    let value_off = key_off + key_len;
    // Small frames (the stress GET/SET) stay on the stack. A multi-megabyte SET
    // is the only path that allocates.
    const STACK_FRAME: usize = HEADER_LEN + 255 + INLINE_BODY;
    if frame_len <= STACK_FRAME {
        let mut tmp = [0u8; STACK_FRAME];
        tmp[..frame_len].copy_from_slice(&conn.inbound[start..start + frame_len]);
        conn.in_pos = start + frame_len;
        apply(
            conn,
            state,
            opcode,
            &tmp[HEADER_LEN..HEADER_LEN + key_len],
            &tmp[HEADER_LEN + key_len..frame_len],
        )?;
    } else {
        let key = conn.inbound[key_off..value_off].to_vec();
        let value = conn.inbound[value_off..start + frame_len].to_vec();
        conn.in_pos = start + frame_len;
        apply(conn, state, opcode, &key, &value)?;
    }
    Ok(!conn.close)
}

fn apply(
    conn: &mut Conn,
    state: &AppState,
    opcode: u8,
    key: &[u8],
    value: &[u8],
) -> io::Result<()> {
    match opcode {
        OP_PING => {
            if key.is_empty() && value.is_empty() {
                push_status(conn, ST_OK);
            } else {
                push_status(conn, ST_BAD_KEY);
            }
        }
        OP_AUTH => {
            if !key.is_empty() {
                push_status(conn, ST_BAD_KEY);
            } else if conn.authed || token_accepted(value, &state.tokens) {
                conn.authed = true;
                push_status(conn, ST_OK);
            } else {
                conn.auth_failures = conn.auth_failures.saturating_add(1);
                push_status(conn, ST_UNAUTHORIZED);
                if conn.auth_failures >= AUTH_MAX_FAILURES {
                    conn.close = true;
                }
            }
        }
        OP_GET | OP_SET | OP_DELETE | OP_HEAD if !conn.authed => {
            push_status(conn, ST_UNAUTHORIZED);
        }
        OP_GET => match parse_key(key) {
            Ok(key) => match state.cache.get(key) {
                Some(stored) => push_body(conn, ST_OK, &stored),
                None => push_status(conn, ST_NOT_FOUND),
            },
            Err(status) => push_status(conn, status),
        },
        OP_SET => match parse_key(key) {
            Ok(key) => {
                if value.len() > state.max_value_bytes {
                    push_status(conn, ST_TOO_LARGE);
                } else {
                    match state.cache.put(key, value) {
                        Ok(()) => push_status(conn, ST_OK),
                        Err(_) => push_status(conn, ST_TOO_LARGE),
                    }
                }
            }
            Err(status) => push_status(conn, status),
        },
        OP_DELETE => match parse_key(key) {
            Ok(key) => {
                let status = if state.cache.delete(key) {
                    ST_OK
                } else {
                    ST_NOT_FOUND
                };
                push_status(conn, status);
            }
            Err(status) => push_status(conn, status),
        },
        OP_HEAD => match parse_key(key) {
            Ok(key) => match state.cache.get(key) {
                Some(stored) => {
                    let len = u32::try_from(stored.len()).unwrap_or(u32::MAX);
                    drop(stored);
                    push_head(conn, len);
                }
                None => push_status(conn, ST_NOT_FOUND),
            },
            Err(status) => push_status(conn, status),
        },
        _ => push_status(conn, ST_BAD_KEY),
    }
    Ok(())
}

fn push_status(conn: &mut Conn, status: u8) {
    push_body(conn, status, &[]);
}

fn push_head(conn: &mut Conn, value_len: u32) {
    let mut header = [0u8; REPLY_HEADER_LEN];
    header[0] = ST_OK;
    header[1..].copy_from_slice(&value_len.to_le_bytes());
    conn.out.extend_from_slice(&header);
}

fn push_body(conn: &mut Conn, status: u8, body: &[u8]) {
    if body.len() <= INLINE_BODY {
        let mut buf = [0u8; REPLY_HEADER_LEN + INLINE_BODY];
        let n = pack_reply(&mut buf, status, body);
        conn.out.extend_from_slice(&buf[..n]);
        return;
    }
    let mut header = [0u8; REPLY_HEADER_LEN];
    header[0] = status;
    header[1..].copy_from_slice(&(body.len() as u32).to_le_bytes());
    conn.out.extend_from_slice(&header);
    conn.out.extend_from_slice(body);
}

fn flush_out(conn: &mut Conn) -> io::Result<()> {
    while conn.out_pos < conn.out.len() {
        match conn.stream.write(&conn.out[conn.out_pos..]) {
            Ok(0) => {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "write closed"));
            }
            Ok(n) => conn.out_pos += n,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    conn.out.clear();
    conn.out_pos = 0;
    Ok(())
}

fn compact_in(conn: &mut Conn) {
    if conn.in_pos == 0 {
        return;
    }
    if conn.in_pos == conn.inbound.len() {
        conn.inbound.clear();
        conn.in_pos = 0;
        if conn.inbound.capacity() > 8 * 1024 {
            conn.inbound.shrink_to(256);
        }
        return;
    }
    if conn.in_pos >= 4096 {
        conn.inbound.drain(..conn.in_pos);
        conn.in_pos = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryCache;
    use std::net::TcpListener;
    use tokio::sync::Semaphore;

    fn frame(op: u8, key: &[u8], value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(op);
        out.push(key.len() as u8);
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(key);
        out.extend_from_slice(value);
        out
    }

    #[test]
    fn pool_get_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(AppState {
            cache: Arc::new(MemoryCache::new(1024)),
            tokens: Arc::from([String::from("secret")]),
            max_value_bytes: 1024,
        });
        let pool = Pool::start(Arc::clone(&state), Duration::ZERO);
        let mut client = std::net::TcpStream::connect(addr).unwrap();
        client.set_nodelay(true).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (server, _) = listener.accept().unwrap();
        server.set_nonblocking(true).unwrap();
        let permit = Arc::new(Semaphore::new(4))
            .try_acquire_owned()
            .expect("permit");
        pool.submit_tcp(server, permit);

        client.write_all(&frame(OP_AUTH, b"", b"secret")).unwrap();
        client.write_all(&frame(OP_SET, b"k", b"value")).unwrap();
        client.write_all(&frame(OP_GET, b"k", b"")).unwrap();
        let mut buf = [0u8; 64];
        let mut got = 0;
        while got < 5 + 5 + 5 + 5 {
            match client.read(&mut buf[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(err) => panic!("{err}"),
            }
        }
        assert_eq!(buf[0], ST_OK, "auth");
        assert_eq!(buf[5], ST_OK, "set");
        assert_eq!(buf[10], ST_OK, "get");
        let len = u32::from_le_bytes(buf[11..15].try_into().unwrap()) as usize;
        assert_eq!(len, 5);
        assert_eq!(&buf[15..20], b"value");
    }
}

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

//! CKV1: length-prefixed TCP cache protocol.
//!
//! One response per request, in order. A connection may send the next frame
//! before reading the previous response (pipelining). The client URL scheme
//! `ckv://` is for addresses and docs only; it is not sent on the wire.
//!
//! Request: `u8 opcode | u8 key_len | u32 value_len | key | value` (little-endian).
//! Response: `u8 status | u32 value_len | value`.
//!
//! HEAD is the exception: on success `value_len` is the stored size and the
//! value bytes are omitted. Every other response uses `value_len` as the
//! number of bytes that follow.

use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, Sleep};

use crate::api::AppState;
use crate::auth::token_accepted;
use crate::store::{Key, MAX_VALUE_BYTES};

pub(crate) const OP_AUTH: u8 = 0;
pub(crate) const OP_GET: u8 = 1;
pub(crate) const OP_SET: u8 = 2;
pub(crate) const OP_DELETE: u8 = 3;
pub(crate) const OP_HEAD: u8 = 4;
pub(crate) const OP_PING: u8 = 5;

pub(crate) const ST_OK: u8 = 0;
pub(crate) const ST_NOT_FOUND: u8 = 1;
pub(crate) const ST_UNAUTHORIZED: u8 = 2;
pub(crate) const ST_BAD_KEY: u8 = 3;
pub(crate) const ST_TOO_LARGE: u8 = 4;

pub(crate) const HEADER_LEN: usize = 6;
pub(crate) const REPLY_HEADER_LEN: usize = 5;
/// GET bodies at or under this size are copied onto the stack and written in
/// one syscall. Larger bodies stay on the slab for the write.
pub(crate) const INLINE_BODY: usize = 256;
/// Frames handled from an already-read buffer before the next poll.
pub(crate) const PIPELINE_BATCH: usize = 32;
/// Poll the idle timer only when it is about to fire. A far deadline would
/// register a sleep on every read.
const IDLE_POLL_WINDOW: Duration = Duration::from_secs(1);
/// AUTH value is a bearer token. Match Hyper's HTTP header cap so CKV cannot
/// buffer more unauthenticated bytes than HTTP already allows.
const AUTH_MAX_VALUE_BYTES: usize = 8 * 1024;
pub(crate) const AUTH_MAX_FAILURES: u8 = 5;

/// One sleep for the connection. Reset at most once a second while traffic
/// is flowing, so a busy GET does not register a timer on every syscall.
struct Idle {
    sleep: Pin<Box<Sleep>>,
    idle: Duration,
    armed_at: Instant,
    reset_every: Duration,
}

impl Idle {
    fn arm(idle: Duration) -> Option<Self> {
        if idle.is_zero() {
            return None;
        }
        let reset_every = if idle >= Duration::from_secs(2) {
            Duration::from_secs(1)
        } else {
            idle / 2
        };
        Some(Self {
            sleep: Box::pin(tokio::time::sleep(idle)),
            idle,
            armed_at: Instant::now(),
            reset_every,
        })
    }

    fn note_activity(&mut self) {
        let now = Instant::now();
        if now.saturating_duration_since(self.armed_at) >= self.reset_every {
            self.sleep.as_mut().reset(now + self.idle);
            self.armed_at = now;
        }
    }
}

pub async fn serve(mut stream: TcpStream, state: Arc<AppState>, idle: Duration) -> io::Result<()> {
    let mut authed = false;
    let mut auth_failures = 0u8;
    let mut inbound = BytesMut::with_capacity(256);
    let mut idle = Idle::arm(idle);

    loop {
        while inbound.len() < HEADER_LEN {
            if read_more(&mut stream, &mut inbound, &mut idle).await? == 0 {
                return Ok(());
            }
        }
        let opcode = inbound[0];
        let key_len = usize::from(inbound[1]);
        let value_len = u32::from_le_bytes(inbound[2..6].try_into().expect("4 bytes")) as usize;
        if value_len > MAX_VALUE_BYTES || value_len > value_budget(opcode, state.max_value_bytes) {
            write_reply(&mut stream, oversize_status(opcode), 0, &[]).await?;
            return Ok(());
        }
        let frame_len = HEADER_LEN + key_len + value_len;
        while inbound.len() < frame_len {
            if read_more(&mut stream, &mut inbound, &mut idle).await? == 0 {
                return Ok(());
            }
        }
        {
            let key = &inbound[HEADER_LEN..HEADER_LEN + key_len];
            let value = &inbound[HEADER_LEN + key_len..frame_len];

            match opcode {
                OP_PING => {
                    if key_len == 0 && value_len == 0 {
                        write_reply(&mut stream, ST_OK, 0, &[]).await?;
                    } else {
                        write_reply(&mut stream, ST_BAD_KEY, 0, &[]).await?;
                    }
                }
                OP_AUTH => {
                    if key_len != 0 {
                        write_reply(&mut stream, ST_BAD_KEY, 0, &[]).await?;
                    } else if authed {
                        write_reply(&mut stream, ST_OK, 0, &[]).await?;
                    } else if token_accepted(value, &state.tokens) {
                        authed = true;
                        write_reply(&mut stream, ST_OK, 0, &[]).await?;
                    } else {
                        auth_failures = auth_failures.saturating_add(1);
                        write_reply(&mut stream, ST_UNAUTHORIZED, 0, &[]).await?;
                        if auth_failures >= AUTH_MAX_FAILURES {
                            return Ok(());
                        }
                    }
                }
                OP_GET | OP_SET | OP_DELETE | OP_HEAD if !authed => {
                    write_reply(&mut stream, ST_UNAUTHORIZED, 0, &[]).await?;
                }
                OP_GET => match parse_key(key) {
                    Ok(key) => match state.cache.get(key) {
                        Some(stored) if stored.len() <= INLINE_BODY => {
                            let mut buf = [0u8; REPLY_HEADER_LEN + INLINE_BODY];
                            let n = pack_reply(&mut buf, ST_OK, &stored);
                            drop(stored);
                            write_all(&mut stream, &buf[..n]).await?;
                        }
                        Some(stored) => {
                            write_reply(&mut stream, ST_OK, stored.len() as u32, &stored).await?;
                        }
                        None => write_reply(&mut stream, ST_NOT_FOUND, 0, &[]).await?,
                    },
                    Err(status) => write_reply(&mut stream, status, 0, &[]).await?,
                },
                OP_SET => match parse_key(key) {
                    Ok(key) => {
                        if value_len > state.max_value_bytes {
                            write_reply(&mut stream, ST_TOO_LARGE, 0, &[]).await?;
                        } else {
                            match state.cache.put(key, value) {
                                Ok(()) => write_reply(&mut stream, ST_OK, 0, &[]).await?,
                                Err(_) => write_reply(&mut stream, ST_TOO_LARGE, 0, &[]).await?,
                            }
                        }
                    }
                    Err(status) => write_reply(&mut stream, status, 0, &[]).await?,
                },
                OP_DELETE => match parse_key(key) {
                    Ok(key) => {
                        let status = if state.cache.delete(key) {
                            ST_OK
                        } else {
                            ST_NOT_FOUND
                        };
                        write_reply(&mut stream, status, 0, &[]).await?;
                    }
                    Err(status) => write_reply(&mut stream, status, 0, &[]).await?,
                },
                OP_HEAD => match parse_key(key) {
                    Ok(key) => match state.cache.get(key) {
                        Some(stored) => {
                            let len = u32::try_from(stored.len()).unwrap_or(u32::MAX);
                            drop(stored);
                            write_reply(&mut stream, ST_OK, len, &[]).await?;
                        }
                        None => write_reply(&mut stream, ST_NOT_FOUND, 0, &[]).await?,
                    },
                    Err(status) => write_reply(&mut stream, status, 0, &[]).await?,
                },
                _ => write_reply(&mut stream, ST_BAD_KEY, 0, &[]).await?,
            }
        }
        inbound.advance(frame_len);
        if inbound.capacity() > 8 * 1024 {
            let leftover = inbound.split().freeze();
            inbound = BytesMut::with_capacity(256.max(leftover.len()));
            if !leftover.is_empty() {
                inbound.extend_from_slice(&leftover);
            }
        }
    }
}

pub(crate) fn parse_key(bytes: &[u8]) -> Result<Key, u8> {
    Key::from_bytes(bytes).map_err(|_| ST_BAD_KEY)
}

async fn read_more(
    stream: &mut TcpStream,
    inbound: &mut BytesMut,
    idle: &mut Option<Idle>,
) -> io::Result<usize> {
    let near_deadline = idle.as_ref().is_some_and(|idle| {
        idle.sleep
            .deadline()
            .saturating_duration_since(Instant::now())
            <= IDLE_POLL_WINDOW
    });
    let n = if near_deadline {
        let idle = idle.as_mut().expect("deadline implies an armed timer");
        tokio::select! {
            biased;
            result = stream.read_buf(inbound) => result?,
            _ = idle.sleep.as_mut() => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "idle timeout"));
            }
        }
    } else {
        stream.read_buf(inbound).await?
    };
    if let Some(idle) = idle.as_mut() {
        idle.note_activity();
    }
    Ok(n)
}

pub(crate) fn value_budget(opcode: u8, max_value_bytes: usize) -> usize {
    match opcode {
        OP_AUTH => AUTH_MAX_VALUE_BYTES,
        OP_SET => max_value_bytes,
        _ => 0,
    }
}

pub(crate) fn oversize_status(opcode: u8) -> u8 {
    match opcode {
        OP_AUTH | OP_SET => ST_TOO_LARGE,
        _ => ST_BAD_KEY,
    }
}

pub(crate) fn pack_reply(buf: &mut [u8], status: u8, body: &[u8]) -> usize {
    let n = REPLY_HEADER_LEN + body.len();
    buf[0] = status;
    buf[1..REPLY_HEADER_LEN].copy_from_slice(&(body.len() as u32).to_le_bytes());
    buf[REPLY_HEADER_LEN..n].copy_from_slice(body);
    n
}

async fn write_all(stream: &mut TcpStream, buf: &[u8]) -> io::Result<()> {
    let mut rest = buf;
    while !rest.is_empty() {
        let n = stream.write(rest).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "write closed"));
        }
        rest = &rest[n..];
    }
    Ok(())
}

async fn write_reply(
    stream: &mut TcpStream,
    status: u8,
    value_len: u32,
    body: &[u8],
) -> io::Result<()> {
    if body.len() <= INLINE_BODY && value_len as usize == body.len() {
        let mut buf = [0u8; REPLY_HEADER_LEN + INLINE_BODY];
        let n = pack_reply(&mut buf, status, body);
        return write_all(stream, &buf[..n]).await;
    }
    let mut header = [0u8; REPLY_HEADER_LEN];
    header[0] = status;
    header[1..].copy_from_slice(&value_len.to_le_bytes());
    if body.is_empty() {
        return write_all(stream, &header).await;
    }
    let mut bufs = [IoSlice::new(&header), IoSlice::new(body)];
    let mut slices: &mut [IoSlice<'_>] = &mut bufs;
    while slices.iter().any(|slice| !slice.is_empty()) {
        let n = stream.write_vectored(slices).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "write closed"));
        }
        IoSlice::advance_slices(&mut slices, n);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::store::{MAX_KEY_BYTES, MemoryCache};
    use tokio::net::TcpListener;

    async fn session(max_value: usize, token: &str) -> TcpStream {
        session_with_idle(max_value, token, Duration::from_secs(5)).await
    }

    async fn session_with_idle(max_value: usize, token: &str, idle: Duration) -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(AppState {
            cache: Arc::new(MemoryCache::new(max_value)),
            tokens: Arc::from([token.to_owned()]),
            max_value_bytes: max_value,
        });
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = stream.set_nodelay(true);
            let _ = serve(stream, state, idle).await;
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        stream.set_nodelay(true).unwrap();
        stream
    }

    async fn exchange(
        stream: &mut TcpStream,
        opcode: u8,
        key: &[u8],
        value: &[u8],
        read_body: bool,
    ) -> (u8, u32, Vec<u8>) {
        let mut frame = Vec::with_capacity(HEADER_LEN + key.len() + value.len());
        frame.push(opcode);
        frame.push(u8::try_from(key.len()).unwrap());
        frame.extend_from_slice(&(u32::try_from(value.len()).unwrap()).to_le_bytes());
        frame.extend_from_slice(key);
        frame.extend_from_slice(value);
        stream.write_all(&frame).await.unwrap();

        let mut header = [0u8; 5];
        stream.read_exact(&mut header).await.unwrap();
        let status = header[0];
        let value_len = u32::from_le_bytes(header[1..5].try_into().unwrap());
        let mut body = Vec::new();
        if read_body {
            body.resize(value_len as usize, 0);
            if !body.is_empty() {
                stream.read_exact(&mut body).await.unwrap();
            }
        }
        (status, value_len, body)
    }

    #[tokio::test]
    async fn ping_auth_and_key_ops() {
        let mut stream = session(64, "secret").await;

        let (status, len, body) = exchange(&mut stream, OP_PING, b"", b"", true).await;
        assert_eq!((status, len, body.as_slice()), (ST_OK, 0, b"".as_slice()));

        let (status, _, _) = exchange(&mut stream, OP_GET, b"alpha", b"", true).await;
        assert_eq!(status, ST_UNAUTHORIZED);

        let (status, _, _) = exchange(&mut stream, OP_AUTH, b"", b"nope", true).await;
        assert_eq!(status, ST_UNAUTHORIZED);
        let (status, _, _) = exchange(&mut stream, OP_GET, b"alpha", b"", true).await;
        assert_eq!(status, ST_UNAUTHORIZED);

        let (status, _, _) = exchange(&mut stream, OP_AUTH, b"", b"secret", true).await;
        assert_eq!(status, ST_OK);

        let (status, _, _) = exchange(&mut stream, OP_GET, b"", b"", true).await;
        assert_eq!(status, ST_BAD_KEY);
        let (status, _, _) =
            exchange(&mut stream, OP_SET, &[b'k'; MAX_KEY_BYTES + 1], b"v", true).await;
        assert_eq!(status, ST_BAD_KEY);

        let (status, _, _) = exchange(&mut stream, OP_SET, b"k00000000", b"hello", true).await;
        assert_eq!(status, ST_OK);
        assert_eq!(6 + b"k00000000".len(), 15);

        let (status, len, body) = exchange(&mut stream, OP_GET, b"k00000000", b"", true).await;
        assert_eq!(
            (status, len, body.as_slice()),
            (ST_OK, 5, b"hello".as_slice())
        );

        let (status, len, body) = exchange(&mut stream, OP_HEAD, b"k00000000", b"", false).await;
        assert_eq!((status, len, body.len()), (ST_OK, 5, 0));

        let (status, _, _) = exchange(&mut stream, OP_GET, b"missing", b"", true).await;
        assert_eq!(status, ST_NOT_FOUND);

        let (status, _, _) = exchange(&mut stream, OP_DELETE, b"k00000000", b"", true).await;
        assert_eq!(status, ST_OK);
        let (status, _, _) = exchange(&mut stream, OP_DELETE, b"k00000000", b"", true).await;
        assert_eq!(status, ST_NOT_FOUND);
        let (status, _, _) = exchange(&mut stream, OP_GET, b"k00000000", b"", true).await;
        assert_eq!(status, ST_NOT_FOUND);
    }

    #[tokio::test]
    async fn rejects_values_over_the_configured_limit() {
        let mut stream = session(4, "secret").await;
        let (status, _, _) = exchange(&mut stream, OP_AUTH, b"", b"secret", true).await;
        assert_eq!(status, ST_OK);
        let (status, _, _) = exchange(&mut stream, OP_SET, b"k", b"12345", true).await;
        assert_eq!(status, ST_TOO_LARGE);
    }

    #[tokio::test]
    async fn auth_with_key_does_not_livelock() {
        let mut stream = session(64, "secret").await;
        let run = async {
            let (status, _, _) = exchange(&mut stream, OP_AUTH, b"x", b"", true).await;
            assert_eq!(status, ST_BAD_KEY);
            let (status, _, _) = exchange(&mut stream, OP_AUTH, b"", b"secret", true).await;
            assert_eq!(status, ST_OK);
            let (status, _, _) = exchange(&mut stream, OP_SET, b"k", b"v", true).await;
            assert_eq!(status, ST_OK);
        };
        tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("AUTH with a key must consume the frame");
    }

    #[tokio::test]
    async fn oversized_set_header_does_not_wait_for_body() {
        let mut stream = session(4, "secret").await;
        let (status, _, _) = exchange(&mut stream, OP_AUTH, b"", b"secret", true).await;
        assert_eq!(status, ST_OK);

        let mut header = [0u8; HEADER_LEN];
        header[0] = OP_SET;
        header[1] = 1;
        header[2..6].copy_from_slice(&100_000u32.to_le_bytes());
        stream.write_all(&header).await.unwrap();

        let run = async {
            let mut reply = [0u8; 5];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0], ST_TOO_LARGE);
            assert_eq!(&reply[1..], &[0, 0, 0, 0]);
        };
        tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("oversize SET must reject from the header");
    }

    #[tokio::test]
    async fn auth_after_success_is_ignored() {
        let mut stream = session(64, "secret").await;
        let (status, _, _) = exchange(&mut stream, OP_AUTH, b"", b"secret", true).await;
        assert_eq!(status, ST_OK);
        let (status, _, _) = exchange(&mut stream, OP_SET, b"k", b"v", true).await;
        assert_eq!(status, ST_OK);
        let (status, _, _) = exchange(&mut stream, OP_AUTH, b"", b"nope", true).await;
        assert_eq!(status, ST_OK);
        let (status, _, body) = exchange(&mut stream, OP_GET, b"k", b"", true).await;
        assert_eq!((status, body.as_slice()), (ST_OK, b"v".as_slice()));
    }

    #[tokio::test]
    async fn too_many_failed_auths_close_the_connection() {
        let mut stream = session(64, "secret").await;
        for _ in 0..AUTH_MAX_FAILURES {
            let (status, _, _) = exchange(&mut stream, OP_AUTH, b"", b"nope", true).await;
            assert_eq!(status, ST_UNAUTHORIZED);
        }
        let mut buf = [0u8; 5];
        let err = stream.read_exact(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn idle_timeout_closes_a_quiet_connection() {
        let mut stream = session_with_idle(64, "secret", Duration::from_millis(50)).await;
        tokio::time::sleep(Duration::from_millis(80)).await;
        stream.write_all(&[OP_PING, 0, 0, 0, 0, 0]).await.unwrap();
        let mut buf = [0u8; 5];
        let err = stream.read_exact(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}

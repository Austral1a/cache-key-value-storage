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

//! Local throughput and latency check for the RAM cache, compared with
//! memcached when that binary is on `PATH`.
//!
//! Each worker holds one TCP connection and waits for the response before
//! sending the next request. Memcached is driven the same way over its text
//! protocol, so the gap is protocol and server cost, not memcached pipelining.
//!
//! The cache process and memcached are started one at a time. The dataset is
//! rejected when the estimated server plus client footprint would exceed 768
//! MiB, leaving headroom under 1 GiB.
//!
//! `--lru` skips HTTP, turns on cachkeystorage LRU, and defaults to 1_000_000 keys
//! so CKV can be compared with memcached on a much larger resident set.

use std::env;
use std::fmt;
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::Barrier;
use tokio::task::JoinSet;

const RAM_BUDGET: usize = 768 * 1024 * 1024;
const SAMPLE_CAP: usize = 8192;
const MAX_VALUE_BYTES: usize = 64 * 1024;
const MAX_WORKERS: usize = 128;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const TOKEN: &str = "stress-token";
const CKV_SOCK: &str = "/tmp/cachkeystorage-stress.sock";
const MC_SOCK: &str = "/tmp/memcached-stress.sock";
const DEFAULT_KEYS: usize = 10_000;
const LRU_DEFAULT_KEYS: usize = 1_000_000;

#[derive(Clone, Debug)]
struct Options {
    keys: usize,
    value_len: usize,
    seconds: u64,
    workers: Vec<usize>,
    http_port: u16,
    ckv_port: u16,
    memcached_port: u16,
    skip_memcached: bool,
    lru: bool,
    pipeline: usize,
    ckv_unix: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            keys: DEFAULT_KEYS,
            value_len: 128,
            seconds: 3,
            workers: vec![1, 16, 64],
            http_port: 18097,
            ckv_port: 19097,
            memcached_port: 21311,
            skip_memcached: false,
            lru: false,
            pipeline: 1,
            ckv_unix: false,
        }
    }
}

#[derive(Debug)]
struct ProtoError(String);

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProtoError {}

struct Server {
    child: Child,
}

impl Drop for Server {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[derive(Clone)]
enum Target {
    Http {
        port: u16,
        token: Arc<str>,
    },
    Ckv {
        port: u16,
        token: Arc<str>,
        unix: Option<Arc<str>>,
    },
    Memcached {
        port: u16,
        unix: Option<Arc<str>>,
    },
}

impl Target {
    fn name(&self) -> &'static str {
        match self {
            Target::Http { .. } => "cache",
            Target::Ckv { .. } => "ckv",
            Target::Memcached { .. } => "memcached",
        }
    }

    async fn connect(&self, reserve: usize) -> Result<Client, ProtoError> {
        match self {
            Target::Http { port, token } => Ok(Client::Http(
                HttpConn::connect(*port, token, reserve).await?,
            )),
            Target::Ckv { port, token, unix } => {
                let conn = if let Some(path) = unix {
                    CkvConn::connect_unix(path, token, reserve).await?
                } else {
                    CkvConn::connect(*port, token, reserve).await?
                };
                Ok(Client::Ckv(conn))
            }
            Target::Memcached { port, unix } => {
                let conn = if let Some(path) = unix {
                    McConn::connect_unix(path, reserve).await?
                } else {
                    McConn::connect(*port, reserve).await?
                };
                Ok(Client::Memcached(conn))
            }
        }
    }
}

enum Client {
    Http(HttpConn),
    Ckv(CkvConn),
    Memcached(McConn),
}

impl Client {
    async fn set(&mut self, key: &str, value: &[u8]) -> Result<(), ProtoError> {
        match self {
            Client::Http(conn) => conn.set(key, value).await,
            Client::Ckv(conn) => conn.set(key, value).await,
            Client::Memcached(conn) => conn.set(key, value).await,
        }
    }

    async fn get(&mut self, key: &str, value: &[u8], compare: bool) -> Result<(), ProtoError> {
        match self {
            Client::Http(conn) => conn.get(key, value, compare).await,
            Client::Ckv(conn) => conn.get(key, value, compare).await,
            Client::Memcached(conn) => conn.get(key, value, compare).await,
        }
    }

    async fn set_many(&mut self, keys: &[&str], value: &[u8]) -> Result<(), ProtoError> {
        match self {
            Client::Ckv(conn) => conn.set_many(keys, value).await,
            Client::Memcached(conn) => conn.set_many(keys, value).await,
            Client::Http(_) => Err(ProtoError("HTTP does not pipeline".to_owned())),
        }
    }

    async fn get_many(&mut self, keys: &[&str], value: &[u8]) -> Result<(), ProtoError> {
        match self {
            Client::Ckv(conn) => conn.get_many(keys, value.len()).await,
            Client::Memcached(conn) => conn.get_many(keys, value).await,
            Client::Http(_) => Err(ProtoError("HTTP does not pipeline".to_owned())),
        }
    }
}

enum Net {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Net {
    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            Net::Tcp(stream) => stream.write_all(buf).await,
            Net::Unix(stream) => stream.write_all(buf).await,
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Net::Tcp(stream) => stream.read(buf).await,
            Net::Unix(stream) => stream.read(buf).await,
        }
    }
}

struct Socket {
    stream: Net,
    buf: Vec<u8>,
    pos: usize,
    out: Vec<u8>,
}

impl Socket {
    async fn connect(port: u16, reserve: usize) -> Result<Self, ProtoError> {
        let stream = tokio::time::timeout(
            Duration::from_secs(2),
            TcpStream::connect(("127.0.0.1", port)),
        )
        .await
        .map_err(|_| ProtoError(format!("timed out connecting to 127.0.0.1:{port}")))?
        .map_err(|err| ProtoError(format!("connect 127.0.0.1:{port}: {err}")))?;
        stream
            .set_nodelay(true)
            .map_err(|err| ProtoError(format!("TCP_NODELAY: {err}")))?;
        Ok(Self {
            stream: Net::Tcp(stream),
            buf: Vec::with_capacity(reserve + 512),
            pos: 0,
            out: Vec::with_capacity(reserve + 512),
        })
    }

    async fn connect_unix(path: &str, reserve: usize) -> Result<Self, ProtoError> {
        let stream = tokio::time::timeout(Duration::from_secs(2), UnixStream::connect(path))
            .await
            .map_err(|_| ProtoError(format!("timed out connecting to {path}")))?
            .map_err(|err| ProtoError(format!("connect {path}: {err}")))?;
        Ok(Self {
            stream: Net::Unix(stream),
            buf: Vec::with_capacity(reserve + 512),
            pos: 0,
            out: Vec::with_capacity(reserve + 512),
        })
    }

    async fn send(&mut self) -> Result<(), ProtoError> {
        self.stream
            .write_all(&self.out)
            .await
            .map_err(|err| ProtoError(format!("write: {err}")))
    }

    fn buffered(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn body(&self, len: usize) -> &[u8] {
        &self.buf[self.pos..self.pos + len]
    }

    fn consume(&mut self, n: usize) {
        self.pos += n;
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos >= 8192 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    async fn read_more(&mut self) -> Result<(), ProtoError> {
        let mut tmp = [0u8; 8192];
        let n = self
            .stream
            .read(&mut tmp)
            .await
            .map_err(|err| ProtoError(format!("read: {err}")))?;
        if n == 0 {
            return Err(ProtoError("connection closed".to_owned()));
        }
        self.buf.extend_from_slice(&tmp[..n]);
        if self.buf.len() > 8 * 1024 * 1024 {
            return Err(ProtoError(
                "response buffer exceeded 8 MiB; closing the connection".to_owned(),
            ));
        }
        Ok(())
    }

    async fn fill_at_least(&mut self, n: usize) -> Result<(), ProtoError> {
        while self.buffered().len() < n {
            self.read_more().await?;
        }
        Ok(())
    }

    async fn read_line(&mut self) -> Result<String, ProtoError> {
        loop {
            if let Some(i) = self.buffered().windows(2).position(|w| w == b"\r\n") {
                let line = std::str::from_utf8(&self.buffered()[..i])
                    .map_err(|_| ProtoError("response line is not utf-8".to_owned()))?
                    .to_owned();
                self.consume(i + 2);
                return Ok(line);
            }
            if self.buffered().len() > 1024 * 1024 {
                return Err(ProtoError("response line exceeded 1 MiB".to_owned()));
            }
            self.read_more().await?;
        }
    }

    async fn read_http(&mut self, max_body: usize) -> Result<(u16, usize), ProtoError> {
        let header_end = loop {
            if let Some(end) = find_header_end(self.buffered()) {
                break end;
            }
            self.read_more().await?;
        };
        let status = parse_http_status(&self.buffered()[..header_end])?;
        let len = parse_content_length(&self.buffered()[..header_end]).unwrap_or(0);
        if len > max_body {
            return Err(ProtoError(format!(
                "response body is {len} bytes, above the {max_body} byte cap"
            )));
        }
        self.consume(header_end + 4);
        self.fill_at_least(len).await?;
        Ok((status, len))
    }
}

struct HttpConn {
    io: Socket,
    token: String,
    host: String,
}

impl HttpConn {
    async fn connect(port: u16, token: &str, reserve: usize) -> Result<Self, ProtoError> {
        Ok(Self {
            io: Socket::connect(port, reserve).await?,
            token: token.to_owned(),
            host: format!("127.0.0.1:{port}"),
        })
    }

    async fn health(&mut self) -> Result<(), ProtoError> {
        self.io.out.clear();
        write!(
            self.io.out,
            "GET /healthz HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.host
        )
        .expect("write to buffer");
        self.io.send().await?;
        let (status, len) = self.io.read_http(64).await?;
        self.io.consume(len);
        if status == 200 {
            Ok(())
        } else {
            Err(ProtoError(format!("healthz returned HTTP {status}")))
        }
    }

    async fn set(&mut self, key: &str, value: &[u8]) -> Result<(), ProtoError> {
        self.io.out.clear();
        write!(
            self.io.out,
            "PUT /k/{key} HTTP/1.1\r\n\
             Authorization: Bearer {token}\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Length: {len}\r\n\
             \r\n",
            token = self.token,
            len = value.len(),
        )
        .expect("write to buffer");
        self.io.out.extend_from_slice(value);
        self.io.send().await?;
        self.finish(204, value, false).await
    }

    async fn get(&mut self, key: &str, value: &[u8], compare: bool) -> Result<(), ProtoError> {
        self.io.out.clear();
        write!(
            self.io.out,
            "GET /k/{key} HTTP/1.1\r\n\
             Authorization: Bearer {token}\r\n\
             \r\n",
            token = self.token,
        )
        .expect("write to buffer");
        self.io.send().await?;
        self.finish(200, value, compare).await
    }

    async fn finish(
        &mut self,
        expected_status: u16,
        value: &[u8],
        compare: bool,
    ) -> Result<(), ProtoError> {
        let max_body = value.len().max(4096);
        let (status, len) = self.io.read_http(max_body).await?;
        if status != expected_status {
            let detail = String::from_utf8_lossy(self.io.body(len)).into_owned();
            return Err(ProtoError(format!("HTTP {status}: {detail}")));
        }
        if expected_status == 200 {
            if len != value.len() {
                return Err(ProtoError(format!(
                    "HTTP body is {len} bytes, expected {}",
                    value.len()
                )));
            }
            if compare && self.io.body(len) != value {
                return Err(ProtoError("cached value did not match".to_owned()));
            }
        }
        self.io.consume(len);
        Ok(())
    }
}

fn push_ckv(out: &mut Vec<u8>, opcode: u8, key: &[u8], value: &[u8]) {
    out.push(opcode);
    out.push(u8::try_from(key.len()).expect("key fits in u8"));
    out.extend_from_slice(&(u32::try_from(value.len()).unwrap_or(u32::MAX)).to_le_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(value);
}

const CKV_AUTH: u8 = 0;
const CKV_GET: u8 = 1;
const CKV_SET: u8 = 2;
const CKV_PING: u8 = 5;

struct CkvConn {
    io: Socket,
}

impl CkvConn {
    async fn connect(port: u16, token: &str, reserve: usize) -> Result<Self, ProtoError> {
        Self::handshake(Socket::connect(port, reserve).await?, token).await
    }

    async fn connect_unix(path: &str, token: &str, reserve: usize) -> Result<Self, ProtoError> {
        Self::handshake(Socket::connect_unix(path, reserve).await?, token).await
    }

    async fn handshake(io: Socket, token: &str) -> Result<Self, ProtoError> {
        let mut conn = Self { io };
        conn.exchange(CKV_AUTH, b"", token.as_bytes(), 0, None)
            .await?;
        Ok(conn)
    }

    async fn ping(&mut self) -> Result<(), ProtoError> {
        self.exchange(CKV_PING, b"", b"", 0, None).await
    }

    async fn set(&mut self, key: &str, value: &[u8]) -> Result<(), ProtoError> {
        self.exchange(CKV_SET, key.as_bytes(), value, 0, None).await
    }

    async fn get(&mut self, key: &str, value: &[u8], compare: bool) -> Result<(), ProtoError> {
        let expected = if compare { Some(value) } else { None };
        self.exchange(CKV_GET, key.as_bytes(), b"", value.len(), expected)
            .await
    }

    async fn set_many(&mut self, keys: &[&str], value: &[u8]) -> Result<(), ProtoError> {
        self.io.out.clear();
        for key in keys {
            push_ckv(&mut self.io.out, CKV_SET, key.as_bytes(), value);
        }
        self.io.send().await?;
        for _ in keys {
            self.read_reply(0, None).await?;
        }
        Ok(())
    }

    async fn get_many(&mut self, keys: &[&str], value_len: usize) -> Result<(), ProtoError> {
        self.io.out.clear();
        for key in keys {
            push_ckv(&mut self.io.out, CKV_GET, key.as_bytes(), b"");
        }
        self.io.send().await?;
        for _ in keys {
            self.read_reply(value_len, None).await?;
        }
        Ok(())
    }

    async fn exchange(
        &mut self,
        opcode: u8,
        key: &[u8],
        value: &[u8],
        expect_body: usize,
        compare: Option<&[u8]>,
    ) -> Result<(), ProtoError> {
        if key.len() > 40 {
            return Err(ProtoError("ckv key longer than 40 bytes".to_owned()));
        }
        self.io.out.clear();
        self.io.out.push(opcode);
        self.io
            .out
            .push(u8::try_from(key.len()).expect("key fits in u8"));
        self.io
            .out
            .extend_from_slice(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_le_bytes());
        self.io.out.extend_from_slice(key);
        self.io.out.extend_from_slice(value);
        self.io.send().await?;
        self.read_reply(expect_body, compare).await
    }

    async fn read_reply(
        &mut self,
        expect_body: usize,
        compare: Option<&[u8]>,
    ) -> Result<(), ProtoError> {
        self.io.fill_at_least(5).await?;
        let status = self.io.buffered()[0];
        let len =
            u32::from_le_bytes(self.io.buffered()[1..5].try_into().expect("4 bytes")) as usize;
        self.io.consume(5);
        if len > 8 * 1024 * 1024 {
            return Err(ProtoError(format!(
                "ckv response is {len} bytes, above the 8 MiB cap"
            )));
        }
        self.io.fill_at_least(len).await?;
        if status != 0 {
            return Err(ProtoError(format!("ckv status {status}")));
        }
        if len != expect_body {
            return Err(ProtoError(format!(
                "ckv body is {len} bytes, expected {expect_body}"
            )));
        }
        if let Some(expected) = compare
            && self.io.body(len) != expected
        {
            return Err(ProtoError("cached value did not match".to_owned()));
        }
        self.io.consume(len);
        Ok(())
    }
}

struct McConn {
    io: Socket,
}

impl McConn {
    async fn connect(port: u16, reserve: usize) -> Result<Self, ProtoError> {
        Ok(Self {
            io: Socket::connect(port, reserve).await?,
        })
    }

    async fn connect_unix(path: &str, reserve: usize) -> Result<Self, ProtoError> {
        Ok(Self {
            io: Socket::connect_unix(path, reserve).await?,
        })
    }

    async fn set_many(&mut self, keys: &[&str], value: &[u8]) -> Result<(), ProtoError> {
        self.io.out.clear();
        for key in keys {
            write!(self.io.out, "set {key} 0 0 {}\r\n", value.len()).expect("write to buffer");
            self.io.out.extend_from_slice(value);
            self.io.out.extend_from_slice(b"\r\n");
        }
        self.io.send().await?;
        for _ in keys {
            let line = self.io.read_line().await?;
            if line != "STORED" {
                return Err(ProtoError(format!("memcached set: {line}")));
            }
        }
        Ok(())
    }

    async fn get_many(&mut self, keys: &[&str], value: &[u8]) -> Result<(), ProtoError> {
        self.io.out.clear();
        self.io.out.extend_from_slice(b"get");
        for key in keys {
            self.io.out.push(b' ');
            self.io.out.extend_from_slice(key.as_bytes());
        }
        self.io.out.extend_from_slice(b"\r\n");
        self.io.send().await?;
        for _ in keys {
            let line = self.io.read_line().await?;
            if line == "END" {
                return Err(ProtoError("memcached miss".to_owned()));
            }
            let len = parse_mc_value_len(&line)?;
            if len != value.len() {
                return Err(ProtoError(format!(
                    "memcached value is {len} bytes, expected {}",
                    value.len()
                )));
            }
            self.io.fill_at_least(len + 2).await?;
            self.io.consume(len + 2);
        }
        let end = self.io.read_line().await?;
        if end == "END" {
            Ok(())
        } else {
            Err(ProtoError(format!("memcached trailer: {end}")))
        }
    }

    async fn version(&mut self) -> Result<(), ProtoError> {
        self.io.out.clear();
        self.io.out.extend_from_slice(b"version\r\n");
        self.io.send().await?;
        let line = self.io.read_line().await?;
        if line.starts_with("VERSION") {
            Ok(())
        } else {
            Err(ProtoError(format!("memcached version reply: {line}")))
        }
    }

    async fn set(&mut self, key: &str, value: &[u8]) -> Result<(), ProtoError> {
        self.io.out.clear();
        write!(self.io.out, "set {key} 0 0 {}\r\n", value.len()).expect("write to buffer");
        self.io.out.extend_from_slice(value);
        self.io.out.extend_from_slice(b"\r\n");
        self.io.send().await?;
        let line = self.io.read_line().await?;
        if line == "STORED" {
            Ok(())
        } else {
            Err(ProtoError(format!("memcached set: {line}")))
        }
    }

    async fn get(&mut self, key: &str, value: &[u8], compare: bool) -> Result<(), ProtoError> {
        self.io.out.clear();
        write!(self.io.out, "get {key}\r\n").expect("write to buffer");
        self.io.send().await?;
        let line = self.io.read_line().await?;
        if line == "END" {
            return Err(ProtoError("memcached miss".to_owned()));
        }
        let len = parse_mc_value_len(&line)?;
        if len != value.len() {
            return Err(ProtoError(format!(
                "memcached value is {len} bytes, expected {}",
                value.len()
            )));
        }
        self.io.fill_at_least(len).await?;
        if compare && self.io.body(len) != value {
            return Err(ProtoError("memcached value did not match".to_owned()));
        }
        self.io.consume(len);
        self.io.fill_at_least(2).await?;
        if self.io.buffered().get(..2) != Some(b"\r\n".as_slice()) {
            return Err(ProtoError(
                "memcached value was not followed by CRLF".to_owned(),
            ));
        }
        self.io.consume(2);
        let end = self.io.read_line().await?;
        if end == "END" {
            Ok(())
        } else {
            Err(ProtoError(format!("memcached trailer: {end}")))
        }
    }
}

#[derive(Clone, Copy)]
enum Op {
    Set,
    Get,
}

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::Set => "set",
            Op::Get => "get",
        }
    }
}

struct Samples {
    values: Vec<u64>,
    seen: u64,
    max: u64,
    rng: Rng,
}

impl Samples {
    fn new(seed: u64) -> Self {
        Self {
            values: Vec::with_capacity(SAMPLE_CAP.min(1024)),
            seen: 0,
            max: 0,
            rng: Rng::new(seed),
        }
    }

    fn record(&mut self, ns: u64) {
        self.max = self.max.max(ns);
        self.seen += 1;
        if self.values.len() < SAMPLE_CAP {
            self.values.push(ns);
            return;
        }
        let j = self.rng.next() % self.seen;
        if j < SAMPLE_CAP as u64 {
            self.values[j as usize] = ns;
        }
    }
}

struct WorkerStats {
    ops: u64,
    errors: u64,
    samples: Samples,
}

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn index(&mut self, limit: usize) -> usize {
        (self.next() as usize) % limit
    }
}

struct Row {
    backend: &'static str,
    workers: usize,
    op: &'static str,
    ops_per_sec: f64,
    p50: u64,
    p99: u64,
    max: u64,
    errors: u64,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), ProtoError> {
    if cfg!(debug_assertions) {
        return Err(ProtoError(
            "refusing to measure a debug build. Run: cargo build --release --bins && ./target/release/stress"
                .to_owned(),
        ));
    }

    let options = parse_args()?;
    let estimate = ensure_budget(
        options.keys,
        options.value_len,
        *options.workers.iter().max().unwrap(),
    )?;
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    if options.ckv_unix {
        eprintln!("Local stress test (unix sockets; TCP comparison is the default command)");
    } else if options.pipeline > 1 {
        eprintln!(
            "Local stress test (pipelined, {} in flight per connection)",
            options.pipeline
        );
    } else {
        eprintln!("Local stress test (one server at a time, no request pipelining)");
    }
    eprintln!(
        "  keys {}   value {} bytes   workers {}   {}s per phase   replacement {}",
        options.keys,
        options.value_len,
        options
            .workers
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(","),
        options.seconds,
        if options.lru { "lru" } else { "none" },
    );
    eprintln!(
        "  estimated data + client buffers: {} MiB (cap {} MiB, machine limit 1024 MiB)",
        mib(estimate),
        mib(RAM_BUDGET)
    );
    eprintln!("  logical cpus: {cpus}");

    let keys = Arc::<[String]>::from(
        (0..options.keys)
            .map(|idx| format!("k{idx:08}"))
            .collect::<Vec<_>>(),
    );
    let value = Arc::<[u8]>::from(vec![b'x'; options.value_len]);

    let cache_bin = cache_binary()?;
    let mut rows = Vec::new();

    eprintln!(
        "==> cache HTTP on 127.0.0.1:{} and CKV on 127.0.0.1:{} ({}){}",
        options.http_port,
        options.ckv_port,
        cache_bin.display(),
        if options.lru {
            "  LRU on, HTTP skipped"
        } else {
            ""
        }
    );
    let ckv_sock = options.ckv_unix.then_some(CKV_SOCK);
    let mut cache = spawn_cache(
        &cache_bin,
        options.http_port,
        options.ckv_port,
        options.keys,
        options.lru,
        ckv_sock,
    )?;
    wait_http(&mut cache, options.http_port).await?;
    if let Some(path) = ckv_sock {
        wait_ckv_unix(&mut cache, path).await?;
    } else {
        wait_ckv(&mut cache, options.ckv_port).await?;
    }
    if !options.lru {
        let http = Target::Http {
            port: options.http_port,
            token: Arc::from(TOKEN),
        };
        run_backend(&http, &keys, &value, &options, &mut rows).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        eprintln!(
            "  cache RSS after HTTP: {}",
            format_rss(cache.child.id()).unwrap_or_else(|| "unknown".to_owned())
        );
        print_memory_map(cache.child.id());
    }
    let ckv = Target::Ckv {
        port: options.ckv_port,
        token: Arc::from(TOKEN),
        unix: ckv_sock.map(Arc::from),
    };
    run_backend(&ckv, &keys, &value, &options, &mut rows).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    eprintln!(
        "  cache RSS after CKV: {}",
        format_rss(cache.child.id()).unwrap_or_else(|| "unknown".to_owned())
    );
    print_memory_map(cache.child.id());
    drop(cache);

    if options.skip_memcached {
        eprintln!("==> memcached skipped");
    } else {
        let mc_sock = options.ckv_unix.then_some(MC_SOCK);
        match spawn_memcached(
            options.memcached_port,
            options.keys,
            options.value_len,
            mc_sock,
        ) {
            Ok(mut memcached) => {
                if let Some(path) = mc_sock {
                    eprintln!("==> memcached text protocol on {path}");
                    wait_memcached_unix(&mut memcached, path).await?;
                } else {
                    eprintln!(
                        "==> memcached text protocol on 127.0.0.1:{}",
                        options.memcached_port
                    );
                    wait_memcached(&mut memcached, options.memcached_port).await?;
                }
                let target = Target::Memcached {
                    port: options.memcached_port,
                    unix: mc_sock.map(Arc::from),
                };
                run_backend(&target, &keys, &value, &options, &mut rows).await?;
                eprintln!(
                    "  memcached RSS: {}",
                    format_rss(memcached.child.id()).unwrap_or_else(|| "unknown".to_owned())
                );
            }
            Err(err) if err.0 == "memcached not found" => {
                eprintln!("==> memcached not on PATH; comparison skipped");
            }
            Err(err) => return Err(err),
        }
    }

    print_table(&rows);
    print_comparison(&rows);
    Ok(())
}

async fn run_backend(
    target: &Target,
    keys: &Arc<[String]>,
    value: &Arc<[u8]>,
    options: &Options,
    rows: &mut Vec<Row>,
) -> Result<(), ProtoError> {
    let fill_workers = *options.workers.iter().max().unwrap();
    eprint!("  fill {} keys with {fill_workers} workers... ", keys.len());
    io::stderr().flush().ok();
    let started = Instant::now();
    let (ops, errors, mut samples) = fill(target, keys, value, fill_workers).await?;
    if errors > 0 || ops != keys.len() as u64 {
        return Err(ProtoError(format!(
            "{} fill stored {ops} of {} keys with {errors} errors",
            target.name(),
            keys.len()
        )));
    }
    let elapsed = started.elapsed();
    let (p50, p99) = percentiles(&mut samples);
    eprintln!("{:.0} ops/s", ops as f64 / elapsed.as_secs_f64());
    rows.push(Row {
        backend: target.name(),
        workers: fill_workers,
        op: "fill",
        ops_per_sec: ops as f64 / elapsed.as_secs_f64(),
        p50,
        p99,
        max: samples.max,
        errors,
    });

    let mut check = target.connect(value.len()).await?;
    check.get(&keys[0], value, true).await?;
    check.get(&keys[keys.len() - 1], value, true).await?;
    drop(check);

    for &workers in &options.workers {
        for op in [Op::Set, Op::Get] {
            eprint!("  {} {} workers... ", op.name(), workers);
            io::stderr().flush().ok();
            let pipeline = match target {
                Target::Http { .. } => 1,
                _ => options.pipeline,
            };
            let row =
                timed_phase(target, keys, value, workers, op, options.seconds, pipeline).await?;
            eprintln!(
                "{:.0} ops/s  p50 {}  p99 {}  errors {}",
                row.ops_per_sec,
                fmt_ns(row.p50),
                fmt_ns(row.p99),
                row.errors
            );
            rows.push(row);
        }
    }
    Ok(())
}

async fn fill(
    target: &Target,
    keys: &Arc<[String]>,
    value: &Arc<[u8]>,
    workers: usize,
) -> Result<(u64, u64, Samples), ProtoError> {
    let mut set = JoinSet::new();
    for worker_id in 0..workers {
        let target = target.clone();
        let keys = Arc::clone(keys);
        let value = Arc::clone(value);
        set.spawn(async move {
            let mut client = target.connect(value.len()).await?;
            let mut stats = WorkerStats {
                ops: 0,
                errors: 0,
                samples: Samples::new(worker_id as u64 + 1),
            };
            let mut idx = worker_id;
            while idx < keys.len() {
                let started = Instant::now();
                match tokio::time::timeout(REQUEST_TIMEOUT, client.set(&keys[idx], &value)).await {
                    Ok(Ok(())) => {
                        stats.ops += 1;
                        stats.samples.record(elapsed_ns(started));
                    }
                    Ok(Err(err)) => {
                        return Err(ProtoError(format!("fill key {}: {err}", keys[idx])));
                    }
                    Err(_) => {
                        return Err(ProtoError(format!("fill key {} timed out", keys[idx])));
                    }
                }
                idx += workers;
            }
            Ok(stats)
        });
    }
    let parts = join_workers(set).await?;
    Ok(merge_stats(parts))
}

async fn timed_phase(
    target: &Target,
    keys: &Arc<[String]>,
    value: &Arc<[u8]>,
    workers: usize,
    op: Op,
    seconds: u64,
    pipeline: usize,
) -> Result<Row, ProtoError> {
    let ready = Arc::new(Barrier::new(workers + 1));
    let go = Arc::new(Barrier::new(workers + 1));
    let deadline = Arc::new(OnceLock::new());
    let mut set = JoinSet::new();
    for worker_id in 0..workers {
        let target = target.clone();
        let keys = Arc::clone(keys);
        let value = Arc::clone(value);
        let ready = Arc::clone(&ready);
        let go = Arc::clone(&go);
        let deadline = Arc::clone(&deadline);
        set.spawn(async move {
            timed_worker(TimedWorker {
                target,
                keys,
                value,
                worker_id,
                op,
                pipeline,
                ready,
                go,
                deadline,
            })
            .await
        });
    }

    tokio::time::timeout(Duration::from_secs(5), ready.wait())
        .await
        .map_err(|_| ProtoError("workers did not finish connecting".to_owned()))?;
    deadline
        .set(Instant::now() + Duration::from_secs(seconds))
        .map_err(|_| ProtoError("deadline was set twice".to_owned()))?;
    go.wait().await;
    let started = Instant::now();

    let parts = join_workers(set).await?;
    let elapsed = started.elapsed().as_secs_f64().max(0.001);
    let (ops, errors, mut samples) = merge_stats(parts);
    let (p50, p99) = percentiles(&mut samples);
    Ok(Row {
        backend: target.name(),
        workers,
        op: op.name(),
        ops_per_sec: ops as f64 / elapsed,
        p50,
        p99,
        max: samples.max,
        errors,
    })
}

struct TimedWorker {
    target: Target,
    keys: Arc<[String]>,
    value: Arc<[u8]>,
    worker_id: usize,
    op: Op,
    pipeline: usize,
    ready: Arc<Barrier>,
    go: Arc<Barrier>,
    deadline: Arc<OnceLock<Instant>>,
}

async fn timed_worker(worker: TimedWorker) -> Result<WorkerStats, ProtoError> {
    let TimedWorker {
        target,
        keys,
        value,
        worker_id,
        op,
        pipeline,
        ready,
        go,
        deadline,
    } = worker;
    let connected = target.connect(value.len()).await;
    ready.wait().await;
    let mut client = match connected {
        Ok(client) => client,
        Err(err) => {
            go.wait().await;
            return Err(err);
        }
    };
    go.wait().await;
    let until = *deadline
        .get()
        .ok_or_else(|| ProtoError("deadline missing".to_owned()))?;
    let mut stats = WorkerStats {
        ops: 0,
        errors: 0,
        samples: Samples::new(0xC0FFEE + worker_id as u64),
    };
    let mut rng = Rng::new(0xA5A5_0000_0000_0001 ^ (worker_id as u64).wrapping_mul(0x9E37_79B9));
    while Instant::now() < until {
        let started = Instant::now();
        let result = if pipeline <= 1 {
            let key = &keys[rng.index(keys.len())];
            match op {
                Op::Set => tokio::time::timeout(REQUEST_TIMEOUT, client.set(key, &value)).await,
                Op::Get => {
                    tokio::time::timeout(REQUEST_TIMEOUT, client.get(key, &value, false)).await
                }
            }
        } else {
            let mut batch = Vec::with_capacity(pipeline);
            for _ in 0..pipeline {
                batch.push(keys[rng.index(keys.len())].as_str());
            }
            match op {
                Op::Set => {
                    tokio::time::timeout(REQUEST_TIMEOUT, client.set_many(&batch, &value)).await
                }
                Op::Get => {
                    tokio::time::timeout(REQUEST_TIMEOUT, client.get_many(&batch, &value)).await
                }
            }
        };
        let n = pipeline.max(1) as u64;
        match result {
            Ok(Ok(())) => {
                stats.ops += n;
                stats.samples.record(elapsed_ns(started) / n);
            }
            Ok(Err(_)) | Err(_) => {
                stats.errors += 1;
                if stats.errors > 50 {
                    break;
                }
                match target.connect(value.len()).await {
                    Ok(next) => client = next,
                    Err(_) => break,
                }
            }
        }
    }
    Ok(stats)
}

async fn join_workers(
    mut set: JoinSet<Result<WorkerStats, ProtoError>>,
) -> Result<Vec<WorkerStats>, ProtoError> {
    let mut parts = Vec::with_capacity(set.len());
    let mut failure = None;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(stats)) => parts.push(stats),
            Ok(Err(err)) => failure = Some(err),
            Err(panic) => {
                failure = Some(ProtoError(format!("worker panicked: {panic}")));
            }
        }
    }
    if let Some(err) = failure {
        return Err(err);
    }
    Ok(parts)
}

fn merge_stats(parts: Vec<WorkerStats>) -> (u64, u64, Samples) {
    let mut ops = 0;
    let mut errors = 0;
    let mut samples = Samples::new(1);
    for part in parts {
        ops += part.ops;
        errors += part.errors;
        samples.max = samples.max.max(part.samples.max);
        samples.values.extend(part.samples.values);
    }
    (ops, errors, samples)
}

fn percentiles(samples: &mut Samples) -> (u64, u64) {
    if samples.values.is_empty() {
        return (0, 0);
    }
    samples.values.sort_unstable();
    (
        percentile(&samples.values, 0.50),
        percentile(&samples.values, 0.99),
    )
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    let last = (sorted.len() - 1) as f64;
    let idx = (last * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn elapsed_ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn spawn_cache(
    bin: &PathBuf,
    port: u16,
    ckv_port: u16,
    keys: usize,
    lru: bool,
    ckv_socket: Option<&str>,
) -> Result<Server, ProtoError> {
    let mut command = Command::new(bin);
    command
        .env("CACHE_LISTEN", format!("127.0.0.1:{port}"))
        .env("CACHE_CKV_LISTEN", format!("127.0.0.1:{ckv_port}"))
        .env("CACHE_AUTH_TOKENS", TOKEN)
        .env("CACHE_CAPACITY", keys.to_string())
        .env("CACHE_IDLE_TIMEOUT_SECS", "0")
        .env("RUST_LOG", "error");
    if let Some(path) = ckv_socket {
        let _ = std::fs::remove_file(path);
        command.env("CACHE_CKV_SOCKET", path);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if lru {
        // Caps are split across shards. An exact key count evicts on the hot
        // shards, so the hit-path run keeps a little headroom.
        command
            .env("CACHE_REPLACEMENT", "lru")
            .env("CACHE_MAX_KEYS", lru_key_cap(keys).to_string());
    }
    let child = command
        .spawn()
        .map_err(|err| ProtoError(format!("start cache: {err}")))?;
    Ok(Server { child })
}

fn spawn_memcached(
    port: u16,
    keys: usize,
    value_len: usize,
    unix: Option<&str>,
) -> Result<Server, ProtoError> {
    let memory_mb = memcached_memory_mb(keys, value_len);
    let mut command = Command::new("memcached");
    if let Some(path) = unix {
        let _ = std::fs::remove_file(path);
        command.args(["-s", path, "-a", "0777"]);
    } else {
        command.args(["-l", "127.0.0.1", "-p", &port.to_string(), "-U", "0"]);
    }
    match command
        .args(["-m", &memory_mb.to_string(), "-M", "-c", "4096"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => Ok(Server { child }),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            Err(ProtoError("memcached not found".to_owned()))
        }
        Err(err) => Err(ProtoError(format!("start memcached: {err}"))),
    }
}

async fn wait_http(server: &mut Server, port: u16) -> Result<(), ProtoError> {
    for _ in 0..100 {
        if let Some(status) = server
            .child
            .try_wait()
            .map_err(|err| ProtoError(format!("cache status: {err}")))?
        {
            return Err(ProtoError(format!("cache exited early: {status}")));
        }
        if let Ok(mut conn) = HttpConn::connect(port, TOKEN, 64).await
            && conn.health().await.is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(ProtoError(format!(
        "cache did not answer on 127.0.0.1:{port}"
    )))
}

async fn wait_ckv(server: &mut Server, port: u16) -> Result<(), ProtoError> {
    for _ in 0..100 {
        if let Some(status) = server
            .child
            .try_wait()
            .map_err(|err| ProtoError(format!("cache status: {err}")))?
        {
            return Err(ProtoError(format!("cache exited early: {status}")));
        }
        if let Ok(mut conn) = CkvConn::connect(port, TOKEN, 64).await
            && conn.ping().await.is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(ProtoError(format!(
        "ckv did not answer on 127.0.0.1:{port}"
    )))
}

async fn wait_ckv_unix(server: &mut Server, path: &str) -> Result<(), ProtoError> {
    for _ in 0..100 {
        if let Some(status) = server
            .child
            .try_wait()
            .map_err(|err| ProtoError(format!("cache status: {err}")))?
        {
            return Err(ProtoError(format!("cache exited early: {status}")));
        }
        if let Ok(mut conn) = CkvConn::connect_unix(path, TOKEN, 64).await
            && conn.ping().await.is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(ProtoError(format!("ckv did not answer on {path}")))
}

async fn wait_memcached(server: &mut Server, port: u16) -> Result<(), ProtoError> {
    for _ in 0..100 {
        if let Some(status) = server
            .child
            .try_wait()
            .map_err(|err| ProtoError(format!("memcached status: {err}")))?
        {
            return Err(ProtoError(format!("memcached exited early: {status}")));
        }
        if let Ok(mut conn) = McConn::connect(port, 64).await
            && conn.version().await.is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(ProtoError(format!(
        "memcached did not answer on 127.0.0.1:{port}"
    )))
}

async fn wait_memcached_unix(server: &mut Server, path: &str) -> Result<(), ProtoError> {
    for _ in 0..100 {
        if let Some(status) = server
            .child
            .try_wait()
            .map_err(|err| ProtoError(format!("memcached status: {err}")))?
        {
            return Err(ProtoError(format!("memcached exited early: {status}")));
        }
        if let Ok(mut conn) = McConn::connect_unix(path, 64).await
            && conn.version().await.is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(ProtoError(format!("memcached did not answer on {path}")))
}

fn cache_binary() -> Result<PathBuf, ProtoError> {
    let exe = env::current_exe().map_err(|err| ProtoError(format!("current exe: {err}")))?;
    let path = exe
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join(env!("CARGO_PKG_NAME"));
    if path.is_file() {
        Ok(path)
    } else {
        Err(ProtoError(format!(
            "cache binary not found at {}. Build both binaries with: cargo build --release --bins",
            path.display()
        )))
    }
}

fn print_table(rows: &[Row]) {
    println!();
    println!(
        "{:<10} {:>7} {:>5} {:>10} {:>10} {:>10} {:>10} {:>7}",
        "backend", "workers", "op", "ops/s", "p50", "p99", "max", "errors"
    );
    for row in rows {
        println!(
            "{:<10} {:>7} {:>5} {:>10.0} {:>10} {:>10} {:>10} {:>7}",
            row.backend,
            row.workers,
            row.op,
            row.ops_per_sec,
            fmt_ns(row.p50),
            fmt_ns(row.p99),
            fmt_ns(row.max),
            row.errors
        );
    }
}

fn print_comparison(rows: &[Row]) {
    let Some(workers) = rows
        .iter()
        .filter(|row| row.op != "fill")
        .map(|row| row.workers)
        .max()
    else {
        return;
    };
    println!();
    if rows.iter().any(|row| row.backend == "memcached") {
        println!("Same workload, request/response, no pipelining:");
        for op in ["get", "set"] {
            let Some(cache) = find_row(rows, "cache", op, workers) else {
                continue;
            };
            let Some(memcached) = find_row(rows, "memcached", op, workers) else {
                continue;
            };
            let ratio = if memcached.ops_per_sec == 0.0 {
                "n/a".to_owned()
            } else {
                format!("{:.2}x", cache.ops_per_sec / memcached.ops_per_sec)
            };
            println!(
                "  {op} at {workers} workers: cache {:.0} ops/s ({}) vs memcached {:.0} ops/s ({})",
                cache.ops_per_sec,
                ratio,
                memcached.ops_per_sec,
                fmt_ns(memcached.p50)
            );
        }
        if let (Some(cache), Some(memcached)) = (
            find_row(rows, "cache", "get", 1),
            find_row(rows, "memcached", "get", 1),
        ) {
            println!(
                "  one-connection get: cache p50 {} vs memcached p50 {}",
                fmt_ns(cache.p50),
                fmt_ns(memcached.p50)
            );
        }
        for op in ["get", "set"] {
            let Some(ckv) = find_row(rows, "ckv", op, workers) else {
                continue;
            };
            let Some(memcached) = find_row(rows, "memcached", op, workers) else {
                continue;
            };
            let ratio = if memcached.ops_per_sec == 0.0 {
                "n/a".to_owned()
            } else {
                format!("{:.2}x", ckv.ops_per_sec / memcached.ops_per_sec)
            };
            println!(
                "  {op} at {workers} workers: ckv {:.0} ops/s ({}) vs memcached {:.0} ops/s ({})",
                ckv.ops_per_sec,
                ratio,
                memcached.ops_per_sec,
                fmt_ns(memcached.p50)
            );
        }
        if let (Some(ckv), Some(memcached)) = (
            find_row(rows, "ckv", "get", 1),
            find_row(rows, "memcached", "get", 1),
        ) {
            println!(
                "  one-connection get: ckv p50 {} vs memcached p50 {}",
                fmt_ns(ckv.p50),
                fmt_ns(memcached.p50)
            );
        }
    }
    println!(
        "Memcached can go faster still with pipelining. This run does not use it, so both sides wait for each response."
    );
}

fn find_row<'a>(rows: &'a [Row], backend: &str, op: &str, workers: usize) -> Option<&'a Row> {
    rows.iter()
        .find(|row| row.backend == backend && row.op == op && row.workers == workers)
}

fn print_memory_map(pid: u32) {
    let output = match Command::new("vmmap")
        .args(["-summary", &pid.to_string()])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => {
            eprintln!("  vmmap summary unavailable");
            return;
        }
    };
    let text = String::from_utf8_lossy(&output.stdout);
    eprintln!("  vmmap summary:");
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("Process:")
            || trimmed.starts_with("Path:")
            || trimmed.starts_with("Load Address:")
            || trimmed.starts_with("Identifier:")
            || trimmed.starts_with("Version:")
            || trimmed.starts_with("Code Type:")
            || trimmed.starts_with("Platform:")
            || trimmed.starts_with("Parent Process:")
            || trimmed.starts_with("Target Type:")
        {
            continue;
        }
        eprintln!("    {trimmed}");
    }
}

fn format_rss(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let kib: u64 = String::from_utf8(output.stdout).ok()?.trim().parse().ok()?;
    Some(format!("{:.1} MiB", kib as f64 / 1024.0))
}

fn lru_key_cap(keys: usize) -> usize {
    keys.saturating_add(keys / 8).max(keys.saturating_add(64))
}

fn memcached_memory_mb(keys: usize, value_len: usize) -> u64 {
    let bytes = keys
        .saturating_mul(value_len.saturating_add(256))
        .saturating_mul(3);
    let mb = bytes.div_ceil(1024 * 1024) as u64;
    mb.clamp(32, 768)
}

fn estimate_bytes(keys: usize, value_len: usize, workers: usize) -> usize {
    let per_entry = 128usize.saturating_add(value_len);
    let server = keys.saturating_mul(per_entry);
    let key_table = keys.saturating_mul(48);
    let per_worker = (128 * 1024usize)
        .saturating_add(SAMPLE_CAP * std::mem::size_of::<u64>())
        .saturating_add(value_len);
    workers
        .saturating_mul(per_worker)
        .saturating_add(key_table)
        .saturating_add(server)
}

fn ensure_budget(keys: usize, value_len: usize, workers: usize) -> Result<usize, ProtoError> {
    let estimate = estimate_bytes(keys, value_len, workers);
    if estimate > RAM_BUDGET || estimate == usize::MAX {
        return Err(ProtoError(format!(
            "estimated footprint is {} MiB, above the {} MiB cap (machine limit 1 GiB). Lower --keys, --value-bytes, or --workers.",
            mib(estimate),
            mib(RAM_BUDGET)
        )));
    }
    Ok(estimate)
}

fn mib(bytes: usize) -> String {
    format!("{:.1}", bytes as f64 / (1024.0 * 1024.0))
}

fn fmt_ns(ns: u64) -> String {
    if ns < 1_000 {
        format!("{ns}ns")
    } else if ns < 1_000_000 {
        format!("{:.1}us", ns as f64 / 1_000.0)
    } else if ns < 1_000_000_000 {
        format!("{:.2}ms", ns as f64 / 1_000_000.0)
    } else {
        format!("{:.2}s", ns as f64 / 1_000_000_000.0)
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_http_status(headers: &[u8]) -> Result<u16, ProtoError> {
    let line = headers
        .split(|&byte| byte == b'\n')
        .next()
        .unwrap_or(headers);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let line = std::str::from_utf8(line)
        .map_err(|_| ProtoError("HTTP status line is not utf-8".to_owned()))?;
    let code = line
        .split(' ')
        .nth(1)
        .ok_or_else(|| ProtoError(format!("bad HTTP status line: {line}")))?;
    code.parse()
        .map_err(|_| ProtoError(format!("bad HTTP status code: {code}")))
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(headers).ok()?;
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value.trim().parse().ok();
        }
    }
    None
}

fn parse_mc_value_len(line: &str) -> Result<usize, ProtoError> {
    let mut parts = line.split_whitespace();
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("VALUE"), Some(_key), Some(_flags), Some(bytes)) => bytes
            .parse()
            .map_err(|_| ProtoError(format!("bad memcached value length: {bytes}"))),
        _ => Err(ProtoError(format!("bad memcached value line: {line}"))),
    }
}

fn parse_args() -> Result<Options, ProtoError> {
    let mut options = Options::default();
    let mut keys_explicit = false;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "--keys" => {
                options.keys = parse_usize(&mut args, "--keys")?;
                keys_explicit = true;
            }
            "--value-bytes" => options.value_len = parse_usize(&mut args, "--value-bytes")?,
            "--seconds" => {
                options.seconds = parse_usize(&mut args, "--seconds")? as u64;
            }
            "--workers" => options.workers = parse_workers(&next_arg(&mut args, "--workers")?)?,
            "--http-port" => {
                options.http_port = parse_port(&next_arg(&mut args, "--http-port")?)?;
            }
            "--ckv-port" => {
                options.ckv_port = parse_port(&next_arg(&mut args, "--ckv-port")?)?;
            }
            "--memcached-port" => {
                options.memcached_port = parse_port(&next_arg(&mut args, "--memcached-port")?)?;
            }
            "--skip-memcached" => options.skip_memcached = true,
            "--lru" => options.lru = true,
            "--pipeline" => options.pipeline = parse_usize(&mut args, "--pipeline")?,
            "--ckv-unix" => options.ckv_unix = true,
            other => {
                return Err(ProtoError(format!("unknown argument {other}. Use --help.")));
            }
        }
    }
    apply_lru_defaults(&mut options, keys_explicit);
    validate_options(&options)?;
    Ok(options)
}

fn apply_lru_defaults(options: &mut Options, keys_explicit: bool) {
    if options.lru && !keys_explicit {
        options.keys = LRU_DEFAULT_KEYS;
    }
}

fn validate_options(options: &Options) -> Result<(), ProtoError> {
    if options.keys == 0 {
        return Err(ProtoError("--keys must be at least 1".to_owned()));
    }
    if options.value_len == 0 || options.value_len > MAX_VALUE_BYTES {
        return Err(ProtoError(format!(
            "--value-bytes must be 1..={MAX_VALUE_BYTES}"
        )));
    }
    if options.seconds == 0 || options.seconds > 30 {
        return Err(ProtoError("--seconds must be 1..=30".to_owned()));
    }
    if !(1..=32).contains(&options.pipeline) {
        return Err(ProtoError("--pipeline must be 1..=32".to_owned()));
    }
    if options.workers.is_empty() {
        return Err(ProtoError(
            "--workers must list at least one count".to_owned(),
        ));
    }
    if options
        .workers
        .iter()
        .any(|count| *count == 0 || *count > MAX_WORKERS)
    {
        return Err(ProtoError(format!(
            "each --workers entry must be 1..={MAX_WORKERS}"
        )));
    }
    if options.http_port == options.memcached_port
        || options.http_port == options.ckv_port
        || options.ckv_port == options.memcached_port
    {
        return Err(ProtoError(
            "--http-port, --ckv-port, and --memcached-port must differ".to_owned(),
        ));
    }
    let key = format!("k{:08}", options.keys - 1);
    if key.len() > 40 {
        return Err(ProtoError(
            "key space does not fit the 40 byte key limit".to_owned(),
        ));
    }
    Ok(())
}

fn parse_workers(raw: &str) -> Result<Vec<usize>, ProtoError> {
    let mut workers = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(ProtoError("--workers entries must not be empty".to_owned()));
        }
        let count: usize = part
            .parse()
            .map_err(|_| ProtoError(format!("bad --workers entry: {part}")))?;
        if !workers.contains(&count) {
            workers.push(count);
        }
    }
    workers.sort_unstable();
    Ok(workers)
}

fn parse_usize(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<usize, ProtoError> {
    let raw = next_arg(args, flag)?;
    raw.parse()
        .map_err(|_| ProtoError(format!("bad value for {flag}: {raw}")))
}

fn parse_port(raw: &str) -> Result<u16, ProtoError> {
    let port: u16 = raw
        .parse()
        .map_err(|_| ProtoError(format!("bad port: {raw}")))?;
    if port == 0 {
        return Err(ProtoError("port must be 1..=65535".to_owned()));
    }
    Ok(port)
}

fn next_arg(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, ProtoError> {
    args.next()
        .ok_or_else(|| ProtoError(format!("{flag} needs a value")))
}

fn print_help() {
    eprintln!(
        "\
Usage: stress [options]

Builds nothing. Start from a release binary:

  cargo build --release --bins
  ./target/release/stress

The tool starts the cache (HTTP and CKV1), measures both, stops it, then
does the same for memcached if `memcached` is on PATH. Peak dataset size is
capped at 768 MiB. CKV is request/response with no pipelining.

`--lru` skips HTTP, enables cachkeystorage LRU, and defaults to 1_000_000 keys
so CKV can be compared with memcached on a much larger resident set.
CACHE_MAX_KEYS is the key count plus 12.5% so shard imbalance does not
evict the working set. This measures LRU hit-path cost, not miss/evict.

Options:
  --keys N             distinct keys (default 10000; 1000000 with --lru)
  --value-bytes N      value size, 1..=65536 (default 128)
  --seconds N          timed phase length, 1..=30 (default 3)
  --workers LIST       comma-separated worker counts (default 1,16,64)
  --http-port N        cache HTTP listen port (default 18097)
  --ckv-port N         cache CKV1 listen port (default 19097)
  --memcached-port N   memcached listen port (default 21311)
  --skip-memcached     do not compare with memcached
  --lru                CKV vs memcached with LRU and a 1M-key default
  --pipeline N         in-flight requests per connection, 1..=32 (default 1)
  --ckv-unix           CKV and memcached over unix sockets (TCP is the default)
"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_dataset_fits_under_the_cap() {
        let estimate = estimate_bytes(DEFAULT_KEYS, 128, 64);
        assert!(estimate < 32 * 1024 * 1024, "{estimate}");
        assert!(estimate < RAM_BUDGET);
    }

    #[test]
    fn lru_default_dataset_fits_under_the_cap() {
        let estimate = estimate_bytes(LRU_DEFAULT_KEYS, 128, 64);
        assert!(estimate < RAM_BUDGET, "{estimate}");
    }

    #[test]
    fn lru_defaults_keys_when_unset() {
        let mut options = Options {
            lru: true,
            ..Options::default()
        };
        apply_lru_defaults(&mut options, false);
        assert_eq!(options.keys, LRU_DEFAULT_KEYS);
        let mut explicit = Options {
            lru: true,
            keys: 50_000,
            ..Options::default()
        };
        apply_lru_defaults(&mut explicit, true);
        assert_eq!(explicit.keys, 50_000);
    }

    #[test]
    fn huge_dataset_is_rejected() {
        assert!(estimate_bytes(2_000_000, 1024, 64) > RAM_BUDGET);
    }

    #[test]
    fn parses_http_response_header() {
        let raw = b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n";
        let end = find_header_end(raw).unwrap();
        assert_eq!(parse_http_status(&raw[..end]).unwrap(), 204);
        assert_eq!(parse_content_length(&raw[..end]), Some(0));
    }

    #[test]
    fn parses_memcached_value_line() {
        assert_eq!(parse_mc_value_len("VALUE k00000000 0 128").unwrap(), 128);
        assert!(parse_mc_value_len("END").is_err());
    }

    #[test]
    fn reservoir_caps_memory_and_tracks_max() {
        let mut samples = Samples::new(7);
        for i in 0..20_000 {
            samples.record(i);
        }
        assert_eq!(samples.values.len(), SAMPLE_CAP);
        assert_eq!(samples.max, 19_999);
    }

    #[test]
    fn lru_key_cap_leaves_shard_headroom() {
        assert!(lru_key_cap(1_000_000) > 1_000_000);
        assert!(lru_key_cap(64) >= 128);
    }

    #[test]
    fn memcached_memory_limit_stays_small() {
        assert_eq!(memcached_memory_mb(10_000, 128), 32);
        assert!(memcached_memory_mb(1_000_000, 1024) <= 768);
        assert!(memcached_memory_mb(LRU_DEFAULT_KEYS, 128) <= 768);
    }
}

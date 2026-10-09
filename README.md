# RAM cache

In-memory key-value cache. Values are opaque bytes (up to 5 MiB). Keys are at most 40 bytes. Data lives only in the process and is discarded on exit. By default the map is **unbounded**: `CACHE_CAPACITY` pre-sizes it and DELETE is the only reclaim. Set `CACHE_REPLACEMENT=lru` with `CACHE_MAX_KEYS` and/or `CACHE_MAX_BYTES` to evict. Caps are split across shards; a single insert larger than a shard share is kept. LRU records a hit on 1 of every 32 GETs.

The crate and binary are `cachkeystorage`. External services talk to it over HTTP. Same-datacenter clients can use CKV1 (`ckv://host:port`) when `CACHE_CKV_LISTEN` is set. No client library is required.

## Run

```sh
CACHE_AUTH_TOKENS='replace-with-a-long-random-secret' cargo run --release
```

```sh
cargo build --release --bins
CACHE_AUTH_TOKENS='replace-with-a-long-random-secret' ./target/release/cachkeystorage
```

| Variable                  | Required | Default          | Meaning                                                                                           |
| ------------------------- | -------- | ---------------- | ------------------------------------------------------------------------------------------------- |
| `CACHE_AUTH_TOKENS`       | yes      |                  | Comma-separated bearer tokens. One token per service is enough. Tokens cannot contain whitespace. |
| `CACHE_LISTEN`            | no       | `127.0.0.1:8080` | Socket address for the plain HTTP listener.                                                       |
| `CACHE_CKV_LISTEN`        | no       | off              | Socket address for CKV1. Unset leaves TCP CKV off. Bind a private address.                        |
| `CACHE_CKV_SOCKET`        | no       | off              | Unix socket path for CKV1. Same frames as TCP. Unset leaves it off.                               |
| `CACHE_MAX_VALUE_BYTES`   | no       | `5242880`        | Value limit. Cannot exceed 5 MiB.                                                                 |
| `CACHE_CAPACITY`          | no       | `0`              | Expected key count. Pre-sizes the map; `0` means grow on insert. Not a max.                       |
| `CACHE_REPLACEMENT`       | no       | `none`           | `none` or `lru`. `lru` requires a key and/or byte cap.                                            |
| `CACHE_EXPIRATION`        | no       | `none`           | `none` only. TTL is not implemented yet.                                                          |
| `CACHE_MAX_KEYS`          | no       | `0`              | Max keys process-wide, split across shards. `0` means no key cap. Requires `lru`.                 |
| `CACHE_MAX_BYTES`         | no       | `0`              | Max slab bytes process-wide, split across shards. `0` means no byte cap. Requires `lru`.          |
| `CACHE_MAX_CONNS`         | no       | `1024`           | HTTP and CKV connections combined. Extra accepts are closed.                                      |
| `CACHE_IDLE_TIMEOUT_SECS` | no       | `60`             | Close a quiet connection after this many seconds. `0` disables.                                   |

`GET /healthz` is unauthenticated. Every `/v1` route requires `Authorization: Bearer <token>`.

Containers and other hosts must set `CACHE_LISTEN` (for example `0.0.0.0:8080`). Listening on all interfaces logs a warning.

## CKV1

`ckv://127.0.0.1:9090` is an address, the same role as `http://` for the HTTP API. The scheme is not sent on the wire. Point `CACHE_CKV_LISTEN` at that socket. The token is still `CACHE_AUTH_TOKENS`; the first command on a connection is `AUTH`, with the token in the value field. `PING` is allowed before `AUTH` (liveness, like `GET /healthz`). After AUTH succeeds, later AUTH commands are ignored. Five failed AUTH attempts close the connection. Frame layout is in [custom-protocol.md](custom-protocol.md). A client may pipeline frames; replies stay in order. HTTP stays available on `CACHE_LISTEN`.

CKV AUTH is plaintext. Bind `CACHE_CKV_LISTEN` on a private address (same datacenter or localhost). Do not expose that port on the public internet. Public clients stay on HTTPS through the reverse proxy.

## TLS

Terminate TLS in front of this process. The binary speaks HTTP so a proxy can own certificates.

Bind a private address when the proxy is on the same machine:

```sh
CACHE_LISTEN=127.0.0.1:8080 CACHE_AUTH_TOKENS='replace-with-a-long-random-secret' cargo run
```

Caddy:

```caddy
cache.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

nginx:

```nginx
server {
    listen 443 ssl;
    server_name cache.example.com;
    ssl_certificate     /etc/ssl/certs/cache.crt;
    ssl_certificate_key /etc/ssl/private/cache.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        client_max_body_size 5m;
    }
}
```

Private-network clients can use the same HTTPS endpoint. Do not expose port 8080 on the public internet.

## API

| Method   | Path                           | Success | Notes                                                                                    |
| -------- | ------------------------------ | ------- | ---------------------------------------------------------------------------------------- |
| `PUT`    | `/v1/keys/{key}` or `/k/{key}` | `204`   | Body is the value. `Content-Type` is `application/octet-stream` or `text/plain` (UTF-8). |
| `GET`    | `/v1/keys/{key}` or `/k/{key}` | `200`   | Body is the stored bytes.                                                                |
| `HEAD`   | `/v1/keys/{key}` or `/k/{key}` | `200`   | Empty body. `Content-Length` is the value size.                                          |
| `DELETE` | `/v1/keys/{key}` or `/k/{key}` | `204`   | `404` when the key is absent.                                                            |
| `GET`    | `/healthz`                     | `200`   | Liveness. No auth.                                                                       |

Keys are a single percent-encoded path segment. `404` means the key is missing. `400` means the key is empty or longer than 40 bytes. `401` means the token is missing or wrong. `413` means the body is over the value limit. `415` means the content type is not accepted.

```sh
curl -sS -X PUT --data-binary 'cached-value' \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/octet-stream' \
  https://cache.example.com/v1/keys/user:42

curl -sS \
  -H "Authorization: Bearer $TOKEN" \
  https://cache.example.com/v1/keys/user:42
```

Clients serialize their own payloads. The cache does not inspect them beyond the size limit and, for `text/plain`, a UTF-8 check.

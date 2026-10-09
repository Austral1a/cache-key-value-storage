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

//! HTTP API for external cache access.
//!
//! `GET /v1/keys/{key}` and the short alias `GET /k/{key}` also serve `HEAD`.
//! The dispatcher sets `Content-Length` and omits the body on HEAD.

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Incoming};

use crate::auth::{constant_time_eq, token_accepted};
use crate::store::{Key, MAX_KEY_BYTES, MemoryCache, StoreError};

pub type Reply = Response<Full<Bytes>>;

#[derive(Clone)]
pub struct AppState {
    pub cache: Arc<MemoryCache>,
    pub tokens: Arc<[String]>,
    pub max_value_bytes: usize,
}

impl AppState {
    fn authorize(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        let presented = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(presented_token)
            .ok_or(ApiError::Unauthorized)?;
        let presented = presented.as_bytes();
        if self.tokens.len() == 1 {
            if constant_time_eq(presented, self.tokens[0].as_bytes()) {
                return Ok(());
            }
            return Err(ApiError::Unauthorized);
        }
        if token_accepted(presented, &self.tokens) {
            Ok(())
        } else {
            Err(ApiError::Unauthorized)
        }
    }
}

pub async fn handle(state: Arc<AppState>, req: Request<Incoming>) -> Result<Reply, Infallible> {
    Ok(dispatch(&state, req).await)
}

async fn dispatch<B>(state: &AppState, req: Request<B>) -> Reply
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    if req.uri().path() == "/healthz" && *req.method() == Method::GET {
        return healthz();
    }
    let Some(segment) = key_segment(req.uri().path()) else {
        return status_only(StatusCode::NOT_FOUND);
    };
    if let Err(err) = state.authorize(req.headers()) {
        return err.into_reply();
    }
    let key = match parse_key_segment(segment) {
        Ok(key) => key,
        Err(err) => return err.into_reply(),
    };
    match *req.method() {
        Method::GET => get_value(state, key, false),
        Method::HEAD => get_value(state, key, true),
        Method::DELETE => delete_value(state, key),
        Method::PUT => put_value(state, key, req).await,
        _ => {
            let mut response = status_only(StatusCode::METHOD_NOT_ALLOWED);
            response.headers_mut().insert(
                header::ALLOW,
                HeaderValue::from_static("GET, HEAD, PUT, DELETE"),
            );
            response
        }
    }
}

fn healthz() -> Reply {
    let mut response = Response::new(Full::new(Bytes::from_static(b"ok")));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    response
}

fn get_value(state: &AppState, key: Key, head: bool) -> Reply {
    match state.cache.get(key) {
        Some(value) => ok_bytes(&value, head),
        None => ApiError::NotFound.into_reply(),
    }
}

fn ok_bytes(value: &[u8], head: bool) -> Reply {
    let mut len = itoa::Buffer::new();
    let content_len = HeaderValue::from_str(len.format(value.len())).expect("itoa is ascii");
    let mut response = if head {
        Response::new(Full::new(Bytes::new()))
    } else {
        Response::new(Full::new(Bytes::copy_from_slice(value)))
    };
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::CONTENT_LENGTH, content_len);
    response
}

fn delete_value(state: &AppState, key: Key) -> Reply {
    if state.cache.delete(key) {
        status_only(StatusCode::NO_CONTENT)
    } else {
        ApiError::NotFound.into_reply()
    }
}

async fn put_value<B>(state: &AppState, key: Key, req: Request<B>) -> Reply
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    if let Some(len) = content_length(req.headers())
        && len > state.max_value_bytes
    {
        return ApiError::PayloadTooLarge.into_reply();
    }
    let media = match media_kind(req.headers().get(header::CONTENT_TYPE)) {
        Ok(media) => media,
        Err(err) => return err.into_reply(),
    };
    let body = match Limited::new(req.into_body(), state.max_value_bytes)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return ApiError::PayloadTooLarge.into_reply(),
    };
    if body.len() > state.max_value_bytes {
        return ApiError::PayloadTooLarge.into_reply();
    }
    if matches!(media, MediaKind::Text) && std::str::from_utf8(&body).is_err() {
        return ApiError::InvalidUtf8.into_reply();
    }
    match state.cache.put(key, &body) {
        Ok(()) => status_only(StatusCode::NO_CONTENT),
        Err(err) => ApiError::from(err).into_reply(),
    }
}

fn status_only(status: StatusCode) -> Reply {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    response
}

fn key_segment(path: &str) -> Option<&str> {
    let rest = path
        .strip_prefix("/k/")
        .or_else(|| path.strip_prefix("/v1/keys/"))?;
    if rest.is_empty() || rest.as_bytes().contains(&b'/') {
        return None;
    }
    Some(rest)
}

fn parse_key_segment(raw: &str) -> Result<Key, ApiError> {
    if raw.as_bytes().contains(&b'%') {
        decode_key(raw)
    } else {
        Key::parse(raw).map_err(ApiError::from)
    }
}

fn decode_key(raw: &str) -> Result<Key, ApiError> {
    let mut buf = [0u8; MAX_KEY_BYTES];
    let mut len = 0usize;
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let byte = if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(ApiError::InvalidKey);
            }
            let decoded = hex_byte(bytes[i + 1], bytes[i + 2]).ok_or(ApiError::InvalidKey)?;
            i += 3;
            decoded
        } else {
            let b = bytes[i];
            i += 1;
            b
        };
        if len >= MAX_KEY_BYTES {
            return Err(ApiError::InvalidKey);
        }
        buf[len] = byte;
        len += 1;
    }
    Key::from_bytes(&buf[..len]).map_err(ApiError::from)
}

fn hex_byte(hi: u8, lo: u8) -> Option<u8> {
    Some((hex_nibble(hi)? << 4) | hex_nibble(lo)?)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn content_length(headers: &HeaderMap) -> Option<usize> {
    headers
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

enum MediaKind {
    Bytes,
    Text,
}

fn media_kind(value: Option<&HeaderValue>) -> Result<MediaKind, ApiError> {
    let Some(value) = value else {
        return Ok(MediaKind::Bytes);
    };
    let Ok(value) = value.to_str() else {
        return Err(ApiError::UnsupportedMediaType);
    };
    let mut parts = value.split(';');
    let essence = parts.next().unwrap_or("").trim();
    if essence.eq_ignore_ascii_case("application/octet-stream") {
        return Ok(MediaKind::Bytes);
    }
    if essence.eq_ignore_ascii_case("text/plain") {
        for param in parts {
            let mut pair = param.splitn(2, '=');
            let name = pair.next().unwrap_or("").trim();
            let raw_value = pair.next().unwrap_or("").trim().trim_matches('"');
            if name.eq_ignore_ascii_case("charset")
                && !raw_value.eq_ignore_ascii_case("utf-8")
                && !raw_value.eq_ignore_ascii_case("us-ascii")
            {
                return Err(ApiError::UnsupportedMediaType);
            }
        }
        return Ok(MediaKind::Text);
    }
    Err(ApiError::UnsupportedMediaType)
}

fn presented_token(header: &str) -> Option<&str> {
    let (scheme, token) = header.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        return None;
    }
    Some(token)
}

enum ApiError {
    Unauthorized,
    InvalidKey,
    NotFound,
    PayloadTooLarge,
    InvalidUtf8,
    UnsupportedMediaType,
}

impl From<StoreError> for ApiError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::EmptyKey | StoreError::KeyTooLong => Self::InvalidKey,
            StoreError::ValueTooLarge => Self::PayloadTooLarge,
        }
    }
}

impl ApiError {
    fn into_reply(self) -> Reply {
        let (status, body): (StatusCode, &'static [u8]) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, br#"{"error":"unauthorized"}"#),
            Self::InvalidKey => (StatusCode::BAD_REQUEST, br#"{"error":"invalid_key"}"#),
            Self::NotFound => (StatusCode::NOT_FOUND, br#"{"error":"not_found"}"#),
            Self::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                br#"{"error":"payload_too_large"}"#,
            ),
            Self::InvalidUtf8 => (StatusCode::BAD_REQUEST, br#"{"error":"invalid_utf8"}"#),
            Self::UnsupportedMediaType => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                br#"{"error":"unsupported_media_type"}"#,
            ),
        };
        let mut response = Response::new(Full::new(Bytes::from_static(body)));
        *response.status_mut() = status;
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MAX_KEY_BYTES;

    fn test_state(max_value_bytes: usize) -> AppState {
        AppState {
            cache: Arc::new(MemoryCache::new(max_value_bytes)),
            tokens: Arc::from([String::from("alpha"), String::from("beta")]),
            max_value_bytes,
        }
    }

    async fn call(state: &AppState, request: Request<Full<Bytes>>) -> Reply {
        dispatch(state, request).await
    }

    async fn body_bytes(response: Reply) -> Bytes {
        response.into_body().collect().await.unwrap().to_bytes()
    }

    fn put_request(
        prefix: &str,
        key: &str,
        token: &str,
        content_type: &str,
        body: &[u8],
    ) -> Request<Full<Bytes>> {
        Request::builder()
            .method("PUT")
            .uri(format!("{prefix}/{key}"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_LENGTH, body.len())
            .body(Full::new(Bytes::copy_from_slice(body)))
            .unwrap()
    }

    #[tokio::test]
    async fn healthz_does_not_require_auth() {
        let response = call(
            &test_state(64),
            Request::builder()
                .uri("/healthz")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_bytes(response).await.as_ref(), b"ok");
    }

    #[tokio::test]
    async fn rejects_missing_and_wrong_credentials() {
        let state = test_state(64);
        let missing = call(
            &state,
            Request::builder()
                .uri("/v1/keys/user")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await;
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            missing.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Bearer"
        );

        let wrong = call(
            &state,
            put_request("/v1/keys", "user", "nope", "application/octet-stream", b"v"),
        )
        .await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

        let basic = call(
            &state,
            Request::builder()
                .uri("/k/user")
                .header(header::AUTHORIZATION, "Basic alpha")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await;
        assert_eq!(basic.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn put_get_head_delete_roundtrip() {
        let state = test_state(64);
        let created = call(
            &state,
            put_request(
                "/v1/keys",
                "user:42",
                "beta",
                "application/octet-stream",
                b"cached-value",
            ),
        )
        .await;
        assert_eq!(created.status(), StatusCode::NO_CONTENT);

        let fetched = call(
            &state,
            Request::builder()
                .uri("/k/user:42")
                .header(header::AUTHORIZATION, "Bearer alpha")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await;
        assert_eq!(fetched.status(), StatusCode::OK);
        assert_eq!(
            fetched.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
        assert_eq!(body_bytes(fetched).await.as_ref(), b"cached-value");

        let head = call(
            &state,
            Request::builder()
                .method("HEAD")
                .uri("/v1/keys/user:42")
                .header(header::AUTHORIZATION, "Bearer alpha")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await;
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(head.headers().get(header::CONTENT_LENGTH).unwrap(), "12");
        assert!(body_bytes(head).await.is_empty());

        let deleted = call(
            &state,
            Request::builder()
                .method("DELETE")
                .uri("/k/user:42")
                .header(header::AUTHORIZATION, "Bearer alpha")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await;
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

        let missing = call(
            &state,
            Request::builder()
                .method("DELETE")
                .uri("/v1/keys/user:42")
                .header(header::AUTHORIZATION, "Bearer alpha")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_missing_is_404() {
        let response = call(
            &test_state(64),
            Request::builder()
                .uri("/v1/keys/missing")
                .header(header::AUTHORIZATION, "Bearer alpha")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_bytes(response).await.as_ref(),
            br#"{"error":"not_found"}"#
        );
    }

    #[tokio::test]
    async fn rejects_overlong_keys_and_bad_media() {
        let state = test_state(64);
        let key = "a".repeat(MAX_KEY_BYTES + 1);
        let too_long = call(
            &state,
            put_request("/v1/keys", &key, "alpha", "text/plain", b"hello"),
        )
        .await;
        assert_eq!(too_long.status(), StatusCode::BAD_REQUEST);

        let json = call(
            &state,
            put_request("/k", "ok", "alpha", "application/json", b"{}"),
        )
        .await;
        assert_eq!(json.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let text = call(
            &state,
            put_request("/k", "ok", "alpha", "text/plain; charset=utf-8", b"hello"),
        )
        .await;
        assert_eq!(text.status(), StatusCode::NO_CONTENT);

        let invalid = call(
            &state,
            put_request("/k", "ok", "alpha", "text/plain", &[0xff, 0xfe]),
        )
        .await;
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_bytes(invalid).await.as_ref(),
            br#"{"error":"invalid_utf8"}"#
        );
    }

    #[tokio::test]
    async fn percent_decoded_key_and_missing_content_type() {
        let state = test_state(64);
        let request = Request::builder()
            .method("PUT")
            .uri("/v1/keys/a%2Fb")
            .header(header::AUTHORIZATION, "Bearer alpha")
            .body(Full::new(Bytes::from_static(b"slash")))
            .unwrap();
        assert_eq!(call(&state, request).await.status(), StatusCode::NO_CONTENT);

        let fetched = call(
            &state,
            Request::builder()
                .uri("/k/a%2Fb")
                .header(header::AUTHORIZATION, "Bearer alpha")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await;
        assert_eq!(body_bytes(fetched).await.as_ref(), b"slash");
    }

    #[tokio::test]
    async fn rejects_bodies_over_the_limit() {
        let state = test_state(4);
        let response = call(
            &state,
            put_request(
                "/v1/keys",
                "k",
                "alpha",
                "application/octet-stream",
                b"12345",
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let accepted = call(
            &state,
            put_request("/k", "k", "alpha", "application/octet-stream", b"1234"),
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::NO_CONTENT);
    }
}

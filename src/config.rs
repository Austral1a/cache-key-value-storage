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

//! Process configuration from the environment.
//!
//! External clients must reach this process through TLS. Terminate TLS at a
//! reverse proxy (Caddy, nginx, or Envoy) and point it at `CACHE_LISTEN`.
//! Prefer a private bind address when the proxy runs on the same host.
//! Do not publish the listen port directly on the public internet.

use std::env;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::policy::{ExpirationKind, ReplacementKind};
use crate::store::MAX_VALUE_BYTES;

const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
const DEFAULT_MAX_CONNS: usize = 1024;
const DEFAULT_IDLE_SECS: u64 = 60;
const MAX_CONNS_LIMIT: usize = 1_048_576;
const MAX_IDLE_SECS: u64 = 86_400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub listen: SocketAddr,
    /// CKV1 listen address. `None` leaves TCP CKV off.
    pub ckv_listen: Option<SocketAddr>,
    /// CKV1 unix socket. Same frames as TCP. `None` leaves it off.
    pub ckv_socket: Option<PathBuf>,
    pub tokens: Vec<String>,
    pub max_value_bytes: usize,
    pub capacity: usize,
    pub replacement: ReplacementKind,
    pub expiration: ExpirationKind,
    pub max_keys: usize,
    pub max_bytes: usize,
    /// HTTP and CKV connections combined. Extra accepts are closed.
    pub max_conns: usize,
    /// Idle read timeout. `Duration::ZERO` disables it.
    pub idle_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    MissingTokens,
    InvalidListen(String),
    InvalidCkvListen(String),
    InvalidCkvSocket,
    InvalidToken,
    InvalidMaxValue,
    InvalidCapacity,
    InvalidReplacement,
    InvalidExpiration,
    InvalidMaxKeys,
    InvalidMaxBytes,
    LruRequiresCap,
    CapRequiresLru,
    InvalidMaxConns,
    InvalidIdleTimeout,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let listen = match env::var("CACHE_LISTEN") {
            Ok(value) => value,
            Err(env::VarError::NotPresent) => DEFAULT_LISTEN.to_owned(),
            Err(env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::InvalidListen("not utf-8".to_owned()));
            }
        };
        let tokens = match env::var("CACHE_AUTH_TOKENS") {
            Ok(value) => value,
            Err(env::VarError::NotPresent) => return Err(ConfigError::MissingTokens),
            Err(env::VarError::NotUnicode(_)) => return Err(ConfigError::InvalidToken),
        };
        let max_value = match env::var("CACHE_MAX_VALUE_BYTES") {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => return Err(ConfigError::InvalidMaxValue),
        };
        let capacity = match env::var("CACHE_CAPACITY") {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => return Err(ConfigError::InvalidCapacity),
        };
        let ckv_listen = match env::var("CACHE_CKV_LISTEN") {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::InvalidCkvListen("not utf-8".to_owned()));
            }
        };
        let ckv_socket = match env::var("CACHE_CKV_SOCKET") {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => return Err(ConfigError::InvalidCkvSocket),
        };
        let max_conns = match env::var("CACHE_MAX_CONNS") {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => return Err(ConfigError::InvalidMaxConns),
        };
        let idle_timeout = match env::var("CACHE_IDLE_TIMEOUT_SECS") {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => return Err(ConfigError::InvalidIdleTimeout),
        };
        let replacement = match env::var("CACHE_REPLACEMENT") {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => return Err(ConfigError::InvalidReplacement),
        };
        let expiration = match env::var("CACHE_EXPIRATION") {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => return Err(ConfigError::InvalidExpiration),
        };
        let max_keys = match env::var("CACHE_MAX_KEYS") {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => return Err(ConfigError::InvalidMaxKeys),
        };
        let max_bytes = match env::var("CACHE_MAX_BYTES") {
            Ok(value) => Some(value),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => return Err(ConfigError::InvalidMaxBytes),
        };
        let mut config =
            Self::from_parts(&listen, &tokens, max_value.as_deref(), capacity.as_deref())?;
        config.ckv_listen = parse_ckv_listen(ckv_listen.as_deref())?;
        config.ckv_socket = parse_ckv_socket(ckv_socket.as_deref())?;
        if let Some(raw) = max_conns.as_deref() {
            config.max_conns = parse_max_conns(raw)?;
        }
        if let Some(raw) = idle_timeout.as_deref() {
            config.idle_timeout = parse_idle_timeout(raw)?;
        }
        if let Some(raw) = replacement.as_deref() {
            config.replacement = parse_replacement(raw)?;
        }
        if let Some(raw) = expiration.as_deref() {
            config.expiration = parse_expiration(raw)?;
        }
        if let Some(raw) = max_keys.as_deref() {
            config.max_keys = parse_max_keys(raw)?;
        }
        if let Some(raw) = max_bytes.as_deref() {
            config.max_bytes = parse_max_bytes(raw)?;
        }
        validate_policy(config.replacement, config.max_keys, config.max_bytes)?;
        Ok(config)
    }

    pub(crate) fn from_parts(
        listen: &str,
        tokens: &str,
        max_value_bytes: Option<&str>,
        capacity: Option<&str>,
    ) -> Result<Self, ConfigError> {
        let listen = listen
            .parse()
            .map_err(|_| ConfigError::InvalidListen(listen.to_owned()))?;
        let tokens = parse_tokens(tokens)?;
        let max_value_bytes = match max_value_bytes {
            None => MAX_VALUE_BYTES,
            Some(raw) => parse_max_value(raw)?,
        };
        let capacity = match capacity {
            None => 0,
            Some(raw) => parse_capacity(raw)?,
        };
        Ok(Self {
            listen,
            ckv_listen: None,
            ckv_socket: None,
            tokens,
            max_value_bytes,
            capacity,
            replacement: ReplacementKind::None,
            expiration: ExpirationKind::None,
            max_keys: 0,
            max_bytes: 0,
            max_conns: DEFAULT_MAX_CONNS,
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_SECS),
        })
    }
}

fn parse_ckv_socket(raw: Option<&str>) -> Result<Option<PathBuf>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.is_empty() || raw.contains('\0') {
        return Err(ConfigError::InvalidCkvSocket);
    }
    Ok(Some(PathBuf::from(raw)))
}

fn parse_ckv_listen(raw: Option<&str>) -> Result<Option<SocketAddr>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    raw.parse()
        .map(Some)
        .map_err(|_| ConfigError::InvalidCkvListen(raw.to_owned()))
}

fn parse_tokens(raw: &str) -> Result<Vec<String>, ConfigError> {
    let mut tokens = Vec::new();
    for part in raw.split(',') {
        let token = part.trim();
        if token.is_empty() || token.chars().any(char::is_whitespace) {
            return Err(ConfigError::InvalidToken);
        }
        if !tokens.iter().any(|existing| existing == token) {
            tokens.push(token.to_owned());
        }
    }
    Ok(tokens)
}

fn parse_max_value(raw: &str) -> Result<usize, ConfigError> {
    let value: usize = raw.parse().map_err(|_| ConfigError::InvalidMaxValue)?;
    if (1..=MAX_VALUE_BYTES).contains(&value) {
        Ok(value)
    } else {
        Err(ConfigError::InvalidMaxValue)
    }
}

fn parse_capacity(raw: &str) -> Result<usize, ConfigError> {
    raw.parse().map_err(|_| ConfigError::InvalidCapacity)
}

fn parse_replacement(raw: &str) -> Result<ReplacementKind, ConfigError> {
    ReplacementKind::parse(raw).ok_or(ConfigError::InvalidReplacement)
}

fn parse_expiration(raw: &str) -> Result<ExpirationKind, ConfigError> {
    ExpirationKind::parse(raw).ok_or(ConfigError::InvalidExpiration)
}

fn parse_max_keys(raw: &str) -> Result<usize, ConfigError> {
    raw.parse().map_err(|_| ConfigError::InvalidMaxKeys)
}

fn parse_max_bytes(raw: &str) -> Result<usize, ConfigError> {
    raw.parse().map_err(|_| ConfigError::InvalidMaxBytes)
}

fn validate_policy(
    replacement: ReplacementKind,
    max_keys: usize,
    max_bytes: usize,
) -> Result<(), ConfigError> {
    let has_cap = max_keys > 0 || max_bytes > 0;
    match (replacement, has_cap) {
        (ReplacementKind::Lru, false) => Err(ConfigError::LruRequiresCap),
        (ReplacementKind::None, true) => Err(ConfigError::CapRequiresLru),
        _ => Ok(()),
    }
}

fn parse_max_conns(raw: &str) -> Result<usize, ConfigError> {
    let value: usize = raw.parse().map_err(|_| ConfigError::InvalidMaxConns)?;
    if (1..=MAX_CONNS_LIMIT).contains(&value) {
        Ok(value)
    } else {
        Err(ConfigError::InvalidMaxConns)
    }
}

fn parse_idle_timeout(raw: &str) -> Result<Duration, ConfigError> {
    let secs: u64 = raw.parse().map_err(|_| ConfigError::InvalidIdleTimeout)?;
    if secs > MAX_IDLE_SECS {
        return Err(ConfigError::InvalidIdleTimeout);
    }
    Ok(Duration::from_secs(secs))
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTokens => {
                f.write_str("CACHE_AUTH_TOKENS is required and must list one or more bearer tokens")
            }
            Self::InvalidListen(value) => {
                write!(f, "CACHE_LISTEN must be a socket address, got {value}")
            }
            Self::InvalidCkvListen(value) => {
                write!(f, "CACHE_CKV_LISTEN must be a socket address, got {value}")
            }
            Self::InvalidCkvSocket => {
                f.write_str("CACHE_CKV_SOCKET must be a non-empty filesystem path")
            }
            Self::InvalidToken => f.write_str(
                "each CACHE_AUTH_TOKENS entry must be non-empty and must not contain whitespace",
            ),
            Self::InvalidMaxValue => write!(
                f,
                "CACHE_MAX_VALUE_BYTES must be an integer from 1 to {MAX_VALUE_BYTES}"
            ),
            Self::InvalidCapacity => {
                f.write_str("CACHE_CAPACITY must be a non-negative integer (0 means no pre-size)")
            }
            Self::InvalidReplacement => f.write_str("CACHE_REPLACEMENT must be none or lru"),
            Self::InvalidExpiration => f.write_str("CACHE_EXPIRATION must be none"),
            Self::InvalidMaxKeys => {
                f.write_str("CACHE_MAX_KEYS must be a non-negative integer (0 means no cap)")
            }
            Self::InvalidMaxBytes => {
                f.write_str("CACHE_MAX_BYTES must be a non-negative integer (0 means no cap)")
            }
            Self::LruRequiresCap => {
                f.write_str("CACHE_REPLACEMENT=lru requires CACHE_MAX_KEYS and/or CACHE_MAX_BYTES")
            }
            Self::CapRequiresLru => {
                f.write_str("CACHE_MAX_KEYS and CACHE_MAX_BYTES require CACHE_REPLACEMENT=lru")
            }
            Self::InvalidMaxConns => write!(
                f,
                "CACHE_MAX_CONNS must be an integer from 1 to {MAX_CONNS_LIMIT}"
            ),
            Self::InvalidIdleTimeout => write!(
                f,
                "CACHE_IDLE_TIMEOUT_SECS must be an integer from 0 to {MAX_IDLE_SECS} (0 disables)"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_listen_and_value_limit() {
        let config = Config::from_parts("127.0.0.1:9", "alpha", None, None).unwrap();
        assert_eq!(config.listen.to_string(), "127.0.0.1:9");
        assert!(config.ckv_listen.is_none());
        assert_eq!(config.tokens, vec!["alpha".to_owned()]);
        assert_eq!(config.max_value_bytes, MAX_VALUE_BYTES);
        assert_eq!(config.capacity, 0);
        assert_eq!(config.replacement, ReplacementKind::None);
        assert_eq!(config.expiration, ExpirationKind::None);
        assert_eq!(config.max_keys, 0);
        assert_eq!(config.max_bytes, 0);
        assert_eq!(config.max_conns, DEFAULT_MAX_CONNS);
        assert_eq!(config.idle_timeout, Duration::from_secs(DEFAULT_IDLE_SECS));
        assert_eq!(DEFAULT_LISTEN, "127.0.0.1:8080");
    }

    #[test]
    fn parses_multiple_tokens_limit_and_capacity() {
        let config = Config::from_parts(
            "0.0.0.0:8080",
            " alpha, beta ,alpha ",
            Some("1024"),
            Some("10000"),
        )
        .unwrap();
        assert_eq!(config.tokens, vec!["alpha".to_owned(), "beta".to_owned()]);
        assert_eq!(config.max_value_bytes, 1024);
        assert_eq!(config.capacity, 10_000);
    }

    #[test]
    fn rejects_bad_listen_tokens_and_limits() {
        assert!(matches!(
            Config::from_parts("not-an-addr", "alpha", None, None),
            Err(ConfigError::InvalidListen(_))
        ));
        assert_eq!(
            Config::from_parts("127.0.0.1:1", "", None, None),
            Err(ConfigError::InvalidToken)
        );
        assert_eq!(
            Config::from_parts("127.0.0.1:1", "has space", None, None),
            Err(ConfigError::InvalidToken)
        );
        assert_eq!(
            Config::from_parts("127.0.0.1:1", "alpha", Some("0"), None),
            Err(ConfigError::InvalidMaxValue)
        );
        assert_eq!(
            Config::from_parts(
                "127.0.0.1:1",
                "alpha",
                Some(&(MAX_VALUE_BYTES + 1).to_string()),
                None
            ),
            Err(ConfigError::InvalidMaxValue)
        );
        assert_eq!(
            Config::from_parts("127.0.0.1:1", "alpha", None, Some("nope")),
            Err(ConfigError::InvalidCapacity)
        );
        assert_eq!(parse_max_conns("0"), Err(ConfigError::InvalidMaxConns));
        assert_eq!(parse_max_conns("1024"), Ok(1024));
        assert_eq!(
            parse_idle_timeout("86401"),
            Err(ConfigError::InvalidIdleTimeout)
        );
        assert_eq!(parse_idle_timeout("0"), Ok(Duration::ZERO));
        assert_eq!(parse_idle_timeout("60"), Ok(Duration::from_secs(60)));
    }

    #[test]
    fn lru_requires_a_cap() {
        assert_eq!(
            validate_policy(ReplacementKind::Lru, 0, 0),
            Err(ConfigError::LruRequiresCap)
        );
        assert_eq!(
            validate_policy(ReplacementKind::None, 10, 0),
            Err(ConfigError::CapRequiresLru)
        );
        assert!(validate_policy(ReplacementKind::Lru, 10, 0).is_ok());
        assert!(validate_policy(ReplacementKind::Lru, 0, 1024).is_ok());
        assert!(validate_policy(ReplacementKind::None, 0, 0).is_ok());
    }

    #[test]
    fn parses_replacement_expiration_and_caps() {
        assert_eq!(parse_replacement("lru"), Ok(ReplacementKind::Lru));
        assert_eq!(parse_replacement("none"), Ok(ReplacementKind::None));
        assert_eq!(
            parse_replacement("lfu"),
            Err(ConfigError::InvalidReplacement)
        );
        assert_eq!(parse_expiration("none"), Ok(ExpirationKind::None));
        assert_eq!(parse_expiration("ttl"), Err(ConfigError::InvalidExpiration));
        assert_eq!(parse_max_keys("100"), Ok(100));
        assert_eq!(parse_max_keys("nope"), Err(ConfigError::InvalidMaxKeys));
        assert_eq!(parse_max_bytes("4096"), Ok(4096));
        assert_eq!(parse_max_bytes("nope"), Err(ConfigError::InvalidMaxBytes));
    }

    #[test]
    fn ckv_listen_is_optional() {
        assert!(parse_ckv_listen(None).unwrap().is_none());
        assert_eq!(
            parse_ckv_listen(Some("127.0.0.1:9090"))
                .unwrap()
                .unwrap()
                .to_string(),
            "127.0.0.1:9090"
        );
        assert!(matches!(
            parse_ckv_listen(Some("nope")),
            Err(ConfigError::InvalidCkvListen(_))
        ));
    }
}

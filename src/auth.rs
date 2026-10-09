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

//! Bearer-token compare used by HTTP and CKV1.

pub fn token_accepted(presented: &[u8], tokens: &[String]) -> bool {
    let mut matched = 0u8;
    for token in tokens {
        matched |= u8::from(constant_time_eq(presented, token.as_bytes()));
    }
    matched != 0
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let n = left.len().max(right.len());
    for i in 0..n {
        let l = left.get(i).copied().unwrap_or(0);
        let r = right.get(i).copied().unwrap_or(0);
        diff |= usize::from(l ^ r);
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_any_configured_token() {
        let tokens = [String::from("alpha"), String::from("beta")];
        assert!(token_accepted(b"alpha", &tokens));
        assert!(token_accepted(b"beta", &tokens));
        assert!(!token_accepted(b"nope", &tokens));
    }

    #[test]
    fn length_mismatch_is_rejected() {
        assert!(!constant_time_eq(b"ab", b"abc"));
        assert!(constant_time_eq(b"ab", b"ab"));
    }
}

//! Time-limited TURN credentials of the "TURN REST API" (draft-uberti-behave-turn-rest-00,
//! section 2.2; coturn's `use-auth-secret` / `static-auth-secret`): the username is the
//! credential's expiry as a Unix timestamp, optionally followed by a separator and an
//! application-chosen id (`1735689600:alice`), and the password is base64(HMAC(secret,
//! username)). A server that checks the timestamp on every authenticated request (coturn does,
//! on Refresh, CreatePermission and ChannelBind as well as Allocate) ends an allocation whose
//! username has expired at its next refresh, so an application rotates the credentials before
//! then (`RTCPeerConnection::rotate_ice_servers` in `rtci`).
//!
//! The draft is an expired individual draft, not an RFC, and nothing in TURN obliges a server
//! to use this format: the client and the engine never look inside a username. This module is
//! a pure helper for applications that know their server does.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// When the REST username `username` expires: its leading Unix timestamp, before the first
/// `separator` (coturn's `--rest-api-separator`, `:` by default) or the whole username when
/// it has none. `None` when that part is not a decimal number of seconds.
///
/// ```
/// use std::time::{Duration, UNIX_EPOCH};
/// use rtci_turn::rest::rest_username_expiry;
///
/// assert_eq!(
///     rest_username_expiry("1735689600:alice", ':'),
///     Some(UNIX_EPOCH + Duration::from_secs(1_735_689_600))
/// );
/// assert_eq!(
///     rest_username_expiry("1735689600", ':'),
///     Some(UNIX_EPOCH + Duration::from_secs(1_735_689_600))
/// );
/// assert_eq!(rest_username_expiry("alice", ':'), None);
/// ```
pub fn rest_username_expiry(username: &str, separator: char) -> Option<SystemTime> {
    let timestamp = username.split(separator).next()?;
    if timestamp.is_empty() || !timestamp.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let seconds: u64 = timestamp.parse().ok()?;
    UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: u64) -> Option<SystemTime> {
        Some(UNIX_EPOCH + Duration::from_secs(s))
    }

    #[test]
    fn the_timestamp_before_the_separator_is_the_expiry() {
        assert_eq!(
            rest_username_expiry("1800000600:host-7", ':'),
            at(1_800_000_600)
        );
        assert_eq!(
            rest_username_expiry("1800000600:a:b", ':'),
            at(1_800_000_600)
        );
        assert_eq!(rest_username_expiry("1800000600", ':'), at(1_800_000_600));
        assert_eq!(rest_username_expiry("1800000600-x", '-'), at(1_800_000_600));
        assert_eq!(rest_username_expiry("0", ':'), at(0));
    }

    #[test]
    fn a_username_without_a_leading_timestamp_has_none() {
        for username in [
            "",
            ":1800000600",
            "alice",
            "alice:1800000600",
            "+1800000600",
            " 1",
            "1.5",
            "18446744073709551616",
        ] {
            assert_eq!(rest_username_expiry(username, ':'), None, "{username:?}");
        }
        assert_eq!(
            rest_username_expiry("1800000600:x", '-'),
            None,
            "another separator"
        );
    }
}

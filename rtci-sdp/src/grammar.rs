//! The terminals of the RFC 8866 section 9 grammar, shared by the line parser and by the typed
//! attributes.
//!
//! Every function here is a predicate or a checked conversion over one field: none allocates
//! more than its result, none reads past the string it is given.

use shared::error::{Error, Result};

/// `SdpInvalidSyntax` for a `what` that `value` is not.
pub(crate) fn syntax(what: &str, value: &str) -> Error {
    Error::SdpInvalidSyntax(format!("{what}: `{}`", abbreviate(value)))
}

/// `SdpInvalidValue` for a `what` whose `value` is well formed but out of range.
pub(crate) fn invalid(what: &str, value: &str) -> Error {
    Error::SdpInvalidValue(format!("{what}: `{}`", abbreviate(value)))
}

/// Error text quotes at most this much of the offending input.
const MAX_QUOTED: usize = 96;

fn abbreviate(value: &str) -> &str {
    if value.len() <= MAX_QUOTED {
        return value;
    }
    let mut end = MAX_QUOTED;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// `token-char`.
pub(crate) fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
        )
}

/// `token = 1*(token-char)`.
pub(crate) fn is_token(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(is_token_char)
}

/// `byte-string = 1*(%x01-09/%x0B-0C/%x0E-FF)`: anything but NUL, CR and LF, not empty.
pub(crate) fn is_byte_string(value: &str) -> bool {
    !value.is_empty() && !value.bytes().any(|b| matches!(b, 0 | b'\r' | b'\n'))
}

/// `non-ws-string = 1*(VCHAR/%x80-FF)`.
pub(crate) fn is_non_ws_string(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b > 0x20 && b != 0x7f)
}

/// `1*DIGIT`.
pub(crate) fn is_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

/// `integer = POS-DIGIT *DIGIT`.
pub(crate) fn is_integer(value: &str) -> bool {
    is_digits(value) && !value.starts_with('0')
}

/// `1*255(alpha-numeric)`: an RFC 8851 `rid-id` as corrected by erratum 7132 (Verified
/// 2022-10-13), "consistent with the rules for the RtpStreamId/RepairedRtpStreamId SDES from
/// RFC 8852 section 3" (255 octets, bytes 48-57, 65-90, 97-122).
pub(crate) fn is_rid_id(value: &str) -> bool {
    (1..=255).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// `1*(alpha-numeric / "-" / "_")`: an RFC 4585 `rtcp-fb-id`, and the `rid-id` of RFC 8851
/// section 10 as published (before erratum 7132).
pub(crate) fn is_alnum_dash_underscore(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// `1*DIGIT` that fits the integer type, with `what` naming the field in the error.
pub(crate) fn digits<T: core::str::FromStr>(what: &str, value: &str) -> Result<T> {
    if !is_digits(value) {
        return Err(syntax(what, value));
    }
    value.parse::<T>().map_err(|_| invalid(what, value))
}

/// `1*DIGIT` without leading zeroes ("0" itself is fine), that fits the integer type.
pub(crate) fn digits_no_leading_zero<T: core::str::FromStr>(what: &str, value: &str) -> Result<T> {
    if value.len() > 1 && value.starts_with('0') {
        return Err(syntax(what, value));
    }
    digits(what, value)
}

/// `non-zero-int-or-real = integer / non-zero-real`, with
/// `non-zero-real = zero-based-integer "." *DIGIT POS-DIGIT`.
pub(crate) fn is_non_zero_int_or_real(value: &str) -> bool {
    match value.split_once('.') {
        None => is_integer(value),
        Some((int, frac)) => {
            (int == "0" || is_integer(int))
                && is_digits(frac)
                && !frac.ends_with('0')
                && frac.bytes().all(|b| b.is_ascii_digit())
        }
    }
}

/// `decimal-uchar`: 0 to 255 without a leading zero.
fn decimal_uchar(value: &str) -> Option<u8> {
    if value.is_empty() || value.len() > 3 || !is_digits(value) {
        return None;
    }
    if value.len() > 1 && value.starts_with('0') {
        return None;
    }
    value.parse::<u8>().ok()
}

/// The four `decimal-uchar` of a dotted quad.
fn dotted_quad(value: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = value.split('.');
    for slot in &mut out {
        *slot = decimal_uchar(parts.next()?)?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

/// `IP4-address = b1 3("." decimal-uchar)`, `b1` "less than 224": a unicast IPv4 address.
pub(crate) fn is_ip4_address(value: &str) -> bool {
    matches!(dotted_quad(value), Some(q) if q[0] < 224)
}

/// The address part of `IP4-multicast`: 224.0.0.0 to 239.255.255.255.
pub(crate) fn is_ip4_multicast_address(value: &str) -> bool {
    matches!(dotted_quad(value), Some(q) if (224..=239).contains(&q[0]))
}

/// `IP6-address`. A zone identifier is not part of the grammar and is refused.
pub(crate) fn is_ip6_address(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        && value.parse::<std::net::Ipv6Addr>().is_ok()
}

/// An `IP6-address` "starting with FF".
pub(crate) fn is_ip6_multicast_address(value: &str) -> bool {
    matches!(value.parse::<std::net::Ipv6Addr>(), Ok(a) if a.is_multicast())
        && is_ip6_address(value)
}

/// `FQDN = 4*(alpha-numeric / "-" / ".")`, and a domain name as RFC 8866 section 5 has it
/// ("MUST comply with [RFC1034] and [RFC1035]"): labels of 1 to 63 characters that neither
/// start nor end with a hyphen (RFC 1035 section 2.3.1, a leading digit allowed since RFC 1123
/// section 2.1), at most 253 characters in all, one final dot (the root) allowed.
pub(crate) fn is_fqdn(value: &str) -> bool {
    let name = value.strip_suffix('.').unwrap_or(value);
    value.len() >= 4
        && name.len() <= 253
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len()) && !label.starts_with('-') && !label.ends_with('-')
        })
}

/// `unicast-address` for an address type: `IP4-address / IP6-address / FQDN / extn-addr`.
///
/// For the two address types RFC 8866 defines, the address has to be of that family or a
/// domain name; for any other registered address type it is an `extn-addr`
/// (`non-ws-string`), which only the application that knows the type can check.
pub(crate) fn is_unicast_address(address_type: &str, value: &str) -> bool {
    match address_type {
        "IP4" => is_ip4_address(value) || is_fqdn(value),
        "IP6" => is_ip6_address(value) || is_fqdn(value),
        _ => is_non_ws_string(value),
    }
}

/// `connection-address` as RFC 8839 uses it for candidates: an IPv4 or IPv6 address of
/// either family, or a domain name.
pub(crate) fn is_candidate_address(value: &str) -> bool {
    dotted_quad(value).is_some() || is_ip6_address(value) || is_fqdn(value)
}

/// `port = 1*DIGIT`, in the range a transport port has.
pub(crate) fn port(value: &str) -> Result<u16> {
    digits("port", value)
}

/// RFC 8839 `ice-char = ALPHA / DIGIT / "+" / "/"`.
pub(crate) fn is_ice_chars(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// `*VCHAR`.
pub(crate) fn is_vchars(value: &str) -> bool {
    value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// `base64 = *base64-unit [base64-pad]`.
pub(crate) fn is_base64(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return false;
    }
    let pad = bytes.iter().rev().take_while(|&&b| b == b'=').count();
    pad <= 2
        && bytes[..bytes.len() - pad]
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// Splits `value` at single spaces, refusing an empty field (two spaces in a row, or a space
/// at either end): `a SP b SP c`.
pub(crate) fn fields<'a>(what: &str, value: &'a str) -> Result<Vec<&'a str>> {
    let fields: Vec<&str> = value.split(' ').collect();
    if fields.iter().any(|f| f.is_empty()) {
        return Err(syntax(what, value));
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_the_rfc_8866_character_set() {
        assert!(is_token("UDP"));
        assert!(is_token("!#$%&'*+-.^_`{|}~aZ09"));
        for bad in [
            "", "a b", "a/b", "a:b", "a=b", "a(b", "a\"b", "é", "a@b", "a,b", "a;b",
        ] {
            assert!(!is_token(bad), "{bad}");
        }
    }

    #[test]
    fn byte_string_excludes_nul_cr_lf_and_the_empty_string() {
        assert!(is_byte_string(" "));
        assert!(is_byte_string("é\t\u{7f}"));
        for bad in ["", "a\0b", "a\rb", "a\nb"] {
            assert!(!is_byte_string(bad), "{bad:?}");
        }
    }

    #[test]
    fn non_zero_int_or_real_follows_the_abnf() {
        for good in ["1", "20", "0.5", "10.25", "0.001", "29.97"] {
            assert!(is_non_zero_int_or_real(good), "{good}");
        }
        // No zero, no leading zero, no trailing zero in the fraction, no bare point.
        for bad in [
            "0", "00", "01", "0.0", "1.0", "1.50", "1.", ".5", "-1", "1e3", "", "1.2.3",
        ] {
            assert!(!is_non_zero_int_or_real(bad), "{bad}");
        }
    }

    #[test]
    fn ip4_addresses_are_decimal_uchars_and_unicast_is_below_224() {
        assert!(is_ip4_address("0.0.0.0"));
        assert!(is_ip4_address("223.255.255.255"));
        assert!(!is_ip4_address("224.0.0.1"));
        assert!(is_ip4_multicast_address("224.0.0.1"));
        assert!(is_ip4_multicast_address("239.255.255.255"));
        assert!(!is_ip4_multicast_address("240.0.0.1"));
        for bad in [
            "1.2.3",
            "1.2.3.4.5",
            "01.2.3.4",
            "256.1.1.1",
            "1..2.3",
            "a.b.c.d",
            "",
        ] {
            assert!(!is_ip4_address(bad), "{bad}");
        }
    }

    #[test]
    fn ip6_addresses_follow_rfc_3986_and_have_no_zone() {
        for good in [
            "::",
            "::1",
            "2001:db8::1",
            "FF15::101",
            "::ffff:192.0.2.1",
            "1:2:3:4:5:6:7:8",
        ] {
            assert!(is_ip6_address(good), "{good}");
        }
        for bad in [
            "",
            "1.2.3.4",
            "fe80::1%eth0",
            "1:2:3:4:5:6:7:8:9",
            "g::1",
            "[::1]",
        ] {
            assert!(!is_ip6_address(bad), "{bad}");
        }
        assert!(is_ip6_multicast_address("FF15::101"));
        assert!(!is_ip6_multicast_address("2001:db8::1"));
    }

    #[test]
    fn unicast_address_depends_on_the_address_type() {
        assert!(is_unicast_address("IP4", "192.0.2.1"));
        assert!(is_unicast_address("IP4", "host.example.com"));
        assert!(!is_unicast_address("IP4", "::1"));
        assert!(is_unicast_address("IP6", "::1"));
        assert!(!is_unicast_address("IP6", "a b"));
        // An address type this crate does not know: any non-whitespace string.
        assert!(is_unicast_address("E164", "+15551234"));
        assert!(!is_unicast_address("E164", ""));
    }

    #[test]
    fn base64_needs_whole_units_and_at_most_two_pad_characters() {
        for good in ["", "QUJD", "QUI=", "QQ==", "ab+/"] {
            assert!(is_base64(good), "{good}");
        }
        for bad in ["QUJ", "Q===", "QU-D", "QUJD=", "====="] {
            assert!(!is_base64(bad), "{bad}");
        }
    }

    #[test]
    fn fields_are_separated_by_exactly_one_space() {
        assert_eq!(fields("x", "a b c").unwrap(), vec!["a", "b", "c"]);
        for bad in ["a  b", " a", "a ", ""] {
            assert!(fields("x", bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn digits_reports_syntax_and_range_separately() {
        assert_eq!(digits::<u8>("n", "255").unwrap(), 255);
        assert!(matches!(
            digits::<u8>("n", "256"),
            Err(Error::SdpInvalidValue(_))
        ));
        assert!(matches!(
            digits::<u8>("n", "+1"),
            Err(Error::SdpInvalidSyntax(_))
        ));
        assert!(digits_no_leading_zero::<u16>("n", "0").is_ok());
        assert!(digits_no_leading_zero::<u16>("n", "05").is_err());
    }
}

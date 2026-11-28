//! Typed, validated access to the attributes the WebRTC specifications use.
//!
//! [`SessionDescription::unmarshal`] keeps every `a=`
//! line as a name and a value: RFC 8866 section 5.13 has an attribute that is not understood
//! ignored, and the parser cannot know which ones its caller understands. This module is
//! where a value gets its grammar. Each type parses the value of one attribute against the
//! ABNF of the RFC that defines it and prints it back in the form that RFC gives.
//!
//! There are three ways in:
//!
//! * The accessors on [`SessionDescription`] and
//!   [`MediaDescription`]: `mid()`, `rtpmaps()`, `candidates()`,
//!   `fingerprints()`, `simulcast()` and so on. Each returns `Err` when the attribute is
//!   present and malformed, so a caller can tell "absent" from "broken".
//! * The generic `typed::<T>()` / `typed_all::<T>()` for any [`TypedAttribute`](crate::attribute::TypedAttribute).
//! * [`SessionDescription::validate`], which checks every
//!   known attribute of a description at once, together with the level each may appear at.
//!
//! | Attribute | Type | Defined in |
//! |---|---|---|
//! | `group` | [`Group`](crate::attribute::Group) | RFC 5888, RFC 9143 |
//! | `mid` | [`Mid`](crate::attribute::Mid) | RFC 5888 |
//! | `msid`, `msid-semantic` | [`Msid`](crate::attribute::Msid), [`MsidSemantic`](crate::attribute::MsidSemantic) | RFC 8830 |
//! | `ssrc`, `ssrc-group` | [`Ssrc`](crate::attribute::Ssrc), [`SsrcGroup`](crate::attribute::SsrcGroup) | RFC 5576 |
//! | `rid` | [`Rid`](crate::attribute::Rid) | RFC 8851 |
//! | `simulcast` | [`Simulcast`](crate::attribute::Simulcast) | RFC 8853 |
//! | `extmap` | [`ExtMap`](crate::extmap::ExtMap) | RFC 8285 |
//! | `rtcp`, `rtcp-fb`, `rtcp-xr` | [`Rtcp`](crate::attribute::Rtcp), [`RtcpFb`](crate::attribute::RtcpFb), [`RtcpXr`](crate::attribute::RtcpXr) | RFC 3605, RFC 4585 / 5104, RFC 3611 |
//! | `rtpmap`, `fmtp` | [`RtpMap`](crate::attribute::RtpMap), [`Fmtp`](crate::attribute::Fmtp) | RFC 8866 |
//! | `ptime`, `maxptime`, `framerate` | [`Ptime`](crate::attribute::Ptime), [`MaxPtime`](crate::attribute::MaxPtime), [`FrameRate`](crate::attribute::FrameRate) | RFC 8866 |
//! | `imageattr` | [`ImageAttr`](crate::attribute::ImageAttr) | RFC 6236 |
//! | `content` | [`Content`](crate::attribute::Content) | RFC 4796 |
//! | `candidate`, `remote-candidates` | [`Candidate`](crate::attribute::Candidate), [`RemoteCandidates`](crate::attribute::RemoteCandidates) | RFC 8839 |
//! | `ice-ufrag`, `ice-pwd`, `ice-options`, `ice-pacing` | [`IceUfrag`](crate::attribute::IceUfrag), [`IcePwd`](crate::attribute::IcePwd), [`IceOptions`](crate::attribute::IceOptions), [`IcePacing`](crate::attribute::IcePacing) | RFC 8839 |
//! | `fingerprint` | [`Fingerprint`](crate::attribute::Fingerprint) | RFC 8122 |
//! | `setup` | [`Setup`](crate::attribute::Setup) | RFC 4145, RFC 8842 |
//! | `tls-id` | [`TlsId`](crate::attribute::TlsId) | RFC 8842 |
//! | `identity` | [`Identity`](crate::attribute::Identity) | RFC 8827 |
//! | `tool`, `type`, `orient`, `quality` | [`Tool`](crate::attribute::Tool), [`ConferenceType`](crate::attribute::ConferenceType), [`Orient`](crate::attribute::Orient), [`Quality`](crate::attribute::Quality) | RFC 8866 |
//! | `sctp-port`, `max-message-size`, `sctpmap` | [`SctpPort`](crate::attribute::SctpPort), [`MaxMessageSize`](crate::attribute::MaxMessageSize), [`SctpMap`](crate::attribute::SctpMap) | RFC 8841 |
//!
//! Attributes without a value (`rtcp-mux`, `rtcp-mux-only`, `rtcp-rsize`, `ice-lite`,
//! `end-of-candidates`, `bundle-only`, `extmap-allow-mixed`, `cryptex` and the four
//! directions) are read with `flag()` or their named accessor, which refuses one that
//! carries a value.
//!
//! [`mux`](crate::attribute::mux) holds the RFC 8859 multiplexing category of every attribute.

use std::fmt;

use shared::error::{Error, Result};

use crate::description::common::Attribute;

mod grouping;
mod ice;
mod informational;
pub mod mux;
mod rtcp;
mod rtp;
mod sctp;
mod security;
mod simulcast;
mod source;
mod validate;

#[cfg(test)]
mod attribute_test;

pub use grouping::{Depend, Dependency, DependencyType, Group, Mid, Msid, MsidSemantic};
pub use ice::{
    Candidate, IceOptions, IcePacing, IcePwd, IceUfrag, RemoteCandidate, RemoteCandidates,
};
pub use informational::{ConferenceType, Orient, Quality, Tool};
pub use rtcp::{
    Rtcp, RtcpAddress, RtcpFb, RtcpFbKind, RtcpFbPayloadType, RtcpXr, RtcpXrFormat, RtcpXrRttMode,
    RtcpXrStatFlag,
};
pub use rtp::{
    Content, Fmtp, FrameRate, ImageAttr, ImageAttrList, ImageAttrRange, ImageAttrSet, MaxPtime,
    Ptime, RtpMap,
};
pub use sctp::{MaxMessageSize, SctpMap, SctpPort};
pub use security::{Fingerprint, Identity, Setup, TlsId};
pub use simulcast::{Rid, RidDirection, RidIdGrammar, Simulcast, SimulcastId};
pub use source::{Ssrc, SsrcGroup};
pub use validate::check_attribute;

/// An attribute with a value whose grammar this crate knows.
///
/// `parse` takes the text after `a=<name>:` and checks all of it; `Display` writes that text
/// back in the form the defining RFC gives.
pub trait TypedAttribute: Sized + fmt::Display {
    /// The attribute name, as it follows `a=`.
    const NAME: &'static str;

    /// Parses the value: everything after `a=<name>:`.
    fn parse(value: &str) -> Result<Self>;

    /// The `a=` line this value makes.
    fn to_attribute(&self) -> Attribute {
        Attribute::new(Self::NAME.to_owned(), Some(self.to_string()))
    }
}

fn no_value(name: &str) -> Error {
    Error::SdpInvalidSyntax(format!("`a={name}` has no value"))
}

/// The first `a=<T::NAME>` line of `attributes`, parsed; `Ok(None)` when there is none.
pub(crate) fn first<T: TypedAttribute>(attributes: &[Attribute]) -> Result<Option<T>> {
    attributes
        .iter()
        .map(Attribute::parts)
        .find(|(name, _)| *name == T::NAME)
        .map(|(_, value)| T::parse(value.ok_or_else(|| no_value(T::NAME))?))
        .transpose()
}

/// Every `a=<T::NAME>` line of `attributes`, parsed, in order. The first malformed one is
/// the error.
pub(crate) fn all<T: TypedAttribute>(attributes: &[Attribute]) -> Result<Vec<T>> {
    attributes
        .iter()
        .map(Attribute::parts)
        .filter(|(name, _)| *name == T::NAME)
        .map(|(_, value)| T::parse(value.ok_or_else(|| no_value(T::NAME))?))
        .collect()
}

/// Whether the property attribute `name` is present. One that carries a value is malformed.
pub(crate) fn flag(attributes: &[Attribute], name: &str) -> Result<bool> {
    match attributes
        .iter()
        .map(Attribute::parts)
        .find(|(n, _)| *n == name)
    {
        None => Ok(false),
        Some((_, None)) => Ok(true),
        Some(_) => Err(Error::SdpInvalidSyntax(format!(
            "`a={name}` takes no value"
        ))),
    }
}

/// A value attribute whose whole value is one checked string.
macro_rules! string_attribute {
    ($(#[$doc:meta])* $name:ident, $key:literal, $what:literal, |$v:ident| $check:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            /// Checks `value` against the grammar and wraps it.
            pub fn new(value: impl Into<String>) -> shared::error::Result<Self> {
                let value = value.into();
                <Self as $crate::attribute::TypedAttribute>::parse(&value)
            }

            /// The value.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl $crate::attribute::TypedAttribute for $name {
            const NAME: &'static str = $key;

            fn parse(value: &str) -> shared::error::Result<Self> {
                let $v = value;
                if $check {
                    Ok($name(value.to_owned()))
                } else {
                    Err($crate::grammar::syntax($what, value))
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}
pub(crate) use string_attribute;

/// The typed accessors both description levels share.
macro_rules! common_accessors {
    () => {
        /// The first `a=<T::NAME>` attribute at this level, parsed. `Ok(None)` when there is
        /// none, `Err` when it is malformed.
        pub fn typed<T: $crate::attribute::TypedAttribute>(
            &self,
        ) -> shared::error::Result<Option<T>> {
            $crate::attribute::first(&self.attributes)
        }

        /// Every `a=<T::NAME>` attribute at this level, parsed, in order.
        pub fn typed_all<T: $crate::attribute::TypedAttribute>(
            &self,
        ) -> shared::error::Result<Vec<T>> {
            $crate::attribute::all(&self.attributes)
        }

        /// Whether the property attribute `name` (one without a value, such as
        /// `rtcp-mux`) is present at this level. `Err` when it carries a value.
        pub fn flag(&self, name: &str) -> shared::error::Result<bool> {
            $crate::attribute::flag(&self.attributes, name)
        }

        /// Appends the `a=` line of a typed attribute.
        pub fn with_typed<T: $crate::attribute::TypedAttribute>(mut self, value: &T) -> Self {
            self.attributes.push(value.to_attribute());
            self
        }

        /// The direction attribute at this level (`sendrecv`, `sendonly`, `recvonly`,
        /// `inactive`). `Ok(None)` when there is none; `Err` when there are several
        /// (RFC 8866 section 6.7: at most one per level) or when one carries a value.
        pub fn direction(&self) -> shared::error::Result<Option<$crate::direction::Direction>> {
            let mut found = None;
            for attribute in &self.attributes {
                let (name, value) = attribute.parts();
                let direction = $crate::direction::Direction::new(name);
                if direction == $crate::direction::Direction::Unspecified {
                    continue;
                }
                if value.is_some() || found.is_some() {
                    return Err(shared::error::Error::SdpInvalidSyntax(format!(
                        "direction attribute `{name}`"
                    )));
                }
                found = Some(direction);
            }
            Ok(found)
        }

        /// `a=extmap` lines at this level (RFC 8285).
        pub fn extmaps(&self) -> shared::error::Result<Vec<$crate::extmap::ExtMap>> {
            self.typed_all()
        }

        /// Whether `a=extmap-allow-mixed` is present at this level (RFC 8285 section 6).
        pub fn extmap_allow_mixed(&self) -> shared::error::Result<bool> {
            self.flag($crate::description::session::ATTR_KEY_EXTMAP_ALLOW_MIXED)
        }

        /// `a=ice-ufrag` at this level (RFC 8839 section 5.4).
        pub fn ice_ufrag(&self) -> shared::error::Result<Option<$crate::attribute::IceUfrag>> {
            self.typed()
        }

        /// `a=ice-pwd` at this level (RFC 8839 section 5.4).
        pub fn ice_pwd(&self) -> shared::error::Result<Option<$crate::attribute::IcePwd>> {
            self.typed()
        }

        /// `a=ice-options` at this level (RFC 8839 section 5.6).
        pub fn ice_options(&self) -> shared::error::Result<Option<$crate::attribute::IceOptions>> {
            self.typed()
        }

        /// `a=fingerprint` lines at this level (RFC 8122 section 5).
        pub fn fingerprints(&self) -> shared::error::Result<Vec<$crate::attribute::Fingerprint>> {
            self.typed_all()
        }

        /// `a=setup` at this level (RFC 4145 section 4, RFC 8842).
        pub fn setup(&self) -> shared::error::Result<Option<$crate::attribute::Setup>> {
            self.typed()
        }

        /// `a=tls-id` at this level (RFC 8842 section 4).
        pub fn tls_id(&self) -> shared::error::Result<Option<$crate::attribute::TlsId>> {
            self.typed()
        }

        /// `a=rtcp-xr` at this level (RFC 3611 section 5.1).
        pub fn rtcp_xr(&self) -> shared::error::Result<Option<$crate::attribute::RtcpXr>> {
            self.typed()
        }

        /// Whether `a=cryptex` is present at this level (RFC 9335 section 4).
        pub fn cryptex(&self) -> shared::error::Result<bool> {
            self.flag($crate::description::session::ATTR_KEY_CRYPTEX)
        }
    };
}
pub(crate) use common_accessors;

/// The typed accessors of the session level.
macro_rules! session_accessors {
    () => {
        /// `a=group` lines (RFC 5888 section 5), every semantics.
        pub fn groups(&self) -> shared::error::Result<Vec<$crate::attribute::Group>> {
            self.typed_all()
        }

        /// The `a=group:BUNDLE` lines (RFC 9143 section 5).
        pub fn bundle_groups(&self) -> shared::error::Result<Vec<$crate::attribute::Group>> {
            Ok(self
                .groups()?
                .into_iter()
                .filter(|g| g.is_bundle())
                .collect())
        }

        /// Whether `a=ice-lite` is present (RFC 8839 section 5.3).
        pub fn ice_lite(&self) -> shared::error::Result<bool> {
            self.flag($crate::description::session::ATTR_KEY_ICELITE)
        }

        /// `a=ice-pacing` (RFC 8839 section 5.5).
        pub fn ice_pacing(&self) -> shared::error::Result<Option<$crate::attribute::IcePacing>> {
            self.typed()
        }

        /// `a=identity` (RFC 8827 section 5). Only the first one counts.
        pub fn identity(&self) -> shared::error::Result<Option<$crate::attribute::Identity>> {
            self.typed()
        }

        /// `a=tool` (RFC 8866 section 6.3).
        pub fn tool(&self) -> shared::error::Result<Option<$crate::attribute::Tool>> {
            self.typed()
        }

        /// `a=type`, the conference type (RFC 8866 section 6.9).
        pub fn conference_type(
            &self,
        ) -> shared::error::Result<Option<$crate::attribute::ConferenceType>> {
            self.typed()
        }

        /// `a=msid-semantic` (draft-ietf-mmusic-msid; browsers still write it).
        pub fn msid_semantic(
            &self,
        ) -> shared::error::Result<Option<$crate::attribute::MsidSemantic>> {
            self.typed()
        }
    };
}
pub(crate) use session_accessors;

/// The typed accessors of a media description.
macro_rules! media_accessors {
    () => {
        /// `a=mid` (RFC 5888 section 4).
        pub fn mid(&self) -> shared::error::Result<Option<$crate::attribute::Mid>> {
            self.typed()
        }

        /// `a=msid` lines (RFC 8830 section 2): one per MediaStream the track is in.
        pub fn msids(&self) -> shared::error::Result<Vec<$crate::attribute::Msid>> {
            self.typed_all()
        }

        /// `a=ssrc` lines (RFC 5576 section 4.1), one per source attribute.
        pub fn ssrcs(&self) -> shared::error::Result<Vec<$crate::attribute::Ssrc>> {
            self.typed_all()
        }

        /// `a=ssrc-group` lines (RFC 5576 section 4.2).
        pub fn ssrc_groups(&self) -> shared::error::Result<Vec<$crate::attribute::SsrcGroup>> {
            self.typed_all()
        }

        /// `a=rid` lines (RFC 8851 section 10).
        pub fn rids(&self) -> shared::error::Result<Vec<$crate::attribute::Rid>> {
            self.typed_all()
        }

        /// `a=simulcast` (RFC 8853 section 5.1).
        pub fn simulcast(&self) -> shared::error::Result<Option<$crate::attribute::Simulcast>> {
            self.typed()
        }

        /// `a=rtcp` (RFC 3605 section 2.1).
        pub fn rtcp(&self) -> shared::error::Result<Option<$crate::attribute::Rtcp>> {
            self.typed()
        }

        /// Whether `a=rtcp-mux` is present (RFC 5761 section 5.1.1).
        pub fn rtcp_mux(&self) -> shared::error::Result<bool> {
            self.flag($crate::description::session::ATTR_KEY_RTCPMUX)
        }

        /// Whether `a=rtcp-mux-only` is present (RFC 8858 section 3).
        pub fn rtcp_mux_only(&self) -> shared::error::Result<bool> {
            self.flag($crate::description::session::ATTR_KEY_RTCPMUX_ONLY)
        }

        /// Whether `a=rtcp-rsize` is present (RFC 5506 section 5).
        pub fn rtcp_rsize(&self) -> shared::error::Result<bool> {
            self.flag($crate::description::session::ATTR_KEY_RTCPRSIZE)
        }

        /// `a=rtcp-fb` lines (RFC 4585 section 4.2), the wildcard ones included.
        pub fn rtcp_fbs(&self) -> shared::error::Result<Vec<$crate::attribute::RtcpFb>> {
            self.typed_all()
        }

        /// `a=rtpmap` lines (RFC 8866 section 6.6).
        pub fn rtpmaps(&self) -> shared::error::Result<Vec<$crate::attribute::RtpMap>> {
            self.typed_all()
        }

        /// `a=fmtp` lines (RFC 8866 section 6.15).
        pub fn fmtps(&self) -> shared::error::Result<Vec<$crate::attribute::Fmtp>> {
            self.typed_all()
        }

        /// `a=ptime` (RFC 8866 section 6.4).
        pub fn ptime(&self) -> shared::error::Result<Option<$crate::attribute::Ptime>> {
            self.typed()
        }

        /// `a=maxptime` (RFC 8866 section 6.5).
        pub fn maxptime(&self) -> shared::error::Result<Option<$crate::attribute::MaxPtime>> {
            self.typed()
        }

        /// `a=framerate` (RFC 8866 section 6.13).
        pub fn framerate(&self) -> shared::error::Result<Option<$crate::attribute::FrameRate>> {
            self.typed()
        }

        /// `a=imageattr` lines (RFC 6236 section 3.1).
        pub fn imageattrs(&self) -> shared::error::Result<Vec<$crate::attribute::ImageAttr>> {
            self.typed_all()
        }

        /// `a=content` (RFC 4796 section 5).
        pub fn content(&self) -> shared::error::Result<Option<$crate::attribute::Content>> {
            self.typed()
        }

        /// `a=candidate` lines (RFC 8839 section 5.1).
        pub fn candidates(&self) -> shared::error::Result<Vec<$crate::attribute::Candidate>> {
            self.typed_all()
        }

        /// Whether `a=end-of-candidates` is present (RFC 8840).
        pub fn end_of_candidates(&self) -> shared::error::Result<bool> {
            self.flag($crate::description::session::ATTR_KEY_END_OF_CANDIDATES)
        }

        /// `a=remote-candidates` (RFC 8839 section 5.2).
        pub fn remote_candidates(
            &self,
        ) -> shared::error::Result<Option<$crate::attribute::RemoteCandidates>> {
            self.typed()
        }

        /// `a=sctp-port` (RFC 8841 section 5).
        pub fn sctp_port(&self) -> shared::error::Result<Option<$crate::attribute::SctpPort>> {
            self.typed()
        }

        /// `a=max-message-size` (RFC 8841 section 6).
        pub fn max_message_size(
            &self,
        ) -> shared::error::Result<Option<$crate::attribute::MaxMessageSize>> {
            self.typed()
        }

        /// `a=sctpmap`, the form `a=sctp-port` replaced (draft-ietf-mmusic-sctp-sdp-05).
        pub fn sctpmap(&self) -> shared::error::Result<Option<$crate::attribute::SctpMap>> {
            self.typed()
        }

        /// `a=orient` (RFC 8866 section 6.8).
        pub fn orient(&self) -> shared::error::Result<Option<$crate::attribute::Orient>> {
            self.typed()
        }

        /// `a=quality` (RFC 8866 section 6.14).
        pub fn quality(&self) -> shared::error::Result<Option<$crate::attribute::Quality>> {
            self.typed()
        }

        /// Whether `a=bundle-only` is present (RFC 9143 section 6).
        pub fn bundle_only(&self) -> shared::error::Result<bool> {
            self.flag($crate::description::session::ATTR_KEY_BUNDLE_ONLY)
        }
    };
}
pub(crate) use media_accessors;

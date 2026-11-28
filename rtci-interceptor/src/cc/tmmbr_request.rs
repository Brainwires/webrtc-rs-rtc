//! The media receiver's side of TMMBR (RFC 5104 sections 3.5.4.1 and 4.2.1.2): asking a remote
//! media sender to stay under a bit rate, for a stream that negotiated `ccm tmmbr`.
//!
//! The application sets a limit per remote media SSRC with [`TmmbrControl`], written into the
//! chain; the congestion control interceptor ([`CongestionControlInterceptor`]
//! (crate::CongestionControlInterceptor)), which already reads TMMBN, holds this state and
//! sends the TMMBRs. What it does:
//!
//! * the overhead in each entry is the running average `avg_OH (new) = 15/16*avg_OH (old) +
//!   1/16*pckt_OH` over the stream's packets (section 4.2.1.2), at the IP layer: IPv4 or IPv6
//!   and UDP headers, and the RTP header with its CSRCs, extensions and padding;
//! * the value never exceeds a negotiated maximum ([`TmmbrControl::NegotiatedMaximum`]),
//!   "MUST NOT exceed the negotiated value";
//! * the latest TMMBN from each media sender is saved ("SHALL save the contents of the latest
//!   TMMBN"), and a TMMBR is sent in the three cases section 4.2.1.2 allows: before any TMMBN
//!   came from that sender; as owner of a bounding tuple when the bit rate or the overhead
//!   changed; as non-owner when the receiver's tuple would enter the bounding set
//!   (section 3.5.4.2, the sender's own algorithm);
//! * the first TMMBR goes at once (section 4.2.1.3: "MAY use early or immediate feedback"); while
//!   no TMMBN has acknowledged it, it is repeated every [`TMMBR_REPEAT_INTERVAL`], a regular
//!   reporting interval rather than early ("Any repetition [...] SHOULD use regular RTCP
//!   mode"), with the overhead brought up to date ("SHALL be updated to the current value of
//!   avg_OH each time the entry is sent");
//! * lifting a limit is a TMMBR at the negotiated maximum, or with no maximum negotiated at the
//!   highest value the entry can carry, so the sender's bounding set no longer holds the
//!   receiver's tuple (section 3.5.4.1: an owner reports changed values).
//!
//! Section 4.2.1.2's SHOULD, to renegotiate the session parameters when a limit is expected to
//! be permanent, is the application's: only it knows whether a limit is.

use super::tmmbr::{TmmbEntry, bounding_set};
use crate::{Attribute, AttributedPacket, Packet, TaggedPacket};
use shared::TransportContext;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long an unacknowledged TMMBR waits before it is sent again (RFC 5104 section 4.2.1.2):
/// about a regular RTCP reporting interval of a WebRTC session.
pub const TMMBR_REPEAT_INTERVAL: Duration = Duration::from_secs(1);

/// IPv4 and UDP headers, in bytes.
const IPV4_UDP: usize = 20 + 8;
/// IPv6 and UDP headers, in bytes.
const IPV6_UDP: usize = 40 + 8;
/// The overhead change, in bytes, that makes an owner report its tuple again: the running
/// average moves by fractions of a byte with every packet.
const OVERHEAD_CHANGE: u16 = 4;
/// The highest value a TMMBR entry can say (17 bits of mantissa, a 6-bit exponent), as far as
/// a `u64` holds it: "no limit".
const UNLIMITED: u64 = 0x1_FFFF << 46;

/// What an application tells the TMMBR requester (the congestion control interceptor), written
/// into the chain with [`into_packet`](Self::into_packet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TmmbrControl {
    /// Ask the remote sender of `media_ssrc` to stay under `bitrate` bits per second, total
    /// media bit rate at the IP layer (RFC 5104 section 2.2: the RTP packets with their IP,
    /// UDP and RTP headers). Only for a remote stream that negotiated `ccm tmmbr`.
    Limit {
        /// The remote media sender's SSRC.
        media_ssrc: u32,
        /// The maximum total media bit rate.
        bitrate: u64,
    },
    /// Lift the limit set on `media_ssrc`.
    Clear {
        /// The remote media sender's SSRC.
        media_ssrc: u32,
    },
    /// The maximum bit rate negotiated in signalling for what this endpoint receives (`b=TIAS`,
    /// or `b=AS` times 1000), which no TMMBR value exceeds (RFC 5104 section 4.2.1.2). `None`:
    /// none was negotiated.
    NegotiatedMaximum(Option<u64>),
}

impl TmmbrControl {
    /// The packet that carries this to the interceptor when written into the chain at `now`.
    pub fn into_packet(self, now: Instant) -> TaggedPacket {
        TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![]))
                .with(Attribute::Custom(Arc::new(self))),
        }
    }
}

/// One remote media sender.
#[derive(Debug, Default)]
struct Remote {
    /// `a=rtcp-fb:<pt> ccm tmmbr` was negotiated for the stream (RFC 5104 section 7.2: no
    /// CCM is used that was not).
    negotiated: bool,
    /// avg_OH, in bytes; `None` before the first packet.
    avg_overhead: Option<f64>,
    /// The limit the application wants; `None`: none.
    wanted: Option<u64>,
    /// The latest TMMBN from this sender: its bounding set (owners and tuples).
    tmmbn: Option<Vec<TmmbEntry>>,
    /// The tuple last sent, and when; cleared by a TMMBN.
    unacknowledged: Option<(TmmbEntry, Instant)>,
    /// A TMMBR is to be sent at the next opportunity.
    owed: bool,
}

impl Remote {
    fn overhead(&self, ipv6: bool) -> u16 {
        let fallback = if ipv6 { IPV6_UDP } else { IPV4_UDP } + 12;
        self.avg_overhead
            .map_or(fallback as u16, |oh| oh.round().clamp(0.0, 511.0) as u16)
    }
}

/// The receiver side of TMMBR for every remote stream. See the module documentation.
#[derive(Debug, Default)]
pub(crate) struct TmmbrRequester {
    remotes: HashMap<u32, Remote>,
    negotiated_maximum: Option<u64>,
    /// Whether the transport runs over IPv6, from the last packet's address.
    ipv6: bool,
    /// Whether every entry [`poll_request`](Self::poll_request) last returned repeats an
    /// unacknowledged one (section 4.2.1.3: regular RTCP timing for those).
    repeats_only: bool,
}

impl TmmbrRequester {
    pub(crate) fn bind(&mut self, media_ssrc: u32, negotiated: bool) {
        self.remotes.entry(media_ssrc).or_default().negotiated = negotiated;
    }

    pub(crate) fn unbind(&mut self, media_ssrc: u32) {
        self.remotes.remove(&media_ssrc);
    }

    /// An RTP packet of `media_ssrc` arrived: `rtp_overhead` bytes of RTP header and padding.
    pub(crate) fn on_rtp(&mut self, media_ssrc: u32, rtp_overhead: usize, ipv6: bool) {
        self.ipv6 = ipv6;
        if let Some(remote) = self.remotes.get_mut(&media_ssrc) {
            let packet = (rtp_overhead + if ipv6 { IPV6_UDP } else { IPV4_UDP }) as f64;
            remote.avg_overhead = Some(match remote.avg_overhead {
                Some(average) => 15.0 / 16.0 * average + packet / 16.0,
                None => packet,
            });
        }
    }

    pub(crate) fn on_control(&mut self, control: TmmbrControl, own_ssrc: u32) {
        match control {
            TmmbrControl::Limit {
                media_ssrc,
                bitrate,
            } => {
                if let Some(remote) = self.remotes.get_mut(&media_ssrc) {
                    remote.wanted = Some(bitrate);
                }
                self.evaluate(media_ssrc, own_ssrc);
            }
            TmmbrControl::Clear { media_ssrc } => {
                if let Some(remote) = self.remotes.get_mut(&media_ssrc) {
                    remote.wanted = None;
                }
                self.evaluate(media_ssrc, own_ssrc);
            }
            TmmbrControl::NegotiatedMaximum(maximum) => {
                self.negotiated_maximum = maximum;
                let ssrcs: Vec<u32> = self.remotes.keys().copied().collect();
                for ssrc in ssrcs {
                    self.evaluate(ssrc, own_ssrc);
                }
            }
        }
    }

    /// A TMMBN arrived from `media_sender`, with its bounding set.
    pub(crate) fn on_tmmbn(&mut self, media_sender: u32, entries: Vec<TmmbEntry>, own_ssrc: u32) {
        let Some(remote) = self.remotes.get_mut(&media_sender) else {
            return;
        };
        remote.tmmbn = Some(entries);
        remote.unacknowledged = None;
        self.evaluate(media_sender, own_ssrc);
    }

    /// The tuple this receiver asks of `media_ssrc` now, if it asks anything: the wanted limit
    /// under the negotiated maximum, or, with none wanted, the lifting value (only meaningful
    /// once something was asked).
    fn tuple(&self, media_ssrc: u32, own_ssrc: u32) -> Option<TmmbEntry> {
        let remote = self.remotes.get(&media_ssrc)?;
        let ceiling = self.negotiated_maximum.unwrap_or(UNLIMITED);
        Some(TmmbEntry {
            ssrc: own_ssrc,
            bitrate: remote.wanted.map_or(ceiling, |wanted| wanted.min(ceiling)),
            overhead: remote.overhead(self.ipv6),
        })
    }

    /// Section 4.2.1.2's three cases.
    fn evaluate(&mut self, media_ssrc: u32, own_ssrc: u32) {
        let Some(ours) = self.tuple(media_ssrc, own_ssrc) else {
            return;
        };
        let Some(remote) = self.remotes.get_mut(&media_ssrc) else {
            return;
        };
        if !remote.negotiated {
            return;
        }
        let owed = match &remote.tmmbn {
            // Before any TMMBN: whenever there is a limit to ask for, or one to lift.
            None => remote.wanted.is_some() || remote.unacknowledged.is_some(),
            Some(bounding) => match bounding.iter().find(|tuple| tuple.ssrc == own_ssrc) {
                // An owner reports a changed tuple.
                Some(owned) => {
                    owned.bitrate != ours.bitrate
                        || owned.overhead.abs_diff(ours.overhead) >= OVERHEAD_CHANGE
                }
                // A non-owner asks when its tuple would bound the sender.
                None => {
                    remote.wanted.is_some() && {
                        let mut tuples = bounding.clone();
                        tuples.push(ours);
                        bounding_set(&tuples).contains(&ours)
                    }
                }
            },
        };
        remote.owed |= owed;
    }

    /// The TMMBR entries to send at `now`, owed ones and repetitions of unacknowledged ones,
    /// each with the overhead as it is now.
    pub(crate) fn poll_request(&mut self, now: Instant, own_ssrc: u32) -> Vec<TmmbEntry> {
        let ssrcs: Vec<u32> = self.remotes.keys().copied().collect();
        let mut entries = Vec::new();
        let mut first_transmission = false;
        for media_ssrc in ssrcs {
            let Some(ours) = self.tuple(media_ssrc, own_ssrc) else {
                continue;
            };
            let Some(remote) = self.remotes.get_mut(&media_ssrc) else {
                continue;
            };
            if !remote.negotiated {
                continue;
            }
            let repeat = remote
                .unacknowledged
                .is_some_and(|(_, at)| now.saturating_duration_since(at) >= TMMBR_REPEAT_INTERVAL);
            if remote.owed || repeat {
                first_transmission |= remote.owed;
                remote.owed = false;
                remote.unacknowledged = Some((ours, now));
                // In a TMMBR an entry names the media sender asked.
                entries.push(TmmbEntry {
                    ssrc: media_ssrc,
                    ..ours
                });
            }
        }
        entries.sort_by_key(|entry| entry.ssrc);
        self.repeats_only = !entries.is_empty() && !first_transmission;
        entries
    }

    /// Whether the entries [`poll_request`](Self::poll_request) last returned are all
    /// repetitions, which RFC 5104 section 4.2.1.3 sends in regular RTCP mode.
    pub(crate) fn repeats_only(&self) -> bool {
        self.repeats_only
    }

    /// When the next repetition is due.
    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        self.remotes
            .values()
            .filter(|remote| remote.negotiated)
            .filter_map(|remote| {
                remote
                    .unacknowledged
                    .map(|(_, at)| at + TMMBR_REPEAT_INTERVAL)
            })
            .min()
    }

    /// The latest TMMBN from `media_sender`, as saved.
    #[cfg(test)]
    pub(crate) fn latest_tmmbn(&self, media_sender: u32) -> Option<&[TmmbEntry]> {
        self.remotes.get(&media_sender)?.tmmbn.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENDER: u32 = 0xA;
    const OWN: u32 = 0xB;
    const OTHER: u32 = 0xC;

    fn requester() -> TmmbrRequester {
        let mut r = TmmbrRequester::default();
        r.bind(SENDER, true);
        r
    }

    fn limit(r: &mut TmmbrRequester, bitrate: u64) {
        r.on_control(
            TmmbrControl::Limit {
                media_ssrc: SENDER,
                bitrate,
            },
            OWN,
        );
    }

    #[test]
    fn the_overhead_is_the_running_average_of_section_4_2_1_2() {
        let mut r = requester();
        r.on_rtp(SENDER, 12, false);
        assert_eq!(r.remotes[&SENDER].avg_overhead, Some(40.0));
        r.on_rtp(SENDER, 28, false);
        // 15/16 * 40 + 1/16 * 56 = 41
        assert_eq!(r.remotes[&SENDER].avg_overhead, Some(41.0));
        r.on_rtp(SENDER, 12, true);
        // IPv6: 15/16 * 41 + 1/16 * 60
        let expected = 15.0 / 16.0 * 41.0 + 60.0 / 16.0;
        assert!((r.remotes[&SENDER].avg_overhead.unwrap() - expected).abs() < 1e-9);
    }

    #[test]
    fn a_first_limit_is_sent_at_once_and_repeated_until_a_tmmbn() {
        let now = Instant::now();
        let mut r = requester();
        r.on_rtp(SENDER, 12, false);
        limit(&mut r, 300_000);
        let sent = r.poll_request(now, OWN);
        assert_eq!(
            sent,
            vec![TmmbEntry {
                ssrc: SENDER,
                bitrate: 300_000,
                overhead: 40
            }]
        );
        assert!(!r.repeats_only(), "the first transmission");
        assert!(
            r.poll_request(now + Duration::from_millis(500), OWN)
                .is_empty()
        );
        assert_eq!(r.poll_timeout(), Some(now + TMMBR_REPEAT_INTERVAL));
        // The overhead moved meanwhile: the repetition carries the current value.
        for _ in 0..32 {
            r.on_rtp(SENDER, 32, false);
        }
        let again = r.poll_request(now + TMMBR_REPEAT_INTERVAL, OWN);
        assert_eq!(again.len(), 1, "repeated without a TMMBN");
        assert!(
            r.repeats_only(),
            "a repetition (section 4.2.1.3: regular RTCP mode)"
        );
        assert!(again[0].overhead > 40, "{again:?}");
        r.on_tmmbn(
            SENDER,
            vec![TmmbEntry {
                ssrc: OWN,
                ..again[0]
            }],
            OWN,
        );
        assert!(r.latest_tmmbn(SENDER).is_some(), "the TMMBN is saved");
        assert_eq!(r.poll_timeout(), None);
        assert!(
            r.poll_request(now + TMMBR_REPEAT_INTERVAL * 3, OWN)
                .is_empty()
        );
    }

    #[test]
    fn an_owner_reports_a_changed_limit_and_lifts_it_at_the_negotiated_maximum() {
        let now = Instant::now();
        let mut r = requester();
        r.on_control(TmmbrControl::NegotiatedMaximum(Some(2_000_000)), OWN);
        limit(&mut r, 500_000);
        let first = r.poll_request(now, OWN);
        r.on_tmmbn(
            SENDER,
            vec![TmmbEntry {
                ssrc: OWN,
                ..first[0]
            }],
            OWN,
        );
        // Unchanged: nothing to say.
        limit(&mut r, 500_000);
        assert!(r.poll_request(now, OWN).is_empty());
        limit(&mut r, 800_000);
        assert_eq!(r.poll_request(now, OWN)[0].bitrate, 800_000);
        r.on_tmmbn(
            SENDER,
            vec![TmmbEntry {
                ssrc: OWN,
                bitrate: 800_000,
                overhead: first[0].overhead,
            }],
            OWN,
        );
        r.on_control(TmmbrControl::Clear { media_ssrc: SENDER }, OWN);
        assert_eq!(r.poll_request(now, OWN)[0].bitrate, 2_000_000);
    }

    #[test]
    fn a_limit_never_exceeds_the_negotiated_maximum() {
        let mut r = requester();
        r.on_control(TmmbrControl::NegotiatedMaximum(Some(1_000_000)), OWN);
        limit(&mut r, 5_000_000);
        assert_eq!(r.poll_request(Instant::now(), OWN)[0].bitrate, 1_000_000);
    }

    #[test]
    fn a_non_owner_asks_only_when_its_tuple_would_bound_the_sender() {
        let now = Instant::now();
        let mut r = requester();
        r.on_rtp(SENDER, 12, false);
        let held = TmmbEntry {
            ssrc: OTHER,
            bitrate: 400_000,
            overhead: 40,
        };
        r.on_tmmbn(SENDER, vec![held], OWN);
        // Looser than another receiver's limit: it would not enter the bounding set.
        limit(&mut r, 600_000);
        assert!(r.poll_request(now, OWN).is_empty());
        // Tighter: it would.
        limit(&mut r, 300_000);
        assert_eq!(r.poll_request(now, OWN)[0].bitrate, 300_000);
    }

    #[test]
    fn a_stream_without_ccm_tmmbr_is_never_asked() {
        let mut r = TmmbrRequester::default();
        r.bind(SENDER, false);
        limit(&mut r, 100_000);
        assert!(r.poll_request(Instant::now(), OWN).is_empty());
        assert_eq!(r.poll_timeout(), None);
    }
}

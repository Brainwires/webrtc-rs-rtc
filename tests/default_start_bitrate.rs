//! The default interceptor set's congestion controller starts where the application says
//! (`DefaultInterceptorOptions::congestion_start_bitrate`): its target before any feedback,
//! the pacer's first budget and the start-up probes all follow the configured start. No
//! specification names a start value (RFC 8836 section 2, requirement 4, allows a
//! "history-based startup"; draft-ietf-rmcat-gcc-02 has none), so the default stays 300
//! kbit/s.

use rtci::interceptor::{
    AttributedPacket, GCC_INITIAL_BITRATE, Interceptor, Packet, ProbePacket, RTCPFeedback,
    RTPHeaderExtension, Registry, StreamInfo, TaggedPacket,
};
use rtci::peer_connection::configuration::interceptor_registry::{
    DefaultInterceptorHandles, DefaultInterceptorOptions,
    register_default_interceptors_with_options,
};
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::sansio::Protocol;
use rtci::shared::TransportContext;
use rtci::shared::error::Error;
use rtci::shared::marshal::MarshalSize;
use std::time::{Duration, Instant};

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
const MEDIA_SSRC: u32 = 0x0C0C_0001;
const RTX_SSRC: u32 = 0x0C0C_0002;
/// The payload of each media packet.
const PAYLOAD_OCTETS: usize = 1000;

fn options(start: f64, probing: bool) -> DefaultInterceptorOptions {
    let mut options = DefaultInterceptorOptions::default();
    options.congestion_start_bitrate = start;
    options.bandwidth_probing = probing;
    options
}

/// What left the default chain in its first second, no feedback arriving, while the
/// application wrote media at one and a half times `options`' start (so the pacer, not the
/// source, decides what leaves, and its queue stays short of a pause): (the controller's
/// target before anything was sent, media bits that left, octets of probe packets that left).
fn first_second(options: &DefaultInterceptorOptions) -> (f64, f64, usize) {
    let mut media_engine = MediaEngine::default();
    let (registry, handles): (Registry, DefaultInterceptorHandles) =
        register_default_interceptors_with_options(Registry::new(), &mut media_engine, options)
            .expect("default interceptors");
    let first_target = handles.congestion_control.target_bitrate();
    let mut chain = registry.build();
    chain.bind_local_stream(&StreamInfo {
        ssrc: MEDIA_SSRC,
        ssrc_rtx: Some(RTX_SSRC),
        payload_type: 96,
        payload_type_rtx: Some(97),
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        rtcp_feedback: vec![
            RTCPFeedback {
                typ: "transport-cc".to_owned(),
                parameter: String::new(),
            },
            RTCPFeedback {
                typ: "nack".to_owned(),
                parameter: String::new(),
            },
        ],
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: 5,
        }],
        ..Default::default()
    });

    let epoch = Instant::now();
    let written_rate = 1.5 * options.congestion_start_bitrate;
    let mut written_bits = 0.0;
    let (mut media_bits, mut probe_octets) = (0.0, 0usize);
    let mut sequence_number = 0u16;
    for millisecond in 0..1_000u64 {
        let now = epoch + Duration::from_millis(millisecond);
        while written_bits < written_rate * (millisecond + 1) as f64 / 1000.0 {
            chain
                .handle_write(TaggedPacket {
                    now,
                    transport: TransportContext::default(),
                    message: AttributedPacket::new(Packet::Rtp(rtci::rtp::packet::Packet {
                        header: rtci::rtp::header::Header {
                            version: 2,
                            payload_type: 96,
                            sequence_number,
                            timestamp: millisecond as u32 * 90,
                            ssrc: MEDIA_SSRC,
                            ..Default::default()
                        },
                        payload: vec![0xAB; PAYLOAD_OCTETS].into(),
                    })),
                })
                .expect("write");
            sequence_number = sequence_number.wrapping_add(1);
            written_bits += (8 * (PAYLOAD_OCTETS + 12)) as f64;
        }
        while chain.poll_timeout().is_some_and(|at| at <= now) {
            chain.handle_timeout(now).expect("timeout");
        }
        while chain.poll_read().is_some() {}
        while let Some(out) = chain.poll_write() {
            let Packet::Rtp(packet) = &out.message.packet else {
                continue;
            };
            if out.message.custom::<ProbePacket>().is_some() {
                probe_octets += packet.marshal_size();
            } else if packet.header.ssrc == MEDIA_SSRC {
                media_bits += (8 * packet.marshal_size()) as f64;
            }
        }
    }
    (first_target, media_bits, probe_octets)
}

/// The controller's target before any feedback is the configured start, and the pacer's
/// first budget is too: in the first second, a source writing above it gets the start
/// through, within the pacer's burst and the header extensions, for the default start and
/// for one four times higher.
#[test]
fn the_first_target_and_the_pacers_first_budget_are_the_configured_start() {
    for start in [GCC_INITIAL_BITRATE, 1_200_000.0] {
        let (first_target, media_bits, _) = first_second(&options(start, false));
        assert_eq!(start, first_target, "the controller starts at {start}");
        assert!(
            media_bits >= 0.85 * start && media_bits <= 1.15 * start,
            "start {start}: {media_bits} bits of media left in the first second"
        );
    }
}

/// The start-up probes are a multiple of the configured start (the first cluster, at three
/// times the start, leaves within the first second): from a 2 Mbit/s start its cluster holds
/// 6 Mbit/s for 15 ms, 11 250 octets, where from 300 kbit/s it is the smallest cluster (6 000
/// octets), so probing runs from the start given, not from the default. (CI 45882447829:
/// 11 700 octets of probe packets against 6 440, headers included; with the start ignored,
/// 6 750 against 6 440.)
#[test]
fn the_start_up_probes_follow_the_configured_start() {
    let (_, _, default_probes) = first_second(&options(GCC_INITIAL_BITRATE, true));
    let (_, _, higher_probes) = first_second(&options(2_000_000.0, true));
    assert!(default_probes > 0, "the default start probes");
    assert!(
        higher_probes as f64 >= 1.5 * default_probes as f64,
        "probes from a 2 Mbit/s start: {higher_probes} octets, from 300 kbit/s: {default_probes}"
    );
}

/// The start must lie within the floor and the ceiling, and all three be finite (libwebrtc's
/// `SetBitrate` refuses the same): the registration fails with `InvalidBitrate` rather than
/// quietly clamping.
#[test]
fn a_start_outside_the_floor_and_the_ceiling_is_refused() {
    let refused = |options: DefaultInterceptorOptions| {
        let mut media_engine = MediaEngine::default();
        matches!(
            register_default_interceptors_with_options(
                Registry::new(),
                &mut media_engine,
                &options
            ),
            Err(Error::InvalidBitrate)
        )
    };
    let mut below = options(50_000.0, true);
    below.congestion_min_bitrate = 100_000.0;
    assert!(refused(below), "start under the floor");
    let mut above = options(5_000_000.0, true);
    above.congestion_max_bitrate = 2_000_000.0;
    assert!(refused(above), "start over the ceiling");
    assert!(
        refused(options(f64::NAN, true)),
        "a start that is no number"
    );
    let mut inverted = options(300_000.0, true);
    inverted.congestion_min_bitrate = 400_000.0;
    inverted.congestion_max_bitrate = 200_000.0;
    assert!(refused(inverted), "a floor over the ceiling");

    let mut media_engine = MediaEngine::default();
    let mut fits = options(500_000.0, true);
    fits.congestion_min_bitrate = 500_000.0;
    fits.congestion_max_bitrate = 500_000.0;
    assert!(
        register_default_interceptors_with_options(Registry::new(), &mut media_engine, &fits)
            .is_ok(),
        "start, floor and ceiling equal"
    );
}

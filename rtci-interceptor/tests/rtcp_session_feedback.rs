//! Feedback through the RTCP session: compound packets (RFC 4585 3.1), the packet sender
//! SSRC (RFC 4585 6.1, RFC 8108 5.4.1), early RTCP and its allowance (RFC 4585 3.5.2) and
//! reduced-size RTCP (RFC 5506).

mod rtcp_session_common;

use rtci_interceptor::{Interceptor, NackControl, Packet, RtcpBandwidth, RtcpSessionControl};
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtcp::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate;
use rtcp::receiver_report::ReceiverReport;
use rtcp::sender_report::SenderReport;
use rtcp::source_description::{
    SdesType, SourceDescription, SourceDescriptionChunk, SourceDescriptionItem,
};
use rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use rtcp_session_common::*;
use sansio::Protocol;
use std::time::Instant;

fn pli(media_ssrc: u32) -> Vec<Box<dyn rtcp::Packet>> {
    vec![Box::new(PictureLossIndication {
        // What an application or an interceptor that knows no better fills in.
        sender_ssrc: 0,
        media_ssrc,
    })]
}

fn nack(media_ssrc: u32, sequence_number: u16) -> Vec<Box<dyn rtcp::Packet>> {
    vec![Box::new(TransportLayerNack {
        sender_ssrc: 0xDEAD_BEEF,
        media_ssrc,
        nacks: vec![NackPair {
            packet_id: sequence_number,
            lost_packets: 0,
        }],
    })]
}

fn remb(media_ssrc: u32) -> Vec<Box<dyn rtcp::Packet>> {
    vec![Box::new(ReceiverEstimatedMaximumBitrate {
        sender_ssrc: 0,
        bitrate: 1_000_000.0,
        ssrcs: vec![media_ssrc],
    })]
}

fn sdes(source: u32, cname: &str) -> Box<dyn rtcp::Packet> {
    Box::new(SourceDescription {
        chunks: vec![SourceDescriptionChunk {
            source,
            items: vec![SourceDescriptionItem {
                sdes_type: SdesType::SdesCname,
                text: cname.to_string().into(),
            }],
        }],
    })
}

/// RFC 4585 3.1 (and RFC 3550 6.1): feedback leaves in a compound packet: RR, SDES with the
/// CNAME, then the feedback message, whose packet sender is the endpoint's own SSRC. Between
/// two parties it leaves at once (RFC 4585 3.5.2: no dither).
#[test]
fn feedback_leaves_at_once_in_a_minimal_compound_packet_from_the_endpoints_ssrc() {
    let mut chain = chain(builder());
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);

    let now = base + secs(0.01);
    chain.handle_write(rtcp(now, pli(200))).unwrap();
    let sent = written(&mut chain);
    assert_eq!(1, sent.len());
    assert_eq!(now, sent[0].at);
    assert_eq!(3, sent[0].packets.len());
    let report = sent[0].packets[0]
        .as_any()
        .downcast_ref::<ReceiverReport>()
        .expect("a receiver report first");
    assert_eq!(REPORTER, report.ssrc);
    assert!(report.reports.is_empty(), "the minimal compound packet");
    assert_eq!(
        vec![REPORTER],
        sent[0].cnames().iter().map(|c| c.0).collect::<Vec<_>>()
    );
    assert!(sent[0].packets[1].as_any().is::<SourceDescription>());
    let pli = sent[0].packets[2]
        .as_any()
        .downcast_ref::<PictureLossIndication>()
        .expect("then the feedback");
    assert_eq!(REPORTER, pli.sender_ssrc);
    assert_eq!(200, pli.media_ssrc);
}

/// Writes the application's NACK horizon for `media_ssrc` into the chain, as the peer
/// connection does on its way to the NACK generator; only its carrier comes out.
fn nack_horizon(chain: &mut impl Interceptor, now: Instant, media_ssrc: u32, oldest_useful: u16) {
    chain
        .handle_write(
            NackControl::Horizon {
                media_ssrc,
                oldest_useful: Some(oldest_useful),
            }
            .into_packet(now),
        )
        .unwrap();
    while let Some(tagged) = chain.poll_write() {
        match tagged.message.packet {
            Packet::Rtcp(packets) => assert!(packets.is_empty(), "only the carrier: {packets:?}"),
            _ => panic!("only the carrier is written"),
        }
    }
}

/// The sequence numbers the NACKs for `media_ssrc` in `sent` ask for.
fn nacked(sent: &[Sent], media_ssrc: u32) -> Vec<u16> {
    let mut requested: Vec<u16> = sent
        .iter()
        .flat_map(|datagram| datagram.get::<TransportLayerNack>())
        .filter(|nack| nack.media_ssrc == media_ssrc)
        .flat_map(|nack| nack.nacks.iter().flat_map(|pair| pair.packet_list()))
        .collect();
    requested.sort_unstable();
    requested
}

/// RFC 4585 3.5.2, step 4a: feedback that may not leave in an Early packet is stored for the
/// next regular one, to go with it if it "is still useful" then. A NACK held that way when
/// the receiving application's NACK horizon (RFC 4588 6.3, `NackControl::Horizon`) passes
/// what it asks for is not: the sequence numbers behind the horizon leave it, those of
/// another stream and the ones at or past the horizon stay, and a NACK left asking for
/// nothing is not sent at all. No NACK that leaves after the horizon names a packet behind it.
#[test]
fn a_nack_held_for_the_regular_packet_drops_what_the_nack_horizon_passed() {
    let mut chain = chain(builder().with_bandwidth(RtcpBandwidth {
        session: Some(64_000),
        ..Default::default()
    }));
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    chain.bind_remote_stream(&video(300));
    control(&mut chain, base, RtcpSessionControl::Start);

    chain
        .handle_write(rtcp(base + secs(0.01), nack(200, 10)))
        .unwrap();
    assert_eq!(1, written(&mut chain).len());

    // No early packet is allowed now: these wait for the regular one.
    for (media_ssrc, sequence_number) in [(200, 12), (200, 13), (200, 20), (300, 12)] {
        chain
            .handle_write(rtcp(base + secs(0.02), nack(media_ssrc, sequence_number)))
            .unwrap();
    }
    assert!(written(&mut chain).is_empty());

    // The application has given up everything of 200 before 13.
    nack_horizon(&mut chain, base + secs(0.03), 200, 13);
    let sent = run(&mut chain, base + secs(0.9));
    assert_eq!(1, sent.len(), "one packet carries what was stored");
    assert_eq!(vec![13, 20], nacked(&sent, 200), "12 is behind the horizon");
    assert_eq!(
        vec![12],
        nacked(&sent, 300),
        "another stream's is untouched"
    );

    // Early feedback is allowed again, is used, and the next NACK waits once more.
    let now = base + secs(0.91);
    chain.handle_write(rtcp(now, pli(200))).unwrap();
    assert_eq!(1, written(&mut chain).len());
    chain
        .handle_write(rtcp(base + secs(0.92), nack(200, 21)))
        .unwrap();
    chain
        .handle_write(rtcp(base + secs(0.92), nack(200, 22)))
        .unwrap();
    assert!(written(&mut chain).is_empty());

    // The horizon passes all it asks for.
    nack_horizon(&mut chain, base + secs(0.93), 200, 23);
    let sent = run(&mut chain, base + secs(4.0));
    assert!(
        sent.iter()
            .all(|datagram| !datagram.has::<TransportLayerNack>()),
        "a NACK that asks for nothing useful is not sent"
    );
}

/// RFC 4585 3.5.2: after an Early packet no other is allowed until the next regular one is
/// due (put off by one interval). Feedback detected meanwhile is stored and goes with it,
/// merged into as few messages as possible.
#[test]
fn a_second_feedback_waits_for_the_regular_packet_and_is_merged() {
    let mut chain = chain(builder().with_bandwidth(RtcpBandwidth {
        session: Some(64_000),
        ..Default::default()
    }));
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);

    chain
        .handle_write(rtcp(base + secs(0.01), nack(200, 10)))
        .unwrap();
    assert_eq!(1, written(&mut chain).len());

    // No early packet is allowed now.
    chain
        .handle_write(rtcp(base + secs(0.02), nack(200, 12)))
        .unwrap();
    chain
        .handle_write(rtcp(base + secs(0.03), nack(200, 11)))
        .unwrap();
    chain
        .handle_write(rtcp(base + secs(0.03), pli(200)))
        .unwrap();
    chain
        .handle_write(rtcp(base + secs(0.04), pli(200)))
        .unwrap();
    assert!(written(&mut chain).is_empty());

    let sent = run(&mut chain, base + secs(0.9));
    assert_eq!(1, sent.len(), "one packet carries what was stored");
    assert!(sent[0].at > base + secs(0.04));
    assert!(sent[0].is_compound());
    let nacks = sent[0].get::<TransportLayerNack>();
    assert_eq!(1, nacks.len(), "the two NACKs are one message");
    let mut requested: Vec<u16> = nacks[0]
        .nacks
        .iter()
        .flat_map(|p| p.packet_list())
        .collect();
    requested.sort_unstable();
    assert_eq!(vec![11, 12], requested);
    assert_eq!(REPORTER, nacks[0].sender_ssrc);
    assert_eq!(1, sent[0].get::<PictureLossIndication>().len());

    // The regular packet went: early feedback is allowed again.
    let now = base + secs(0.91);
    chain.handle_write(rtcp(now, pli(200))).unwrap();
    let sent = written(&mut chain);
    assert_eq!(1, sent.len());
    assert_eq!(now, sent[0].at);

    // And not again right after. The next regular packet is not due yet (`T_rr_interval`),
    // so what is stored leaves with a packet of its own when the timer expires (RFC 4585
    // 3.5.3, case 2b): the minimal compound packet, no report blocks.
    chain
        .handle_write(rtcp(now + secs(0.001), nack(200, 30)))
        .unwrap();
    assert!(written(&mut chain).is_empty());
    let sent = run(&mut chain, now + secs(0.6));
    assert_eq!(1, sent.len());
    assert!(sent[0].is_compound());
    assert_eq!(1, sent[0].get::<TransportLayerNack>().len());
    assert!(sent[0].reported().is_empty());
}

/// RFC 5506 4.2.2: a large feedback packet goes out compound even when reduced-size RTCP was
/// negotiated.
#[test]
fn a_large_feedback_packet_is_sent_compound() {
    let mut chain = chain(builder().with_reduced_size(true));
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain
        .handle_write(rtcp(base + secs(0.01), pli(200)))
        .unwrap();
    written(&mut chain);
    run(&mut chain, base + secs(2.0));

    // 150 separate losses: 150 PID/BLP pairs, 600 octets of FCI.
    let large: Vec<Box<dyn rtcp::Packet>> = vec![Box::new(TransportLayerNack {
        sender_ssrc: 0,
        media_ssrc: 200,
        nacks: (0..150u16)
            .map(|n| NackPair {
                packet_id: n * 20,
                lost_packets: 0,
            })
            .collect(),
    })];
    chain.handle_write(rtcp(base + secs(2.0), large)).unwrap();
    let sent = written(&mut chain);
    assert_eq!(1, sent.len());
    assert!(sent[0].is_compound());
}

/// RFC 3550 6.1: "If the overall length of a compound packet would exceed the MTU of the
/// network path, it SHOULD be segmented into multiple shorter compound packets to be
/// transmitted in separate packets of the underlying protocol", each beginning with an SR or
/// RR. A NACK larger than the MTU by itself leaves at once in several compound packets, each
/// under the MTU, that together ask for every packet it asked for.
#[test]
fn a_nack_larger_than_the_mtu_is_split_into_several_compound_packets() {
    let mut chain = chain(builder().with_mtu(300));
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);

    // 150 separate losses: 150 PID/BLP pairs, 612 octets of NACK, twice the MTU.
    let pairs: Vec<NackPair> = (0..150u16)
        .map(|n| NackPair {
            packet_id: n * 20,
            lost_packets: 0,
        })
        .collect();
    let asked: Vec<u16> = {
        let mut asked: Vec<u16> = pairs.iter().flat_map(|pair| pair.packet_list()).collect();
        asked.sort_unstable();
        asked
    };
    let large: Vec<Box<dyn rtcp::Packet>> = vec![Box::new(TransportLayerNack {
        sender_ssrc: 0,
        media_ssrc: 200,
        nacks: pairs,
    })];
    let now = base + secs(0.01);
    chain.handle_write(rtcp(now, large)).unwrap();
    let sent = written(&mut chain);

    assert!(
        sent.len() >= 3,
        "612 octets in 300-octet packets: {}",
        sent.len()
    );
    for datagram in &sent {
        assert_eq!(now, datagram.at, "all at once");
        let size: usize = datagram.packets.iter().map(|p| p.marshal_size()).sum();
        assert!(size <= 300, "{size} octets");
        assert!(datagram.is_compound());
        assert_eq!(Some(REPORTER), datagram.leader());
        assert!(datagram.has::<TransportLayerNack>());
        for nack in datagram.get::<TransportLayerNack>() {
            assert_eq!(REPORTER, nack.sender_ssrc);
        }
    }
    assert_eq!(asked, nacked(&sent, 200), "every packet asked for, once");
}

/// RFC 4585 3.5.2 step 3: when the next regular packet is due within the dither of an Early
/// one, no Early packet is scheduled; the feedback goes with the regular packet.
#[test]
fn feedback_close_to_the_regular_packet_waits_for_it() {
    let mut chain = chain(builder());
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    // Two CNAMEs: a multiparty session, so an Early packet would be dithered by up to half
    // the regular interval (about 88 ms here; the first regular packet is due at 175 ms).
    chain
        .handle_read(rtcp(base, vec![sdes(200, "alice"), sdes(201, "bob")]))
        .unwrap();
    read(&mut chain);

    chain
        .handle_write(rtcp(base + secs(0.12), pli(200)))
        .unwrap();
    assert!(written(&mut chain).is_empty());
    let sent = run(&mut chain, base + secs(3.0));
    let carrier = sent
        .iter()
        .find(|sent| sent.has::<PictureLossIndication>())
        .expect("the PLI is sent");
    // Not as an Early packet (that would have left by 208 ms): with the first regular one.
    assert!(carrier.at > base + secs(0.25), "{:?}", carrier.at - base);
    assert_eq!(carrier.at, sent[0].at);
}

/// RFC 8108 5.4.1: feedback about a media type comes from an SSRC of that media type when
/// the endpoint sends one; RFC 3550 6.4: a sending SSRC leads with its sender report.
#[test]
fn feedback_about_video_comes_from_the_video_ssrc() {
    let mut chain = chain(builder());
    let base = Instant::now();
    chain.bind_local_stream(&audio(10));
    chain.bind_local_stream(&video(20));
    chain.bind_remote_stream(&video(200));
    chain.bind_remote_stream(&audio(300));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_write(rtp(base, 20, 1, 0)).unwrap();

    chain
        .handle_write(rtcp(base + secs(0.01), pli(200)))
        .unwrap();
    let sent = written(&mut chain);
    assert_eq!(20, sent[0].get::<PictureLossIndication>()[0].sender_ssrc);
    let report = sent[0].packets[0]
        .as_any()
        .downcast_ref::<SenderReport>()
        .expect("the video SSRC is sending: a sender report");
    assert_eq!(20, report.ssrc);
    assert!(report.reports.is_empty());

    // Feedback about audio, and about a stream the session does not know, from the first
    // media SSRC.
    let mut chain = self::chain(builder());
    chain.bind_local_stream(&audio(10));
    chain.bind_local_stream(&video(20));
    chain.bind_remote_stream(&audio(300));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain
        .handle_write(rtcp(base + secs(0.01), nack(300, 1)))
        .unwrap();
    let sent = written(&mut chain);
    assert_eq!(10, sent[0].get::<TransportLayerNack>()[0].sender_ssrc);
}

/// RFC 5506: reduced-size RTCP only when negotiated, never before a compound packet was
/// sent, and not for feedback whose delivery cannot be seen.
#[test]
fn reduced_size_feedback_needs_negotiation_and_a_first_compound_packet() {
    let mut chain = chain(builder().with_reduced_size(true));
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);

    // The first RTCP packet of the session: compound.
    chain
        .handle_write(rtcp(base + secs(0.01), pli(200)))
        .unwrap();
    let sent = written(&mut chain);
    assert!(sent[0].is_compound());

    // Later, with early feedback allowed again: the PLI alone.
    run(&mut chain, base + secs(2.0));
    chain
        .handle_write(rtcp(base + secs(2.0), pli(200)))
        .unwrap();
    let sent = written(&mut chain);
    assert_eq!(1, sent.len());
    assert_eq!(1, sent[0].packets.len());
    assert_eq!(
        REPORTER,
        sent[0].get::<PictureLossIndication>()[0].sender_ssrc
    );

    // A bitrate estimate gets no visible answer: it travels compound (RFC 5506 4.2.1).
    run(&mut chain, base + secs(4.0));
    chain
        .handle_write(rtcp(base + secs(4.0), remb(200)))
        .unwrap();
    let sent = written(&mut chain);
    assert_eq!(1, sent.len());
    assert!(sent[0].is_compound());
    assert_eq!(
        REPORTER,
        sent[0].get::<ReceiverEstimatedMaximumBitrate>()[0].sender_ssrc
    );
}

#[test]
fn without_negotiation_feedback_is_always_compound() {
    let mut chain = chain(builder());
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    for step in 1..=5u32 {
        let now = base + secs(2.0) * step;
        run(&mut chain, now);
        chain.handle_write(rtcp(now, pli(200))).unwrap();
        let sent = written(&mut chain);
        assert_eq!(1, sent.len());
        assert!(sent[0].is_compound());
    }

    // Negotiated while running.
    control(
        &mut chain,
        base + secs(11.0),
        RtcpSessionControl::ReducedSize(true),
    );
    run(&mut chain, base + secs(12.0));
    chain
        .handle_write(rtcp(base + secs(12.0), pli(200)))
        .unwrap();
    assert_eq!(1, written(&mut chain)[0].packets.len());
}

/// RFC 5506 4.2.1: when reduced-size NACKs consistently get no answer, the session goes back
/// to compound packets; an answer (a requested packet arriving) shows they get through.
#[test]
fn reduced_size_is_given_up_when_nacks_get_no_answer() {
    let mut chain = chain(builder().with_reduced_size(true));
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain
        .handle_write(rtcp(base + secs(0.01), pli(200)))
        .unwrap();
    written(&mut chain);

    let mut shapes = vec![];
    for step in 1..=12u32 {
        let now = base + secs(2.0) * step;
        run(&mut chain, now);
        chain
            .handle_write(rtcp(now, nack(200, step as u16)))
            .unwrap();
        let sent = written(&mut chain);
        assert_eq!(1, sent.len());
        shapes.push(sent[0].is_compound());
    }
    // Nine reduced-size NACKs, eight of them sent while the one before was unanswered.
    assert_eq!(
        vec![
            false, false, false, false, false, false, false, false, false, true, true, true
        ],
        shapes
    );

    // With answers arriving, it stays reduced-size.
    let mut chain = self::chain(builder().with_reduced_size(true));
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain
        .handle_write(rtcp(base + secs(0.01), pli(200)))
        .unwrap();
    written(&mut chain);
    for step in 1..=12u32 {
        let now = base + secs(2.0) * step;
        run(&mut chain, now);
        chain
            .handle_write(rtcp(now, nack(200, step as u16)))
            .unwrap();
        let sent = written(&mut chain);
        assert!(!sent[0].is_compound(), "step {step}");
        // The retransmission.
        chain
            .handle_read(rtp(now + secs(0.05), 200, step as u16, 0))
            .unwrap();
        read(&mut chain);
    }
}

/// Runs the chain from `from` to `until` while media arrives from the remote source 200, a
/// packet every 20 ms from sequence number `seq` on; returns the RTCP datagrams written.
fn run_with_media(
    chain: &mut impl Interceptor,
    from: Instant,
    until: Instant,
    seq: &mut u16,
) -> Vec<Sent> {
    let mut sent = vec![];
    let mut now = from;
    while now < until {
        now = (now + secs(0.02)).min(until);
        sent.extend(run(chain, now));
        chain
            .handle_read(rtp(now, 200, *seq, u32::from(*seq) * 3000))
            .unwrap();
        read(chain);
        *seq = seq.wrapping_add(1);
    }
    sent
}

/// Whether `sent` is a full compound packet (RFC 3550 6.1): an SR or RR first and an SDES
/// that gives the reporting SSRC's CNAME.
fn full_compound(sent: &Sent) -> bool {
    sent.is_compound()
        && sent
            .cnames()
            .iter()
            .any(|(source, _)| Some(*source) == sent.leader())
}

/// RFC 5506 4.1: a reduced-size packet "MUST NOT be used for Regular (scheduled) RTCP report
/// purposes"; 4.2.3: "all Regular RTCP MUST be full compound RTCP". With reduced-size RTCP
/// negotiated and in use (the feedback that leaves early goes reduced-size), every packet the
/// regular timer sends is still a full compound packet, an RR first with the report block of
/// the source heard and the SDES with the CNAME: the one that carries feedback stored for it
/// as well as those that carry none.
#[test]
fn regular_reports_stay_full_compound_when_reduced_size_is_negotiated() {
    use rtcp::header::PacketType;

    let mut chain = chain(builder().with_reduced_size(true));
    let base = Instant::now();
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);
    let mut seq = 1000u16;

    // The first RTCP packet of the session is compound (RFC 5506 4.2.2).
    chain
        .handle_write(rtcp(base + secs(0.01), pli(200)))
        .unwrap();
    let first = written(&mut chain);
    assert!(full_compound(&first[0]));
    let mut regular = run_with_media(&mut chain, base + secs(0.01), base + secs(2.0), &mut seq);

    // Early feedback now goes reduced-size: the PLI alone.
    let now = base + secs(2.0);
    chain.handle_write(rtcp(now, pli(200))).unwrap();
    let early = written(&mut chain);
    assert_eq!(1, early.len());
    assert!(!early[0].is_compound(), "reduced-size RTCP is in use");
    assert_eq!(1, early[0].packets.len());

    // No other Early packet is allowed now: a NACK waits for the regular packet, which is
    // full compound with the NACK in it.
    chain
        .handle_write(rtcp(now + secs(0.001), nack(200, seq.wrapping_sub(1))))
        .unwrap();
    assert!(written(&mut chain).is_empty());
    let after = run_with_media(&mut chain, now + secs(0.001), now + secs(12.0), &mut seq);
    let carrier = after
        .iter()
        .find(|sent| sent.has::<TransportLayerNack>())
        .expect("the stored NACK is sent");
    assert_eq!(
        carrier.at, after[0].at,
        "with the next packet the timer sends"
    );
    assert!(
        full_compound(carrier),
        "the regular packet that carries feedback is full compound: {:?}",
        carrier.packets
    );
    regular.extend(after);

    // Thirty more seconds with no feedback: every packet is a regular one.
    let now = base + secs(14.0);
    regular.extend(run_with_media(&mut chain, now, now + secs(30.0), &mut seq));
    let reports = regular
        .iter()
        .filter(|sent| sent.reported().contains(&200))
        .count();
    assert!(reports >= 5, "{reports} regular reports in 42 s");
    for sent in &regular {
        assert!(
            full_compound(sent),
            "a packet the regular timer sent is not full compound: {:?}",
            sent.packets
        );
    }
    // Reduced-size packets carry feedback only (RFC 5506 4.2.1).
    for packet in &early[0].packets {
        assert!(matches!(
            packet.header().packet_type,
            PacketType::TransportSpecificFeedback | PacketType::PayloadSpecificFeedback
        ));
    }
}

/// RFC 8108 5.4.2 and RFC 4585 3.5.2: with remote sources under more than one CNAME the
/// session is multiparty, and an Early packet is dithered instead of leaving at once.
#[test]
fn early_feedback_is_dithered_in_a_multiparty_session() {
    let mut chain = chain(builder());
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    chain
        .handle_read(rtcp(base, vec![sdes(200, "alice"), sdes(201, "bob")]))
        .unwrap();
    read(&mut chain);

    let now = base + secs(0.01);
    chain.handle_write(rtcp(now, pli(200))).unwrap();
    assert!(written(&mut chain).is_empty(), "not at once");
    // Feedback detected while that packet is scheduled joins it (step 2a).
    chain
        .handle_write(rtcp(now + secs(0.005), nack(201, 4)))
        .unwrap();
    assert!(written(&mut chain).is_empty());
    let sent = run(&mut chain, base + secs(2.0));
    let early = sent
        .iter()
        .find(|sent| sent.has::<PictureLossIndication>())
        .expect("the PLI is sent");
    assert!(early.at > now);
    assert!(early.at < now + secs(0.1), "{:?}", early.at - now);
    assert!(early.has::<TransportLayerNack>(), "one packet carries both");

    // Said to be point to point (RFC 8108 5.4.2: "unless signaling indicates"), it is not.
    let mut chain = self::chain(builder().with_point_to_point(true));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain
        .handle_read(rtcp(base, vec![sdes(200, "alice"), sdes(201, "bob")]))
        .unwrap();
    read(&mut chain);
    chain.handle_write(rtcp(now, pli(200))).unwrap();
    assert_eq!(1, written(&mut chain).len());
}

/// Reports written by anything but the session are not sent beside its own: one voice.
#[test]
fn reports_written_from_above_are_replaced_by_the_sessions_own() {
    let mut chain = chain(builder());
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);
    chain
        .handle_write(rtcp(
            base + secs(0.01),
            vec![
                Box::new(ReceiverReport {
                    ssrc: 0x7777,
                    ..Default::default()
                }),
                sdes(0x7777, "someone-else"),
            ],
        ))
        .unwrap();

    let sent = run(&mut chain, base + secs(3.0));
    assert!(!sent.is_empty());
    for sent in &sent {
        assert_eq!(Some(REPORTER), sent.leader());
        assert!(sent.cnames().iter().all(|c| c.0 == REPORTER));
    }
}

/// RTP passes the session untouched in both directions, and inbound RTCP goes on to the
/// interceptors behind it.
#[test]
fn media_and_inbound_rtcp_pass_through() {
    let mut chain = rtci_interceptor::Registry::new()
        .with(rtci_interceptor::Slot::RtcpSession, builder().build())
        .with(
            rtci_interceptor::Slot::KeyFrameRequests,
            rtci_interceptor::KeyFrameRequestInterceptor::new(),
        )
        .build();
    let base = Instant::now();
    chain.bind_local_stream(&video(100));
    chain.handle_write(rtp(base, 100, 5, 0)).unwrap();
    let out = chain.poll_write().expect("the packet");
    assert!(
        matches!(out.message.packet, rtci_interceptor::Packet::Rtp(p) if p.header.sequence_number == 5)
    );

    chain.handle_read(rtcp(base, pli(100))).unwrap();
    let (packets, _) = read(&mut chain);
    assert_eq!(
        1,
        packets.len(),
        "the key-frame request reaches the application"
    );
}

fn sender_report_request(media_ssrc: u32) -> Vec<Box<dyn rtcp::Packet>> {
    vec![Box::new(
        rtcp::transport_feedbacks::rapid_resynchronization_request::RapidResynchronizationRequest {
            sender_ssrc: 200,
            media_ssrc,
        },
    )]
}

/// RFC 6051 section 3.2: "a media source that understands the RTCP-SR-REQ packet SHOULD
/// generate an RTCP SR packet as soon as possible while complying with the RTCP early feedback
/// rules". Between two parties (no dither) the SR of the SSRC the request names leaves at
/// once, in an Early compound packet, long before the first regular one; a request for an
/// SSRC this side does not send gets nothing early.
#[test]
fn an_rtcp_sr_req_is_answered_with_a_sender_report_at_once() {
    let mut chain = chain(builder().with_bandwidth(RtcpBandwidth {
        session: Some(64_000),
        ..Default::default()
    }));
    let base = Instant::now();
    chain.bind_local_stream(&video(100));
    chain.bind_remote_stream(&video(200));
    control(&mut chain, base, RtcpSessionControl::Start);
    chain.handle_write(rtp(base, 100, 1, 3000)).unwrap();
    assert!(
        written(&mut chain)
            .iter()
            .all(|sent| !sent.has::<SenderReport>())
    );

    let other = base + secs(0.02);
    chain
        .handle_read(rtcp(other, sender_report_request(4242)))
        .unwrap();
    read(&mut chain);
    assert!(written(&mut chain).is_empty(), "not an SSRC of ours");

    let now = base + secs(0.05);
    chain
        .handle_read(rtcp(now, sender_report_request(100)))
        .unwrap();
    read(&mut chain);
    let sent = written(&mut chain);
    assert_eq!(1, sent.len(), "an Early packet");
    assert_eq!(now, sent[0].at);
    let reports = sent[0].get::<SenderReport>();
    assert_eq!(1, reports.len());
    assert_eq!(100, reports[0].ssrc);
}

/// RFC 5104 sections 4.3.2.3 and 4.3.3.3: a TSTR "is not time critical and SHOULD be sent
/// using regular RTCP timing", and so does the TSTN that acknowledges it. Written where a PLI
/// would leave at once in an Early packet, each waits for the next regular compound packet.
#[test]
fn a_tstr_and_a_tstn_wait_for_the_regular_packet() {
    use rtcp::payload_feedbacks::temporal_spatial_tradeoff::{
        TemporalSpatialTradeoffNotification, TemporalSpatialTradeoffRequest, TstEntry,
    };
    for request in [true, false] {
        let mut chain = chain(builder());
        let base = Instant::now();
        chain.bind_remote_stream(&video(200));
        control(&mut chain, base, RtcpSessionControl::Start);
        let entries = vec![TstEntry {
            ssrc: 200,
            sequence_number: 0,
            index: 7,
        }];
        let packet: Box<dyn rtcp::Packet> = if request {
            Box::new(TemporalSpatialTradeoffRequest {
                sender_ssrc: 0,
                entries,
            })
        } else {
            Box::new(TemporalSpatialTradeoffNotification {
                sender_ssrc: 0,
                entries,
            })
        };
        let now = base + secs(0.01);
        chain.handle_write(rtcp(now, vec![packet])).unwrap();
        assert!(
            written(&mut chain).is_empty(),
            "no Early packet (TSTR: {request})"
        );

        let sent = run(&mut chain, base + secs(10.0));
        let first = sent.first().expect("a regular packet");
        assert!(first.is_compound());
        let carried = if request {
            first.has::<TemporalSpatialTradeoffRequest>()
        } else {
            first.has::<TemporalSpatialTradeoffNotification>()
        };
        assert!(carried, "the regular packet carries it (TSTR: {request})");
    }
}

/// RFC 7728 sections 6.3 and 8.2 (PAUSED "SHALL also [be repeated] in the next two regular
/// RTCP reports"), through [`RepeatInRegularReports`]: the packet leaves as feedback (an Early
/// packet: the minimal compound packet, no report blocks) and a copy of it rides each of the
/// next two Regular compound packets, the ones with the report blocks, and no packet after
/// them. [`RtcpSessionControl::StopRepeating`] ends what is still owed.
#[test]
fn a_packet_to_repeat_rides_the_next_two_regular_packets() {
    use rtci_interceptor::{Attribute, RepeatInRegularReports};
    use rtcp::transport_feedbacks::pause_resume::{PauseResume, PauseResumeEntry};
    use std::sync::Arc;

    let paused = |now: Instant, count: u8| {
        let mut packet = rtcp(
            now,
            vec![Box::new(PauseResume {
                sender_ssrc: 300,
                entries: vec![PauseResumeEntry::paused(300, 7, 1000)],
            })],
        );
        packet
            .message
            .attributes
            .push(Attribute::Custom(Arc::new(RepeatInRegularReports {
                key: 300,
                count,
            })));
        packet
    };
    for stop in [false, true] {
        let mut chain = chain(builder());
        let base = Instant::now();
        chain.bind_local_stream(&video(300));
        chain.bind_remote_stream(&video(200));
        control(&mut chain, base, RtcpSessionControl::Start);
        // The remote stream is received, so a Regular packet reports on it.
        let mut sent = vec![];
        let mut seq = 0u16;
        let mut t = base;
        let until = base + secs(40.0);
        let mut pause_at = None;
        while t < until {
            chain
                .handle_read(rtp(t, 200, seq, u32::from(seq) * 3000))
                .unwrap();
            let _ = read(&mut chain);
            seq = seq.wrapping_add(1);
            if pause_at.is_none() && t >= base + secs(8.0) {
                chain.handle_write(paused(t, 2)).unwrap();
                pause_at = Some(t);
            }
            if stop && pause_at == Some(t) {
                sent.extend(written(&mut chain));
                control(
                    &mut chain,
                    t,
                    RtcpSessionControl::StopRepeating { key: 300 },
                );
            }
            t += secs(0.1);
            sent.extend(run(&mut chain, t));
        }
        let pause_at = pause_at.expect("written");
        let after: Vec<&Sent> = sent.iter().filter(|s| s.at >= pause_at).collect();
        let carrying: Vec<usize> = after
            .iter()
            .enumerate()
            .filter(|(_, sent)| sent.has::<PauseResume>())
            .map(|(i, _)| i)
            .collect();
        assert_eq!(after[0].at, pause_at, "the first copy leaves at once");
        assert!(after[0].reported().is_empty(), "in an Early packet");
        assert_eq!(carrying[0], 0);
        let regular: Vec<usize> = after
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(_, sent)| !sent.reported().is_empty())
            .map(|(i, _)| i)
            .collect();
        assert!(
            regular.len() >= 4,
            "regular packets follow: {}",
            regular.len()
        );
        if stop {
            assert_eq!(carrying, vec![0], "stopped before the next regular packet");
        } else {
            assert_eq!(
                carrying,
                vec![0, regular[0], regular[1]],
                "the next two regular packets carry it, and no other"
            );
        }
    }
}

fn twcc(media_ssrc: u32, count: u8) -> Vec<Box<dyn rtcp::Packet>> {
    use rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;
    vec![Box::new(TransportLayerCc {
        sender_ssrc: 0,
        media_ssrc,
        fb_pkt_count: count,
        ..Default::default()
    })]
}

/// RFC 4585 section 3.5.2, as written, for congestion control feedback too
/// (`with_immediate_congestion_feedback(false)`): after an Early packet a second transport-wide
/// feedback message is held for the next regular packet ("allow_early == FALSE"), not sent
/// at once. With the default (`true`) each leaves as it is built.
#[test]
fn with_rfc_4585_timing_a_second_congestion_feedback_waits_for_the_regular_packet() {
    use rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;
    for immediate in [false, true] {
        let mut chain = chain(
            builder()
                .with_bandwidth(RtcpBandwidth {
                    session: Some(64_000),
                    ..Default::default()
                })
                .with_immediate_congestion_feedback(immediate),
        );
        let base = Instant::now();
        chain.bind_remote_stream(&video(200));
        control(&mut chain, base, RtcpSessionControl::Start);

        chain
            .handle_write(rtcp(base + secs(0.01), twcc(200, 1)))
            .unwrap();
        assert_eq!(1, written(&mut chain).len(), "immediate {immediate}");
        chain
            .handle_write(rtcp(base + secs(0.02), twcc(200, 2)))
            .unwrap();
        let second = written(&mut chain);
        if immediate {
            assert_eq!(1, second.len(), "leaves as it is built");
            assert_eq!(1, second[0].get::<TransportLayerCc>().len());
        } else {
            assert!(second.is_empty(), "no second Early packet");
            let sent = run(&mut chain, base + secs(0.9));
            assert!(!sent.is_empty());
            assert!(sent[0].at > base + secs(0.02));
            assert!(sent[0].is_compound(), "with the regular packet");
            assert_eq!(1, sent[0].get::<TransportLayerCc>().len());
        }
    }
}

/// The RTCP datagrams a chain wrote, without the attribute carriers that pass it.
fn datagrams(chain: &mut impl Interceptor) -> Vec<Sent> {
    let mut sent = vec![];
    while let Some(tagged) = chain.poll_write() {
        if let Packet::Rtcp(packets) = tagged.message.packet
            && !packets.is_empty()
        {
            sent.push(Sent {
                at: tagged.now,
                packets,
            });
        }
    }
    sent
}

/// RFC 5104 section 4.2.1.3: "The first transmission of the TMMBR message MAY use early or
/// immediate feedback [...]. Any repetition of a request message SHOULD use regular RTCP mode
/// for its transmission timing." Congestion control above the RTCP session: the first TMMBR
/// leaves at once in an Early (minimal) compound packet; every repetition of it, while no
/// TMMBN answers, rides a Regular compound packet (one with the report block on the media
/// sender), never an Early one of its own.
#[test]
fn a_repeated_tmmbr_waits_for_the_regular_compound_packet() {
    use rtci_interceptor::{
        CongestionControlBuilder, ConstantBitrate, Registry, Slot, StreamInfo, TmmbrControl,
    };
    use rtcp::transport_feedbacks::tmmb::TemporaryMaximumBitrateRequest;

    let (cc, _handle) =
        CongestionControlBuilder::new(ConstantBitrate::new(2_000_000.0)).build_with_handle();
    let mut chain = Registry::new()
        .with(Slot::CongestionControl, cc)
        .with(Slot::RtcpSession, builder().build())
        .build();
    let media = StreamInfo {
        rtcp_feedback: vec![feedback("ccm", "tmmbr")],
        ..video(200)
    };
    chain.bind_remote_stream(&media);
    let base = Instant::now();
    control(&mut chain, base, RtcpSessionControl::Start);

    let limit_at = base + secs(0.5);
    let mut sent = vec![];
    let mut at = base;
    let mut sequence_number = 0u16;
    let mut limited = false;
    while at < base + secs(8.0) {
        sequence_number = sequence_number.wrapping_add(1);
        chain
            .handle_read(rtp(
                at,
                200,
                sequence_number,
                u32::from(sequence_number) * 3000,
            ))
            .unwrap();
        read(&mut chain);
        if !limited && at >= limit_at {
            limited = true;
            chain
                .handle_write(
                    TmmbrControl::Limit {
                        media_ssrc: 200,
                        bitrate: 250_000,
                    }
                    .into_packet(at),
                )
                .unwrap();
            sent.extend(datagrams(&mut chain));
        }
        at += secs(0.02);
        while let Some(next) = chain.poll_timeout() {
            if next > at {
                break;
            }
            chain.handle_timeout(next).unwrap();
            sent.extend(datagrams(&mut chain));
        }
        chain.handle_timeout(at).unwrap();
        sent.extend(datagrams(&mut chain));
    }

    let with_request: Vec<&Sent> = sent
        .iter()
        .filter(|datagram| datagram.has::<TemporaryMaximumBitrateRequest>())
        .collect();
    assert!(
        with_request.len() >= 4,
        "repeated while no TMMBN answers: {}",
        with_request.len()
    );
    let first = with_request[0];
    assert!(
        first.at >= limit_at && first.at < limit_at + secs(0.02),
        "at once"
    );
    assert!(first.is_compound());
    for repetition in &with_request[1..] {
        assert!(repetition.is_compound());
        assert!(
            repetition.reported().contains(&200),
            "a repetition at {:?} left in an Early packet, not a Regular one",
            repetition.at - base
        );
    }
}

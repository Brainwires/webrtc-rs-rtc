//! RFC 3758 (PR-SCTP) and RFC 7496: negotiation, FORWARD TSN on the receiving side whatever
//! this side's own settings for the stream, lifetimes of messages not yet sent, and the size
//! of a FORWARD TSN.

use super::robustness_test::*;
use super::*;
use crate::chunk::chunk_type::*;
use crate::endpoint::Endpoint;
use crate::endpoint::link_test::Link;
use crate::{ClientConfig, EndpointConfig};
use std::cell::RefCell;
use std::rc::Rc;

const PPI: PayloadProtocolIdentifier = PayloadProtocolIdentifier::Binary;

fn data(
    tsn: u32,
    stream: u16,
    ssn: u16,
    unordered: bool,
    begin: bool,
    end: bool,
) -> ChunkPayloadData {
    ChunkPayloadData {
        tsn,
        stream_identifier: stream,
        stream_sequence_number: ssn,
        unordered,
        beginning_fragment: begin,
        ending_fragment: end,
        payload_type: PPI,
        user_data: Bytes::from_static(b"0123456789"),
        ..Default::default()
    }
}

fn forward_tsns(datagrams: &[Bytes]) -> Vec<ChunkForwardTsn> {
    datagrams
        .iter()
        .flat_map(|raw| Packet::unmarshal(raw).unwrap().chunks)
        .filter_map(|c| {
            c.as_any()
                .downcast_ref::<ChunkForwardTsn>()
                .map(|f| ChunkForwardTsn {
                    new_cumulative_tsn: f.new_cumulative_tsn,
                    streams: f
                        .streams
                        .iter()
                        .map(|s| ChunkForwardTsnStream {
                            identifier: s.identifier,
                            sequence: s.sequence,
                        })
                        .collect(),
                })
        })
        .collect()
}

/// RFC 3758 3.6: a FORWARD TSN removes every partially reassembled message that misses a TSN
/// at or below the new cumulative TSN. Unordered fragments were kept, and counted against
/// the receive window for the life of the stream, when this side's own setting for the
/// stream was ordered (the default, and the state of a stream before its DCEP OPEN is read).
#[test]
fn forward_tsn_removes_unordered_fragments_whatever_this_side_sends() -> Result<()> {
    let mut a = timed_test_association();
    let base = a.peer_last_tsn;
    // The beginning of an unordered message whose rest the peer has given up.
    a.handle_data(&data(base.wrapping_add(2), 1, 0, true, true, false))?;
    assert_eq!(10, a.bytes_in_reassembly_queues());

    a.handle_forward_tsn(&ChunkForwardTsn {
        new_cumulative_tsn: base.wrapping_add(3),
        streams: vec![],
    })?;
    assert_eq!(base.wrapping_add(3), a.peer_last_tsn);
    assert_eq!(
        0,
        a.bytes_in_reassembly_queues(),
        "the abandoned fragment is held"
    );
    Ok(())
}

/// RFC 3758 3.6: the stream sequence numbers a FORWARD TSN lists release the ordered data
/// stranded behind the abandoned message, on every stream listed. They were ignored when
/// this side's own setting for the stream was unordered.
#[test]
fn forward_tsn_releases_ordered_data_whatever_this_side_sends() -> Result<()> {
    let mut a = timed_test_association();
    let base = a.peer_last_tsn;
    a.open_stream(1, PPI)?
        .set_reliability_params(true, ReliabilityType::Rexmit, 0)?;
    // SSN 0 (TSN base+1) is lost; SSN 1 arrives and waits behind it.
    a.handle_data(&data(base.wrapping_add(2), 1, 1, false, true, true))?;
    assert!(!a.streams[&1].reassembly_queue.is_readable());

    a.handle_forward_tsn(&ChunkForwardTsn {
        new_cumulative_tsn: base.wrapping_add(1),
        streams: vec![ChunkForwardTsnStream {
            identifier: 1,
            sequence: 0,
        }],
    })?;
    assert!(
        a.streams[&1].reassembly_queue.is_readable(),
        "the message after the abandoned one is still held back"
    );
    Ok(())
}

/// RFC 3758 4.1 (TR3, TR4): the lifetime of a message is checked before it is transmitted,
/// and an expired message MUST NOT get a TSN. An ordered message whose lifetime ran out while
/// it waited for the window was sent all the same; later it was abandoned with a TSN and a
/// FORWARD TSN, because its stream sequence number was given when it was written. A message
/// now takes its stream sequence number when its first fragment is sent: the expired one is
/// dropped with neither a TSN nor a number, and the next message takes both.
#[test]
fn an_ordered_message_that_expired_in_the_queue_is_not_sent() -> Result<()> {
    let mut a = timed_test_association();
    let start = Instant::now();
    let first = a.my_next_tsn;
    a.cwnd = 1000;
    {
        let mut s = a.open_stream(1, PPI)?;
        s.set_reliability_params(false, ReliabilityType::Timed, 100)?;
        s.write_sctp(start, &Bytes::from(vec![0u8; 1000]), PPI)?;
        s.write_sctp(start, &Bytes::from(vec![1u8; 1000]), PPI)?;
    }
    let sent = transmitted_data(&a.gather_outbound(start).0);
    assert_eq!(vec![first], sent.iter().map(|c| c.tsn).collect::<Vec<_>>());
    assert_eq!(0, sent[0].stream_sequence_number);

    // A second later the window opens. The second message is ten lifetimes old.
    let later = start + Duration::from_secs(1);
    a.handle_sack(
        &ChunkSelectiveAck {
            cumulative_tsn_ack: first,
            advertised_receiver_window_credit: 1 << 20,
            gap_ack_blocks: vec![],
            duplicate_tsn: vec![],
        },
        later,
    )?;
    a.stream(1)?
        .write_sctp(later, &Bytes::from(vec![2u8; 1000]), PPI)?;
    let datagrams = a.gather_outbound(later).0;
    let sent = transmitted_data(&datagrams);
    assert_eq!(1, sent.len(), "only the message written just now");
    assert_eq!(2, sent[0].user_data[0]);
    assert_eq!(
        first.wrapping_add(1),
        sent[0].tsn,
        "the expired message took no TSN"
    );
    assert_eq!(
        1, sent[0].stream_sequence_number,
        "the expired message took no stream sequence number"
    );
    assert!(
        forward_tsns(&datagrams).is_empty(),
        "nothing for the peer to pass over"
    );
    // RFC 3758 4.1 TR3: "SHOULD issue a notification to the upper layer".
    let abandoned: Vec<(u16, bool)> = a
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Stream(StreamEvent::MessageAbandoned { id, transmitted }) => {
                Some((*id, *transmitted))
            }
            _ => None,
        })
        .collect();
    assert_eq!(abandoned, vec![(1, false)], "the upper layer is told");
    Ok(())
}

/// RFC 3758 3.5 (C4): a FORWARD TSN fits one packet. With abandoned messages on more ordered
/// streams than fit, the chunk covered them all and went past the MTU (and past 16382
/// streams its length field wrapped). It now stops at the last TSN whose streams fit, and
/// the next one goes on from there.
#[test]
fn a_forward_tsn_fits_one_packet() -> Result<()> {
    const STREAMS: u16 = 400;
    let mut a = create_association_with_mtu(1200);
    a.control_queue.clear();
    a.timers.stop(Timer::T1Init);
    a.set_state(AssociationState::Established);
    a.use_forward_tsn = true;
    a.rwnd = 1 << 24;
    a.cwnd = 1 << 24;
    a.rto_mgr.set_rto(1000, true);
    let now = Instant::now();
    let first = a.my_next_tsn;
    for id in 0..STREAMS {
        let mut s = a.open_stream(id, PPI)?;
        s.set_reliability_params(false, ReliabilityType::Rexmit, 0)?;
        s.write_sctp(now, &Bytes::from_static(b"x"), PPI)?;
    }
    assert_eq!(
        STREAMS as usize,
        transmitted_data(&a.gather_outbound(now).0).len()
    );

    // Nothing is acknowledged: at the timeout every message has used up its retransmissions.
    let at = a.timers.get(Timer::T3RTX).expect("T3-rtx runs");
    a.handle_timeout(at);
    let datagrams = a.gather_outbound(at).0;
    for datagram in &datagrams {
        assert!(
            datagram.len() <= 1200,
            "a packet of {} bytes",
            datagram.len()
        );
    }
    let forward = forward_tsns(&datagrams);
    assert_eq!(1, forward.len());
    let room = (1200 - 12 - 4 - 4) / 4;
    assert_eq!(room, forward[0].streams.len(), "as many streams as fit");
    assert_eq!(
        first.wrapping_add(room as u32 - 1),
        forward[0].new_cumulative_tsn,
        "and the cumulative TSN that goes with them"
    );

    // The peer acknowledges that much; the rest follows.
    a.handle_sack(
        &ChunkSelectiveAck {
            cumulative_tsn_ack: forward[0].new_cumulative_tsn,
            advertised_receiver_window_credit: 1 << 24,
            gap_ack_blocks: vec![],
            duplicate_tsn: vec![],
        },
        at,
    )?;
    let forward = forward_tsns(&a.gather_outbound(at).0);
    assert_eq!(1, forward.len());
    assert_eq!(
        first.wrapping_add(u32::from(STREAMS) - 1),
        forward[0].new_cumulative_tsn
    );
    assert_eq!(STREAMS as usize - room, forward[0].streams.len());
    Ok(())
}

// ---- Negotiation (RFC 3758 3.3) ----------------------------------------------------------------

fn param_types(chunk: &[u8]) -> Vec<u16> {
    tlvs(&chunk[20..]).into_iter().map(|(typ, _)| typ).collect()
}

fn supported_chunks(chunk: &[u8]) -> Vec<u8> {
    tlvs(&chunk[20..])
        .into_iter()
        .find(|(typ, _)| *typ == 0x8008)
        .map(|(_, value)| value)
        .unwrap_or_default()
}

/// RFC 3758 3.3.1, 3.3.2: an endpoint that does PR-SCTP says so with the
/// Forward-TSN-Supported parameter in its INIT and its INIT ACK. Only the Supported
/// Extensions list said it, which a peer that knows only RFC 3758 does not read.
#[test]
fn forward_tsn_supported_is_announced_in_init_and_init_ack() {
    let mut link = Link::new(TransportConfig::default(), TransportConfig::default(), 401);
    let seen = Rc::new(RefCell::new(vec![]));
    let log = seen.clone();
    link.filter = Some(Box::new(move |_from_client: bool, datagram: &Bytes| {
        log.borrow_mut().push(datagram.clone());
        false
    }));
    link.connect();
    let datagrams = seen.borrow().clone();
    for typ in [CT_INIT.0, CT_INIT_ACK.0] {
        let chunk = chunks_of_type(&datagrams, typ).remove(0);
        assert!(param_types(&chunk).contains(&49152), "chunk type {typ}");
        assert!(supported_chunks(&chunk).contains(&CT_FORWARD_TSN.0));
    }
    assert!(link.client.conn().partial_reliability());
    assert!(link.server.conn().partial_reliability());
}

/// RFC 3758 4.2: PR-SCTP can be turned off before the association is set up. Then it is not
/// announced either way, the association does not use it, and the upper layer can tell.
#[test]
fn partial_reliability_can_be_turned_off() {
    let off = TransportConfig::default().with_partial_reliability(false);
    for (client, server) in [
        (off.clone(), TransportConfig::default()),
        (TransportConfig::default(), off.clone()),
    ] {
        let client_off = !client.partial_reliability();
        let mut link = Link::new(client, server, 402);
        let seen = Rc::new(RefCell::new(vec![]));
        let log = seen.clone();
        link.filter = Some(Box::new(move |_from_client: bool, datagram: &Bytes| {
            log.borrow_mut().push(datagram.clone());
            false
        }));
        link.connect();
        let datagrams = seen.borrow().clone();
        let typ = if client_off { CT_INIT.0 } else { CT_INIT_ACK.0 };
        let chunk = chunks_of_type(&datagrams, typ).remove(0);
        assert!(!param_types(&chunk).contains(&49152));
        assert!(!supported_chunks(&chunk).contains(&CT_FORWARD_TSN.0));
        assert!(
            !link.client.conn().partial_reliability(),
            "one side is not enough"
        );
        assert!(!link.server.conn().partial_reliability());
    }
}

/// RFC 3758 3.3.1, 3.3.2: without PR-SCTP on both sides no FORWARD TSN is ever sent (a
/// message on a stream with a retransmission limit is then sent reliably), and a FORWARD TSN
/// received is answered with an ERROR "Unrecognized Chunk Type" that holds the chunk.
#[test]
fn without_partial_reliability_no_forward_tsn_is_sent_or_taken() {
    let off = TransportConfig::default().with_partial_reliability(false);
    let mut link = Link::new(TransportConfig::default(), off, 403);
    let forward_tsns_sent = Rc::new(RefCell::new(0));
    let count = forward_tsns_sent.clone();
    let mut dropped = false;
    link.filter = Some(Box::new(move |from_client: bool, datagram: &Bytes| {
        if from_client && datagram.get(12) == Some(&CT_FORWARD_TSN.0) {
            *count.borrow_mut() += 1;
        }
        if from_client && !dropped && datagram.get(12) == Some(&0) {
            dropped = true;
            return true;
        }
        false
    }));
    link.connect();
    let now = link.now;
    {
        let mut s = link.client.conn().open_stream(1, PPI).unwrap();
        s.set_reliability_params(false, ReliabilityType::Rexmit, 0)
            .unwrap();
        s.write_sctp(now, &Bytes::from_static(b"lost once"), PPI)
            .unwrap();
    }
    let deadline = link.now + Duration::from_secs(30);
    assert!(
        link.run_until(deadline, |l| !l.server.received.is_empty()),
        "the message was abandoned though the peer cannot be told"
    );
    assert_eq!(0, *forward_tsns_sent.borrow());

    let now = link.now;
    let a = link.server.conn();
    let forward = chunk_bytes(&ChunkForwardTsn {
        new_cumulative_tsn: a.peer_last_tsn.wrapping_add(5),
        streams: vec![],
    });
    let before = a.peer_last_tsn;
    let raw = packet_to(a, std::slice::from_ref(&forward));
    inject(a, now, raw);
    assert_eq!(before, a.peer_last_tsn, "the FORWARD TSN is not applied");
    let errors = chunks_of_type(&sent_datagrams(a, now), CT_ERROR.0);
    assert_eq!(1, errors.len());
    assert_eq!(vec![(6u16, forward)], tlvs(&errors[0][4..]));
}

/// RFC 3758 3.3.3: a peer that reports the Forward-TSN-Supported parameter as unrecognized,
/// in its INIT ACK or in an ERROR, does not do PR-SCTP: the association goes on without it.
#[test]
fn a_peer_that_rejects_the_parameter_gets_no_partial_reliability() {
    let rejected = raw_tlv(49152, &[]);

    // In the INIT ACK, as an Unrecognized Parameter.
    let mut endpoint = Endpoint::new(
        remote(),
        TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        None,
    );
    let now = Instant::now();
    let (_, mut a) = endpoint
        .connect(
            now,
            ClientConfig::new(TransportConfig::default()),
            "10.0.0.2:5000".parse().unwrap(),
        )
        .unwrap();
    let _ = sent_datagrams(&mut a, now);
    let init_ack = init_chunk(
        CT_INIT_ACK.0,
        4242,
        9000,
        &[
            raw_tlv(7, b"cookie"),
            raw_tlv(8, &rejected),
            raw_tlv(0x8008, &[CT_FORWARD_TSN.0]),
        ],
    );
    let raw = packet_to(&a, &[init_ack]);
    inject(&mut a, now, raw);
    assert_eq!(AssociationState::CookieEchoed, a.state());
    assert!(!a.partial_reliability());

    // In an ERROR, on an association that had it.
    let mut link = connected_link(404);
    let now = link.now;
    let a = link.client.conn();
    assert!(a.partial_reliability());
    let raw = packet_to(a, &[raw_chunk(CT_ERROR.0, 0, &raw_tlv(8, &rejected))]);
    inject(a, now, raw);
    assert!(!a.partial_reliability());
    assert!(!a.is_ended(), "the association goes on");
}

/// The counters that explain how long a partially reliable transfer over a lossy path takes
/// (`AssociationStats`): a T3-rtx expiry and the RTO it waited, the message it abandoned instead
/// of sending again (RFC 3758 3.5 A2, A5), the FORWARD TSN that skips it (C3), and no
/// retransmission. For a reliable message the same expiry is one retransmission.
#[test]
fn a_t3_expiry_is_counted_with_what_it_abandoned_or_sent_again() -> Result<()> {
    for reliable in [false, true] {
        let mut a = timed_test_association();
        let now = Instant::now();
        {
            let mut s = a.open_stream(1, PPI)?;
            if !reliable {
                s.set_reliability_params(true, ReliabilityType::Rexmit, 0)?;
            }
            s.write_sctp(now, &Bytes::from_static(b"lost"), PPI)?;
        }
        assert_eq!(1, transmitted_data(&a.gather_outbound(now).0).len());
        let at = a.timers.get(Timer::T3RTX).unwrap();
        a.handle_timeout(at);
        let _ = a.gather_outbound(at);

        let mut stats = a.stats();
        assert_eq!(1, stats.get_num_t3timeouts(), "reliable: {reliable}");
        assert_eq!(Duration::from_millis(1000), stats.get_t3_wait());
        assert_eq!(u64::from(reliable), stats.get_num_retransmissions());
        assert_eq!(u64::from(!reliable), stats.get_num_abandoned_messages());
        assert_eq!(u64::from(!reliable), stats.get_num_forward_tsns());
        assert_eq!(0, stats.get_num_fast_retrans());
    }
    Ok(())
}

/// `AssociationStats::get_num_partially_reliable_retransmissions` tells the retransmissions of
/// a channel with `maxRetransmits` 0 (RFC 8831 6.6, RFC 7496) from those of a reliable message
/// sent beside it: the DCEP DATA_CHANNEL_OPEN, sent reliably whatever the channel's
/// reliability (RFC 8832 5), whose acknowledgement can be lost after the channel's own messages
/// have started. One T3-rtx expiry with both outstanding sends the OPEN again (a retransmission)
/// and abandons the unreliable message (RFC 3758 3.5 A2): one retransmission in all, none of
/// partially reliable DATA. (tests/testenv_impairment.rs
/// `unreliable_channel_loses_without_retransmitting` counted every retransmission from the first
/// message and failed when the OPEN's went again after it, run 46050142067.)
#[test]
fn a_reliable_message_sent_again_is_not_counted_as_a_partially_reliable_retransmission()
-> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    a.open_stream(0, PayloadProtocolIdentifier::Dcep)?
        .write_sctp(
            now,
            &Bytes::from_static(b"open"),
            PayloadProtocolIdentifier::Dcep,
        )?;
    {
        let mut s = a.open_stream(1, PPI)?;
        s.set_reliability_params(true, ReliabilityType::Rexmit, 0)?;
        s.write_sctp(now, &Bytes::from_static(b"user"), PPI)?;
    }
    let sent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(2, sent.len(), "the OPEN and the user message");
    let at = a.timers.get(Timer::T3RTX).unwrap();
    a.handle_timeout(at);
    let again = transmitted_data(&a.gather_outbound(at).0);
    assert_eq!(
        vec![0],
        again
            .iter()
            .map(|c| c.stream_identifier)
            .collect::<Vec<_>>(),
        "only the reliable message goes again"
    );

    let mut stats = a.stats();
    assert_eq!(1, stats.get_num_retransmissions());
    assert_eq!(0, stats.get_num_partially_reliable_retransmissions());
    assert_eq!(1, stats.get_num_abandoned_messages());
    Ok(())
}

/// A loss that three miss indications reveal (RFC 9260 7.2.4) in a message whose retransmission
/// budget is spent is abandoned there and skipped with FORWARD TSN (RFC 3758 3.5 A2, C3), and
/// counted as such, not as a Fast Retransmit or a T3-rtx expiry.
#[test]
fn a_loss_found_by_fast_retransmit_in_a_spent_message_is_counted_as_abandoned() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    {
        let mut s = a.open_stream(1, PPI)?;
        s.set_reliability_params(true, ReliabilityType::Rexmit, 0)?;
        for i in 0..5u8 {
            s.write_sctp(now, &Bytes::from(vec![i; 100]), PPI)?;
        }
    }
    let sent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(5, sent.len());
    let first = sent[0].tsn;
    // The first is lost; the next ones arrive, each reported by a SACK.
    for end in 2..=4u16 {
        a.handle_sack(
            &ChunkSelectiveAck {
                cumulative_tsn_ack: first.wrapping_sub(1),
                advertised_receiver_window_credit: 1 << 20,
                gap_ack_blocks: vec![crate::chunk::chunk_selective_ack::GapAckBlock {
                    start: 2,
                    end,
                }],
                duplicate_tsn: vec![],
            },
            now,
        )?;
    }
    let out = a.gather_outbound(now).0;
    assert!(transmitted_data(&out).is_empty(), "nothing is sent again");
    let mut stats = a.stats();
    assert_eq!(1, stats.get_num_fast_retrans_abandoned());
    assert_eq!(1, stats.get_num_abandoned_messages());
    assert_eq!(0, stats.get_num_fast_retrans());
    assert_eq!(0, stats.get_num_t3timeouts());
    assert_eq!(1, stats.get_num_forward_tsns());
    Ok(())
}

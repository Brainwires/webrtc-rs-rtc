//! RFC 6525: what an Outgoing SSN Reset Request leaves behind on the side that sent it.

use super::*;

fn response(rsn: u32, result: ReconfigResult) -> ChunkReconfig {
    ChunkReconfig {
        param_a: Some(Box::new(ParamReconfigResponse {
            reconfig_response_sequence_number: rsn,
            result,
            next_tsns: None,
        })),
        param_b: None,
    }
}

/// Writes two messages on stream 3, resets its outgoing direction and returns the RE-CONFIG
/// request's sequence number.
fn reset_after_two_messages(a: &mut Association, now: Instant) -> Result<u32> {
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(3, ppi)?;
    stream.write_sctp(now, &Bytes::from_static(b"one"), ppi)?;
    stream.write_sctp(now, &Bytes::from_static(b"two"), ppi)?;
    stream.stop(now)?;
    let sent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(
        vec![0, 1],
        sent.iter()
            .map(|c| c.stream_sequence_number)
            .collect::<Vec<_>>()
    );
    assert_eq!(2, a.streams[&3].sequence_number);
    let rsn = *a
        .reconfigs
        .keys()
        .next()
        .expect("a RE-CONFIG request was sent");
    Ok(rsn)
}

/// RFC 6525 5.1.2: once the peer performed the reset, the stream sends from SSN 0 again,
/// which is what the peer now expects. It kept its old SSN, so the peer held every later
/// ordered message back waiting for SSN 0.
#[test]
fn a_performed_reset_restarts_the_outgoing_ssn() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let rsn = reset_after_two_messages(&mut a, now)?;

    a.handle_reconfig(&response(rsn, ReconfigResult::SuccessPerformed))?;
    assert!(a.reconfigs.is_empty());
    assert_eq!(0, a.streams[&3].sequence_number);

    // The next message on the stream carries SSN 0.
    let ppi = PayloadProtocolIdentifier::Binary;
    a.stream(3)?
        .write_sctp(now, &Bytes::from_static(b"three"), ppi)?;
    let sent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(
        vec![0],
        sent.iter()
            .map(|c| c.stream_sequence_number)
            .collect::<Vec<_>>()
    );
    Ok(())
}

/// A refused reset changes nothing: the peer still expects the old sequence.
#[test]
fn a_denied_reset_keeps_the_outgoing_ssn() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let rsn = reset_after_two_messages(&mut a, now)?;

    a.handle_reconfig(&response(rsn, ReconfigResult::Denied))?;
    assert!(a.reconfigs.is_empty());
    assert_eq!(2, a.streams[&3].sequence_number);
    Ok(())
}

/// "In progress" is not the outcome (RFC 6525 5.1.1): the request stays outstanding, so the
/// final response still finds it and still restarts the SSN.
#[test]
fn an_in_progress_reset_waits_for_its_final_response() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let rsn = reset_after_two_messages(&mut a, now)?;

    a.handle_reconfig(&response(rsn, ReconfigResult::InProgress))?;
    assert!(a.reconfigs.contains_key(&rsn), "still outstanding");
    assert!(a.timers.get(Timer::Reconfig).is_some(), "still timed");
    assert_eq!(2, a.streams[&3].sequence_number);

    a.handle_reconfig(&response(rsn, ReconfigResult::SuccessPerformed))?;
    assert!(a.reconfigs.is_empty());
    assert!(a.timers.get(Timer::Reconfig).is_none());
    assert_eq!(0, a.streams[&3].sequence_number);
    Ok(())
}

/// RFC 6525 section 5.2.7 H1: "If the timer was not running for the Re-configuration Request
/// Sequence Number, the processing of the Re-configuration Response Parameter is complete."
/// While the reset of stream 3 is outstanding, responses whose sequence number has no running
/// timer (the one after the outstanding request's, an earlier one, and one far away), each
/// of every result, change nothing: the request stays outstanding and timed, the stream keeps
/// its sequence numbers and its pending reset, and nothing is reported. The response for the
/// outstanding request still completes it.
#[test]
fn a_response_for_no_outstanding_request_changes_nothing() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let rsn = reset_after_two_messages(&mut a, now)?;
    assert!(
        a.timers.get(Timer::Reconfig).is_some(),
        "the request is timed"
    );
    assert!(a.streams[&3].outgoing_reset_pending);
    a.events.clear();

    for unknown in [
        rsn.wrapping_add(1),
        rsn.wrapping_sub(1),
        rsn.wrapping_add(0x8000_0000),
    ] {
        for result in [
            ReconfigResult::SuccessPerformed,
            ReconfigResult::SuccessNop,
            ReconfigResult::Denied,
            ReconfigResult::ErrorRequestAlreadyInProgress,
            ReconfigResult::InProgress,
        ] {
            a.handle_reconfig(&response(unknown, result))?;
            assert_eq!(
                a.reconfigs.keys().copied().collect::<Vec<_>>(),
                vec![rsn],
                "response {unknown} ({result:?}): the request stays outstanding"
            );
            assert!(
                a.timers.get(Timer::Reconfig).is_some(),
                "response {unknown} ({result:?}): the timer runs on"
            );
            assert!(
                a.reconfig_in_flight.is_some(),
                "response {unknown} ({result:?}): the request is still in flight"
            );
            assert!(
                !a.restart_reconfig_timer && !a.reconfig_in_progress,
                "response {unknown} ({result:?}): not taken as the request's in-progress answer"
            );
            assert_eq!(2, a.streams[&3].sequence_number, "response {unknown}");
            assert!(a.streams[&3].outgoing_reset_pending, "response {unknown}");
            assert!(
                a.events.is_empty(),
                "response {unknown} ({result:?}): nothing reported: {:?}",
                a.events
            );
        }
    }

    a.handle_reconfig(&response(rsn, ReconfigResult::SuccessPerformed))?;
    assert!(a.reconfigs.is_empty());
    assert!(a.timers.get(Timer::Reconfig).is_none());
    assert_eq!(0, a.streams[&3].sequence_number);
    Ok(())
}

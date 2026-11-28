// Browser <-> rtci interop. Each test opens a page on a local origin (served by
// Playwright, a secure context), loads peer.js and drives a session with
// examples/interop-peer at RTC_INTEROP_WS.
import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { naBrowser, naEnv, skipUnlessCodec } from "./na.mjs";
import { fixtureExists, recordDescriptions } from "./common.mjs";

recordDescriptions();

const WS = process.env.RTC_INTEROP_WS || "ws://127.0.0.1:8080";
const PEER_JS = readFileSync(new URL("./peer.js", import.meta.url), "utf8");

test.beforeEach(async ({ page }) => {
  page.on("console", (m) => {
    if (m.type() === "error") console.log(`[${test.info().project.name}] console: ${m.text()}`);
  });
  await page.route("http://localhost/**", (route) =>
    route.fulfill({ contentType: "text/html", body: "<!doctype html><title>interop</title><body></body>" }),
  );
  await page.goto("http://localhost/index.html");
  await page.addScriptTag({ content: PEER_JS });
});

// ---- data channels ----

for (const [name, init, count, size, exact] of [
  ["data channel ordered", { ordered: true }, 200, 0, true],
  ["data channel unordered", { ordered: false }, 200, 0, false],
  ["data channel unreliable (maxRetransmits 0)", { ordered: false, maxRetransmits: 0 }, 200, 0, false],
  ["data channel 64 KiB binary messages", { ordered: true }, 20, 65536, true],
]) {
  test(name, async ({ page }) => {
    const r = await page.evaluate(
      async ([ws, init, count, size]) => {
        const s = await Interop.open(ws, {});
        const dc = s.pc.createDataChannel("interop", init);
        await s.negotiate();
        await s.connected();
        const e = await Interop.echo(dc, count, size);
        await e.wait(count, 20000);
        const got = e.got.map((m) => (typeof m === "string" ? m : new DataView(m.buffer).getUint32(0)));
        const sizes = e.got.map((m) => (typeof m === "string" ? m.length : m.length));
        s.close();
        return { got, sizes };
      },
      [WS, init, count, size],
    );
    const want = Array.from({ length: count }, (_, i) => (size ? i : `msg-${i}`));
    if (exact) expect(r.got).toEqual(want);
    else expect([...r.got].sort()).toEqual([...want].sort());
    if (size) expect(new Set(r.sizes)).toEqual(new Set([size]));
  });
}

test("data channel negotiated (id 5)", async ({ page }) => {
  const got = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { negotiated: [{ label: "neg", id: 5, ordered: true }] });
    const dc = s.pc.createDataChannel("neg", { negotiated: true, id: 5 });
    // A negotiated channel alone does not make the offer carry an SCTP section; an in-band
    // one does, so the association exists for the pre-negotiated stream.
    s.pc.createDataChannel("carrier");
    await s.negotiate();
    await s.connected();
    const e = await Interop.echo(dc, 50);
    await e.wait(50, 15000);
    s.close();
    return e.got;
  }, WS);
  expect(got).toEqual(Array.from({ length: 50 }, (_, i) => `msg-${i}`));
});

test("renegotiation: the browser adds a channel", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, {});
    const a = s.pc.createDataChannel("first");
    await s.negotiate();
    await s.connected();
    const e1 = await Interop.echo(a, 10);
    await e1.wait(10, 10000);
    const b = s.pc.createDataChannel("second");
    // A second channel needs no new offer once SCTP is up; renegotiate anyway (W3C allows
    // it), and the transport must survive the new offer/answer.
    await s.negotiate();
    const e2 = await Interop.echo(b, 10);
    await e2.wait(10, 10000);
    s.close();
    return [e1.got.length, e2.got.length, s.errors];
  }, WS);
  expect(r).toEqual([10, 10, []]);
});

test("renegotiation: Rust offers a new channel", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, {});
    s.pc.createDataChannel("first");
    await s.negotiate();
    await s.connected();
    const got = new Promise((res) => {
      s.pc.ondatachannel = (e) => {
        e.channel.onmessage = (m) => res([e.channel.label, m.data]);
      };
    });
    s.send({ type: "request-offer" });
    const result = await Promise.race([got, Interop.sleep(15000).then(() => "timeout")]);
    s.close();
    return { result, offers: s.remoteOffers, errors: s.errors };
  }, WS);
  expect(r.errors).toEqual([]);
  expect(r.offers).toBe(1);
  expect(r.result).toEqual(["from-rust", "hello-from-rust"]);
});

test("ICE restart keeps the data channel", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, {});
    const dc = s.pc.createDataChannel("restart");
    await s.negotiate();
    await s.connected();
    const before = (await Interop.transport(s.pc))?.selectedCandidatePairChanges;
    const ufrag = s.pc.localDescription.sdp.match(/a=ice-ufrag:(\S+)/)[1];
    s.pc.restartIce();
    await s.negotiate();
    const ufrag2 = s.pc.localDescription.sdp.match(/a=ice-ufrag:(\S+)/)[1];
    await Interop.sleep(2000);
    await s.connected();
    const e = await Interop.echo(dc, 20);
    await e.wait(20, 15000);
    s.close();
    return { changed: ufrag !== ufrag2, echoed: e.got.length, errors: s.errors, before };
  }, WS);
  expect(r.errors).toEqual([]);
  expect(r.changed).toBe(true);
  expect(r.echoed).toBe(20);
});

test("DTLS and SRTP are negotiated", async ({ page }) => {
  const t = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { media: "reflect", video: "VP8" });
    const tr = s.pc.addTransceiver(Interop.canvasStream().getVideoTracks()[0], { direction: "sendrecv" });
    Interop.prefer(tr, "video", "video/VP8");
    await s.negotiate();
    await s.connected();
    await Interop.sleep(1000);
    const t = await Interop.transport(s.pc);
    s.close();
    return t;
  }, WS);
  expect(t.dtlsState).toBe("connected");
  // Which version, suite and SRTP profile each browser cell settled on, for the train's log:
  // the engine offers AEAD_AES_256_GCM first and the TLS 1.3 suites before the 1.2 ones.
  console.log(
    `[${test.info().project.name}] negotiated tlsVersion=${t.tlsVersion} dtlsCipher=${t.dtlsCipher} srtpCipher=${t.srtpCipher}`,
  );
  // Chromium and Firefox report the negotiated suites; WebKit may not fill them in.
  if (t.dtlsCipher !== undefined) expect(t.dtlsCipher).toMatch(/AES_128_GCM|AES_256_GCM|CHACHA20/);
  if (t.srtpCipher !== undefined) expect(t.srtpCipher).toMatch(/AES|AEAD/);
});

// ---- media: the browser sends, Rust reflects ----

// H.265 and AV1 too: a browser without the encoder is na-browser by its own
// RTCRtpSender.getCapabilities.
for (const codec of ["VP8", "VP9", "H264", "H265", "AV1"]) {
  test(`reflect video ${codec}`, async ({ page }) => {
    await skipUnlessCodec(page, "video", `video/${codec}`, "sender");
    const r = await page.evaluate(
      async ([ws, codec]) => {
        const s = await Interop.open(ws, { media: "reflect", video: codec });
        const tr = s.pc.addTransceiver(Interop.canvasStream().getVideoTracks()[0], { direction: "sendrecv" });
        Interop.prefer(tr, "video", `video/${codec}`);
        s.pc.ontrack = (e) => Interop.sink(new MediaStream([e.track]));
        await s.negotiate();
        await s.connected();
        // 15 frames: headless WebKit's canvas capture runs at a few frames per second.
        const rtp = await Interop.until(async () => {
          const r = await Interop.inbound(s.pc, "video");
          return r && r.framesDecoded > 15 && r;
        }, 25000, "15 decoded frames").catch(async (e) => ({ error: String(e), last: await Interop.inbound(s.pc, "video") }));
        const report = await s.report();
        // What Rust received on a payload type the browser's offer does not have: a format the
        // answer added (RFC 9429 section 5.3.1) that the browser switched to (RFC 3264 section 7
        // lets it), which Rust cannot reflect (its sender may only use the offer's formats, RFC
        // 3264 section 6.1), or one the answer lacks too (a browser defect). WebKit did this in
        // train-36 round 10d (test-env 46081695534): VP8 on 96 offered, VP9 on 98 sent, Rust
        // reflected 7 VP8 packets and then only RTX probe padding, the cell timed out.
        const offPt = Interop.receivedOutside(report, s.pc.localDescription.sdp);
        const notInAnswer = Interop.receivedOutside(report, s.pc.remoteDescription.sdp);
        const answerVideo = Interop.codecLines(s.pc.remoteDescription.sdp, "video");
        const sending = (await Interop.codecView(s.pc)).sending;
        s.close();
        return { rtp, report, offPt, notInAnswer, answerVideo, sending };
      },
      [WS, codec],
    );
    console.log(
      `[${test.info().project.name}] reflect ${codec} payload types: answer ${JSON.stringify(r.answerVideo)}; ` +
        `received ${JSON.stringify(r.report?.wireRtp?.received)}; sent ${JSON.stringify(r.report?.wireRtp?.sent)}; ` +
        `the engine ignored ${r.report?.unnegotiatedPayloadTypeRtp} for an unnegotiated payload type; ` +
        `PLIs forwarded ${r.report?.plisForwarded}; the browser sending ${JSON.stringify(r.sending)}`,
    );
    expect(
      r.offPt,
      `the browser sent media on a payload type its offer does not have (${r.notInAnswer.length ? "nor the answer, RFC 3264 section 7" : "a format the answer added, RFC 9429 section 5.3.1, which Rust cannot reflect"}): ${JSON.stringify({ offPt: r.offPt, answer: r.answerVideo, received: r.report?.wireRtp?.received, sent: r.report?.wireRtp?.sent, sending: r.sending })}`,
    ).toEqual([]);
    expect(r.rtp.error, JSON.stringify(r)).toBeUndefined();
    expect(r.rtp.mimeType.toLowerCase()).toBe(`video/${codec}`.toLowerCase());
  });
}

// ---- the video pipeline: the browser sends, rtci-video assembles, times and decodes ----
// interop-peer's `pipeline` scenario runs the browser's video through rtci-video's receive
// pipeline (frame assembly, reference finding, jitter buffer, PLI) and its pure-Rust decoder:
// vp8-decoder for VP8, rav1d for AV1 (docs/video-pipeline.md, phase 2). The freezes and the
// longest interval it measured are recorded as the `video-pipeline` annotation, not asserted:
// headless canvas capture runs at a browser-dependent frame rate.
for (const codec of ["VP8", "AV1"]) {
  test(`pipeline receive ${codec}`, async ({ page }) => {
    await skipUnlessCodec(page, "video", `video/${codec}`, "sender");
    const r = await page.evaluate(
      async ([ws, codec]) => {
        const s = await Interop.open(ws, { media: "pipeline", video: codec });
        const tr = s.pc.addTransceiver(Interop.canvasStream(320, 240).getVideoTracks()[0], { direction: "sendonly" });
        Interop.prefer(tr, "video", `video/${codec}`);
        await s.negotiate();
        await s.connected();
        const report = await Interop.until(async () => {
          const rep = await s.report();
          const st = rep.pipeline && rep.pipeline.streams && rep.pipeline.streams[0];
          return st && st.framesDecoded >= 15 && rep;
        }, 25000, "15 pictures decoded by rtci-video").catch(async (e) => ({ error: String(e), last: await s.report() }));
        s.close();
        return report;
      },
      [WS, codec],
    );
    expect(r.error, JSON.stringify(r.last && r.last.pipeline)).toBeUndefined();
    const p = r.pipeline;
    test.info().annotations.push({ type: "video-pipeline", description: JSON.stringify(p) });
    expect(p.unsupported).toBe(0);
    expect(p.decoderErrors).toBe(0);
    expect(p.decoder).toBe(codec === "VP8" ? "vp8-decoder" : "rav1d");
    // The browser may scale down under load, never up, and keeps the aspect ratio.
    expect(p.width).toBeGreaterThan(0);
    expect(p.width).toBeLessThanOrEqual(320);
    expect(p.height * 4).toBe(p.width * 3);
  });
}

// The wire payload types both ways (interop-peer's `wireRtp`, counted from the SRTP header
// before the engine takes RED apart) are recorded as the `wire-payload-types` annotation of
// the result. Chromium and WebKit offer RED (RFC 2198) after Opus and the engine's answer keeps
// that order; RFC 3264 6.1 has each side send its peer's preferred format and libwebrtc sends
// RED only when it precedes the codec it protects, so Opus, not RED, crosses the wire both
// ways.
test("reflect audio Opus", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { media: "reflect", audio: true });
    s.pc.addTransceiver(Interop.audioStream().getAudioTracks()[0], { direction: "sendrecv" });
    s.pc.ontrack = (e) => Interop.sink(new MediaStream([e.track]));
    await s.negotiate();
    await s.connected();
    const rtp = await Interop.until(async () => {
      const r = await Interop.inbound(s.pc, "audio");
      return r && r.packetsReceived > 100 && r;
    }, 20000, "100 audio packets").catch(async (e) => ({ error: String(e), last: await Interop.inbound(s.pc, "audio") }));
    const report = await s.report().catch((e) => ({ error: String(e) }));
    const payloadTypes = (sdp) => {
      const section = sdp.split(/\r?\nm=/).find((m) => /^(m=)?audio /.test(m)) || "";
      const pt = (name) => (section.match(new RegExp(`a=rtpmap:(\\d+) ${name}/`, "i")) || [])[1];
      return { opus: pt("opus"), red: pt("red"), order: (section.match(/^(?:m=)?audio \S+ \S+ (.*)/) || [])[1] };
    };
    const offer = payloadTypes(s.pc.localDescription.sdp);
    const answer = payloadTypes(s.pc.remoteDescription.sdp);
    s.close();
    return { ...rtp, wire: report.wireRtp, offer, answer };
  }, WS);
  test.info().annotations.push({
    type: "wire-payload-types",
    description: JSON.stringify({ wire: r.wire, offer: r.offer, answer: r.answer }),
  });
  expect(r.error, JSON.stringify(r)).toBeUndefined();
  expect(r.mimeType.toLowerCase()).toBe("audio/opus");
  expect(r.wire, JSON.stringify(r)).toBeTruthy();
  // The browser sends with the answer's numbering (RFC 3264 5.1), the engine with the offer's.
  const opusIn = Number(r.answer.opus);
  const opusOut = Number(r.offer.opus);
  expect(Object.keys(r.wire.received).map(Number), JSON.stringify(r)).toEqual([opusIn]);
  expect(Object.keys(r.wire.sent).map(Number), JSON.stringify(r)).toEqual([opusOut]);
});

// The engine sends transport-wide congestion control feedback only for a stream whose section
// negotiated `a=rtcp-fb:... transport-cc` (draft-holmer-rmcat-transport-wide-cc-extensions
// section 2.3), not on the header extension alone: every browser's video offer must carry
// both, and the Rust answer must keep both, or the browser's sender gets no feedback.
test("transport-cc: the browser's video offer negotiates it and Rust keeps it", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { media: "reflect", video: "VP8" });
    const tr = s.pc.addTransceiver(Interop.canvasStream().getVideoTracks()[0], { direction: "sendrecv" });
    Interop.prefer(tr, "video", "video/VP8");
    await s.negotiate();
    const section = (sdp) => (sdp.split(/\r?\nm=/).find((m) => /^video /.test(m) || /^m=video /.test(m)) || "");
    const feedback = (sdp) => /a=rtcp-fb:(\d+|\*) transport-cc/.test(section(sdp));
    const extension = (sdp) => /a=extmap:\d+(\/\w+)? http:\/\/www\.ietf\.org\/id\/draft-holmer-rmcat-transport-wide-cc-extensions-01/.test(section(sdp));
    const offer = s.pc.localDescription.sdp;
    const answer = s.pc.remoteDescription.sdp;
    s.close();
    return {
      offered: { feedback: feedback(offer), extension: extension(offer) },
      answered: { feedback: feedback(answer), extension: extension(answer) },
      offer: section(offer),
      answer: section(answer),
    };
  }, WS);
  expect(r.offered, JSON.stringify(r)).toEqual({ feedback: true, extension: true });
  expect(r.answered, JSON.stringify(r)).toEqual({ feedback: true, extension: true });
});

// ---- media: Rust sends GStreamer-encoded files, the browser decodes ----

// [title, codec, kind, mime, fixture]: the fixture is the file interop-peer streams (entry.sh
// makes them); the multi-slice H.264 and multi-packet Ogg ones check the readers' framing end to
// end with the browser's decoder as the judge.
for (const [title, codec, kind, mime, fixture] of [
  ["VP8", "VP8", "video", "video/VP8", "vp8.ivf"],
  ["VP9", "VP9", "video", "video/VP9", "vp9.ivf"],
  ["H264", "H264", "video", "video/H264", "h264.h264"],
  ["H265", "H265", "video", "video/H265", "h265.h265"],
  ["AV1", "AV1", "video", "video/AV1", "av1.ivf"],
  ["OPUS", "OPUS", "audio", "audio/opus", "opus.ogg"],
  ["H264 with four slices per picture", "H264", "video", "video/H264", "h264-slices.h264"],
  ["OPUS from multi-packet Ogg pages", "OPUS", "audio", "audio/opus", "opus-multi.ogg"],
]) {
  test(`receive ${title} from Rust (GStreamer fixture)`, async ({ page }) => {
    await skipUnlessCodec(page, kind, mime, "receiver");
    naEnv(
      !fixtureExists(fixture),
      `the test image's GStreamer could not encode the ${codec} fixture ${fixture}`,
      `entry.sh's fixture log (fixture-${codec.toLowerCase()}.log in the artifacts)`,
    );
    const r = await page.evaluate(
      async ([ws, codec, kind, mime, fixture]) => {
        const sc = kind === "video"
          ? { media: "send", video: codec, fixture: { video: fixture } }
          : { media: "send", audio: true, fixture: { audio: fixture } };
        const s = await Interop.open(ws, sc);
        const tr = s.pc.addTransceiver(kind, { direction: "recvonly" });
        if (kind === "video") Interop.prefer(tr, "video", mime);
        s.pc.ontrack = (e) => Interop.sink(new MediaStream([e.track]));
        await s.negotiate();
        await s.connected();
        const rtp = await Interop.until(async () => {
          const r = await Interop.inbound(s.pc, kind);
          return r && (kind === "video" ? r.framesDecoded > 30 : r.packetsReceived > 100) && r;
        }, 25000, "decoded media").catch(async (e) => ({ error: String(e), last: await Interop.inbound(s.pc, kind) }));
        const report = await s.report();
        const after = await Interop.inbound(s.pc, kind);
        s.close();
        return { rtp, report, after };
      },
      [WS, codec, kind, mime, fixture],
    );
    expect(r.rtp.error, JSON.stringify(r)).toBeUndefined();
    expect(r.rtp.mimeType.toLowerCase()).toBe(mime.toLowerCase());
    if (kind === "audio") {
      // Every Opus packet is one RTP packet (RFC 7587 4.2): what Rust sent is what arrived,
      // give or take the ones in flight.
      const sent = r.report.sent.find((x) => x.mime.toLowerCase() === "audio/opus")?.frames || 0;
      expect(Math.abs(sent - (r.after?.packetsReceived || 0)), JSON.stringify(r)).toBeLessThanOrEqual(25);
      // A payload that is not one Opus packet (a whole page, say) does not decode, and the
      // browser conceals it; a healthy stream conceals little (webrtc-stats concealedSamples).
      const a = r.after || {};
      if (a.concealedSamples !== undefined && a.totalSamplesReceived > 0) {
        expect(a.concealedSamples / a.totalSamplesReceived, JSON.stringify(a)).toBeLessThan(0.2);
      }
    }
  });
}

// ---- simulcast ----

test("simulcast: three RIDs reach Rust", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const s = await Interop.open(ws, { media: "count" });
    // libwebrtc sends as many simulcast layers as the input resolution allows (one at
    // 320x240, three from 960x540); the canvas is 1280x720. Each layer's cap keeps the total
    // within the starting bandwidth estimate.
    const track = Interop.canvasStream(1280, 720).getVideoTracks()[0];
    const tr = s.pc.addTransceiver(track, {
      direction: "sendonly",
      sendEncodings: [
        { rid: "q", scaleResolutionDownBy: 4.0, maxBitrate: 100000 },
        { rid: "h", scaleResolutionDownBy: 2.0, maxBitrate: 200000 },
        { rid: "f", maxBitrate: 400000 },
      ],
    });
    Interop.prefer(tr, "video", "video/VP8");
    // What the browser kept: webrtc-pc 5.1 addTransceiver lets a user agent drop the
    // encodings past the number it supports, and getParameters() then shows the rest.
    const params = tr.sender.getParameters();
    const acceptedRids = (params.encodings || []).map((e) => e.rid).filter(Boolean);
    // CPU adaptation lowers the input resolution, and a lower input carries fewer layers:
    // under a busy container that alone leaves only "q". Keep the resolution, drop frames.
    let degradation = "unsupported";
    try {
      params.degradationPreference = "maintain-resolution";
      await tr.sender.setParameters(params);
      degradation = tr.sender.getParameters().degradationPreference || "not reported";
    } catch (e) {
      degradation = `refused: ${e.name}`;
    }
    await s.negotiate();
    const offeredRids = [...s.pc.localDescription.sdp.matchAll(/^a=rid:(\S+) send/gm)].map((m) => m[1]);
    await s.connected();
    let report;
    await Interop.until(async () => {
      report = await s.report();
      const rids = new Set(Object.keys(report.rtp).filter((k) => report.rtp[k] > 20).map((k) => k.split(":")[1]));
      return ["q", "h", "f"].every((x) => rids.has(x));
    }, 25000, "packets on q, h and f").catch(() => {});
    // What the browser says it sent, per layer, and why it held a layer back.
    const sent = {};
    let availableOutgoingBitrate;
    (await s.pc.getStats()).forEach((x) => {
      if (x.type === "outbound-rtp" && x.kind === "video" && x.rid) {
        sent[x.rid] = {
          packets: x.packetsSent || 0,
          width: x.frameWidth,
          limit: x.qualityLimitationReason,
          encoder: x.encoderImplementation,
        };
      }
      if (x.type === "candidate-pair" && x.nominated && x.availableOutgoingBitrate !== undefined) {
        availableOutgoingBitrate = x.availableOutgoingBitrate;
      }
    });
    const offer = s.pc.localDescription.sdp;
    const answer = s.pc.remoteDescription.sdp;
    s.close();
    return { report, sent, acceptedRids, offeredRids, degradation, availableOutgoingBitrate, offer, answer };
  }, WS);
  naBrowser(
    r.acceptedRids.length < 3,
    `the browser kept ${r.acceptedRids.length} of 3 send encodings`,
    `RTCRtpSender.getParameters().encodings after addTransceiver with three sendEncodings: ${JSON.stringify(r.acceptedRids)}`,
  );
  naBrowser(
    r.offeredRids.length < 3,
    `the browser's own offer declares ${r.offeredRids.length} send RIDs`,
    `its offer's a=rid lines (RFC 8853 section 5): ${JSON.stringify(r.offeredRids)}`,
  );
  naBrowser(
    r.sent.q?.width > 1280 / 2,
    `the browser encodes layer q at ${r.sent.q?.width} px wide, not a quarter of the 1280 px input: ` +
      "its encoder does not do simulcast (one stream from the full frame, on the first encoding)",
    `outbound-rtp.frameWidth of rid "q" against its scaleResolutionDownBy 4 (webrtc-pc 5.2; ` +
      `W3C webrtc-stats 7.3): ${JSON.stringify(r.sent)}`,
  );
  const quiet = ["q", "h", "f"].filter((x) => (r.sent[x]?.packets || 0) <= 20);
  const cpuLimited = Object.values(r.sent).some((v) => v.limit === "cpu");
  naEnv(
    quiet.length > 0 && cpuLimited,
    `the browser held back layer(s) ${quiet.join(",")} for lack of CPU in the test container ` +
      `(degradationPreference: ${r.degradation})`,
    `outbound-rtp.qualityLimitationReason = "cpu" (W3C webrtc-stats 7.3): ${JSON.stringify(r.sent)}`,
  );
  // Declared, accepted, and not CPU-starved: the browser must send all three, and every one
  // must reach Rust. A "bandwidth" limit here means our congestion feedback starved it.
  expect(
    quiet,
    `layers the browser sent 20 packets or fewer on: ${JSON.stringify(r.sent)}, ` +
      `availableOutgoingBitrate ${r.availableOutgoingBitrate}, degradationPreference ${r.degradation}` +
      `\noffer:\n${r.offer}\nanswer:\n${r.answer}`,
  ).toEqual([]);
  const rids = Object.keys(r.report.rtp).filter((k) => r.report.rtp[k] > 20).map((k) => k.split(":")[1]);
  expect(new Set(rids), JSON.stringify(r)).toEqual(new Set(["q", "h", "f"]));
});

// ---- encoded transforms (an SFrame-style end-to-end transform) ----

test("encoded transform: Rust forwards transformed VP8 untouched", async ({ page }) => {
  const r = await page.evaluate(async (ws) => {
    const insertable = !!RTCRtpSender.prototype.createEncodedStreams;
    if (!insertable && !window.RTCRtpScriptTransform) return { unsupported: true };
    const s = await Interop.open(ws, { media: "reflect", video: "VP8" }, { insertableStreams: insertable });
    const tr = s.pc.addTransceiver(Interop.canvasStream().getVideoTracks()[0], { direction: "sendrecv" });
    Interop.prefer(tr, "video", "video/VP8");
    const api = Interop.attachTransform(tr.sender);
    s.pc.ontrack = (e) => {
      Interop.attachTransform(e.receiver);
      Interop.sink(new MediaStream([e.track]));
    };
    await s.negotiate();
    await s.connected();
    const rtp = await Interop.until(async () => {
      const r = await Interop.inbound(s.pc, "video");
      return r && r.framesDecoded > 30 && r;
    }, 25000, "30 decoded frames through the transform").catch(async (e) => ({ error: String(e), last: await Interop.inbound(s.pc, "video") }));
    s.close();
    return { api, rtp };
  }, WS);
  naBrowser(
    r.unsupported,
    "this browser has no encoded transform API",
    "RTCRtpSender.prototype.createEncodedStreams and window.RTCRtpScriptTransform are both undefined",
  );
  expect(r.rtp.error, JSON.stringify(r)).toBeUndefined();
});

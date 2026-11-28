#!/usr/bin/env python3
"""RFC 9429 section 5.11 evidence (audit row RFC9429-5.11-6): the a=rtcp-fb lines in answers
written by browsers and by the interop peers that the offer lacked (per payload type, wildcard
followed, renumbered formats matched by encoding name and clock rate).

Usage: scripts/answer-feedback-evidence.py <repo> <test-env artifact dir>...

The artifact directories are downloaded `test-env` artifacts (`browser-sdp/`, `peers/*/`);
the repository's tests/fixtures/browser-sdp is always read.

Exact pairs: interop peers' result.json `descriptions` ([direction, type, sdp]): every `sent`
answer against the `received` offer before it (the offer rtci wrote).
Browser answers (browser-sdp/*-answer.sdp, which the harness records without the offer): against
the union of every rtci offer seen (peer cells' received offers, tests/fixtures/engine-offers),
per codec (encoding name / clock rate): a line outside it is extra for any rtci offer.
"""
import glob, json, os, sys
from collections import defaultdict


def sections(sdp):
    out, cur = [], None
    for raw in sdp.replace("\r\n", "\n").split("\n"):
        line = raw.rstrip()
        if line.startswith("m="):
            parts = line.split()
            cur = {"media": parts[0][2:], "port": parts[1], "pts": parts[3:], "rtpmap": {}, "fb": defaultdict(set)}
            out.append(cur)
        elif cur is not None and line.startswith("a=rtpmap:"):
            pt, enc = line[9:].split(" ", 1)
            name = enc.split("/")
            cur["rtpmap"][pt] = (name[0].lower(), name[1] if len(name) > 1 else "")
        elif cur is not None and line.startswith("a=rtcp-fb:"):
            pt, _, val = line[10:].partition(" ")
            val = " ".join(val.split())
            if val.startswith("trr-int"):
                val = "trr-int"
            cur["fb"][pt].add(val)
    return out


def codec(sec, pt):
    return sec["rtpmap"].get(pt, ("static-%s" % pt, ""))


def offered_for(osec, asec, pt):
    """Feedback the offer section has for the answer's format pt (same codec)."""
    c = codec(asec, pt)
    have = set(osec["fb"].get("*", set()))
    for opt in osec["pts"]:
        if codec(osec, opt) == c:
            have |= osec["fb"].get(opt, set())
    return have


def extras_pair(offer, answer):
    found = []
    for i, (o, a) in enumerate(zip(sections(offer), sections(answer))):
        if a["port"] == "0":
            continue
        for pt, vals in a["fb"].items():
            pts = a["pts"] if pt == "*" else [pt]
            for v in sorted(vals):
                for p in pts:
                    if v not in offered_for(o, a, p):
                        found.append("m%d %s %s (for %s/%s)" % (i, pt, v, *codec(a, p)))
                        break
    return found


def main():
    repo, arts = sys.argv[1], sys.argv[2:]
    union = defaultdict(set)  # (media, codec) -> feedback rtci offered
    wild = defaultdict(set)

    def learn(offer):
        for s in sections(offer):
            for pt in s["pts"]:
                union[(s["media"], codec(s, pt))] |= s["fb"].get(pt, set())
            wild[s["media"]] |= s["fb"].get("*", set())

    rows = []
    pairs = 0
    seen_peer_answers = set()
    for art in arts:
        for f in sorted(glob.glob(os.path.join(art, "**/peers/*/*.result.json"), recursive=True)):
            peer = f.split(os.sep)[-2]
            try:
                d = json.load(open(f))
            except Exception:
                continue
            last_offer = None
            for direction, typ, sdp in d.get("descriptions") or []:
                if direction == "received" and typ == "offer":
                    last_offer = sdp
                    learn(sdp)
                elif direction == "sent" and typ == "answer" and last_offer:
                    key = (peer, os.path.basename(f))
                    pairs += 1
                    if "m=audio" not in sdp and "m=video" not in sdp:
                        continue
                    seen_peer_answers.add(key)
                    rows.append((peer + " " + str(d.get("version")), os.path.basename(f), "exact pair", extras_pair(last_offer, sdp)))
    for f in glob.glob(os.path.join(repo, "tests/fixtures/engine-offers/*.sdp")):
        learn(open(f).read())
    # From the source, for offers no artifact records (the harness keeps only what a browser
    # sent): media_engine.rs register_default_codecs gives every video format goog-remb, ccm
    # fir, nack, nack pli (AV1 also ccm lrr), register_default_interceptors adds transport-cc
    # and (configure_receiver_reference_time) rrtr to every video format; the Chrome profile's
    # rtcp.receiver-reference-time-on-audio adds rrtr to every audio format and
    # fec.video-red-ulpfec offers red / ulpfec (+ rtx), which then carry the video kind's
    # registered feedback (MediaEngine::register_feedback: every codec of the kind).
    video_fb = {"goog-remb", "ccm fir", "nack", "nack pli", "transport-cc", "rrtr", "ccm tmmbr"}
    for c in ["vp8", "vp9", "h264", "h265", "av1", "red", "ulpfec", "rtx"]:
        union[("video", (c, "90000"))] |= video_fb | ({"ccm lrr"} if c == "av1" else set())
    for k in list(union):
        if k[0] == "audio":
            union[k].add("rrtr")

    # Browser answers and recorded webrtc-rs answers: against the union.
    answers = set()
    for d in [os.path.join(repo, "tests/fixtures/browser-sdp")] + [p for a in arts for p in glob.glob(os.path.join(a, "**/browser-sdp"), recursive=True)]:
        for f in glob.glob(os.path.join(d, "*-answer.sdp")):
            answers.add((os.path.basename(f), f))
    by_name = {}
    for name, f in sorted(answers):
        by_name.setdefault(name, []).append(f)
    browser_media = 0
    for name, fs in sorted(by_name.items()):
        for f in fs:
            sdp = open(f).read()
            secs = sections(sdp)
            if not any(s["media"] in ("audio", "video") and s["port"] != "0" for s in secs):
                continue
            browser_media += 1
            found = []
            for i, s in enumerate(secs):
                if s["port"] == "0" or s["media"] not in ("audio", "video"):
                    continue
                for pt, vals in s["fb"].items():
                    pts = s["pts"] if pt == "*" else [pt]
                    for v in sorted(vals):
                        for p in pts:
                            if v not in union[(s["media"], codec(s, p))] | wild[s["media"]]:
                                found.append("m%d %s %s (for %s/%s)" % (i, pt, v, *codec(s, p)))
                                break
            rows.append((name.split("--")[0], name, "vs union of rtci offers", sorted(set(found))))

    writers = defaultdict(lambda: [0, 0, set()])
    for w, n, how, found in rows:
        k = (w, how)
        writers[k][0] += 1
        if found:
            writers[k][1] += 1
            writers[k][2] |= set(x.split(" (")[0].split(" ", 1)[1] for x in found)
    print("| Writer | Comparison | Answers with media | With un-offered a=rtcp-fb | Lines |")
    print("|---|---|---|---|---|")
    for (w, how), (n, bad, lines) in sorted(writers.items()):
        print("| %s | %s | %d | %d | %s |" % (w, how, n, bad, ", ".join(sorted(lines)) or "-"))
    print()
    print("peer answer pairs (all, data-only included):", pairs)
    print("union of rtci-offered feedback per codec:")
    for k in sorted(union):
        print("  ", k, sorted(union[k] | wild[k[0]]))
    for w, n, how, found in rows:
        if found:
            print("EXTRA", w, n, how, found)


main()

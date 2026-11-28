//! `a=rid` (RFC 8851) and `a=simulcast` (RFC 8853) of a media section: which lines of a
//! received description are usable, what an answer says about them, and what an answer leaves
//! of the encodings a sender offered.

use super::{SDP_ATTRIBUTE_RID, SDP_ATTRIBUTE_SIMULCAST};
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::RTCRtpRidRestrictions;
use sdp::attribute::{Rid, RidDirection, RidIdGrammar, Simulcast, SimulcastId};
use sdp::description::media::MediaDescription;
use std::collections::{HashMap, HashSet};

/// The restrictions of RFC 8851 section 5, the ones this endpoint understands: it hands them
/// to the application, whose encoder they bind (`RTCRtpCodingParameters::rid_restrictions`).
const INTEGER_RESTRICTIONS: [&str; 6] = [
    "max-width",
    "max-height",
    "max-fps",
    "max-fs",
    "max-br",
    "max-pps",
];
const MAX_BPP: &str = "max-bpp";
const DEPEND: &str = "depend";

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) enum SimulcastDirection {
    Send,
    Recv,
}

impl SimulcastDirection {
    pub(crate) fn reversed(self) -> Self {
        match self {
            SimulcastDirection::Send => SimulcastDirection::Recv,
            SimulcastDirection::Recv => SimulcastDirection::Send,
        }
    }
}

impl From<RidDirection> for SimulcastDirection {
    fn from(direction: RidDirection) -> Self {
        match direction {
            RidDirection::Send => SimulcastDirection::Send,
            RidDirection::Recv => SimulcastDirection::Recv,
        }
    }
}

impl From<SimulcastDirection> for RidDirection {
    fn from(direction: SimulcastDirection) -> Self {
        match direction {
            SimulcastDirection::Send => RidDirection::Send,
            SimulcastDirection::Recv => RidDirection::Recv,
        }
    }
}

/// One usable `a=rid` line of a media section, with what the section's `a=simulcast` line
/// says of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SimulcastRid {
    pub(crate) id: String,
    /// The direction as the description that carries the line states it.
    pub(crate) direction: SimulcastDirection,
    /// Whether the `a=simulcast` line lists the rid as a simulcast stream of that direction.
    pub(crate) simulcast: bool,
    /// The `~` of the `a=simulcast` line (RFC 8853 section 5.2: initially paused).
    pub(crate) paused: bool,
    /// The `pt=` list, without the payload types the m= line does not have. Empty when the
    /// line has no `pt=`.
    pub(crate) formats: Vec<u8>,
    /// Every other restriction, as written.
    pub(crate) restrictions: Vec<(String, Option<String>)>,
}

impl SimulcastRid {
    fn from_rid(rid: Rid) -> Self {
        Self {
            id: rid.id,
            direction: rid.direction.into(),
            simulcast: false,
            paused: false,
            formats: rid.formats,
            restrictions: rid.restrictions,
        }
    }

    fn restriction(&self, name: &str) -> Option<Option<&str>> {
        self.restrictions
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_deref())
    }

    fn depend(&self) -> Vec<&str> {
        match self.restriction(DEPEND) {
            Some(Some(list)) => list.split(',').collect(),
            _ => vec![],
        }
    }

    /// The `a=rid` value for this rid in `direction`, with `formats` as its `pt=` list.
    pub(crate) fn line(&self, direction: SimulcastDirection, formats: Vec<u8>) -> String {
        Rid {
            id: self.id.clone(),
            direction: direction.into(),
            formats,
            restrictions: self.restrictions.clone(),
        }
        .to_string()
    }

    /// The `a=rid` value with no restrictions: `<id> <direction>` (W3C webrtc-pc
    /// `createAnswer`, `SettingEngineBuilder::with_w3c_simulcast_answer`).
    pub(crate) fn bare_line(&self, direction: SimulcastDirection) -> String {
        self.line_without_restrictions(direction)
    }

    fn line_without_restrictions(&self, direction: SimulcastDirection) -> String {
        Rid {
            id: self.id.clone(),
            direction: direction.into(),
            formats: vec![],
            restrictions: vec![],
        }
        .to_string()
    }

    /// The restrictions as the application sees them. One this endpoint does not know (only
    /// a `send` line keeps such a one) is left out.
    pub(crate) fn to_restrictions(&self) -> RTCRtpRidRestrictions {
        let integer = |name: &str| self.restriction(name)??.parse::<u64>().ok();
        RTCRtpRidRestrictions {
            payload_types: self.formats.clone(),
            max_width: integer("max-width"),
            max_height: integer("max-height"),
            max_fps: integer("max-fps"),
            max_fs: integer("max-fs"),
            max_br: integer("max-br"),
            max_pps: integer("max-pps"),
            max_bpp: self
                .restriction(MAX_BPP)
                .flatten()
                .and_then(|v| v.parse().ok()),
            depend: self.depend().into_iter().map(str::to_owned).collect(),
        }
    }

    /// A rid of this endpoint's own, from an encoding's restrictions.
    pub(crate) fn from_restrictions(
        id: &str,
        direction: SimulcastDirection,
        restrictions: &RTCRtpRidRestrictions,
    ) -> Self {
        let mut written: Vec<(String, Option<String>)> = vec![];
        for (name, value) in [
            ("max-width", restrictions.max_width),
            ("max-height", restrictions.max_height),
            ("max-fps", restrictions.max_fps),
            ("max-fs", restrictions.max_fs),
            ("max-br", restrictions.max_br),
            ("max-pps", restrictions.max_pps),
        ] {
            if let Some(value) = value {
                written.push((name.to_owned(), Some(value.to_string())));
            }
        }
        if let Some(bpp) = restrictions
            .max_bpp
            .filter(|bpp| bpp.is_finite() && *bpp >= 0.0)
        {
            // float-param-val = 1*DIGIT "." 1*DIGIT
            written.push((MAX_BPP.to_owned(), Some(format!("{bpp:.4}"))));
        }
        if !restrictions.depend.is_empty() {
            written.push((DEPEND.to_owned(), Some(restrictions.depend.join(","))));
        }
        Self {
            id: id.to_owned(),
            direction,
            simulcast: false,
            paused: false,
            formats: restrictions.payload_types.clone(),
            restrictions: written,
        }
    }
}

/// Whether `value` is a value the restriction `name` can take: `None` for a restriction this
/// endpoint does not know.
fn understood(name: &str, value: Option<&str>) -> Option<bool> {
    if INTEGER_RESTRICTIONS.contains(&name) {
        // A limit of zero leaves nothing any codec could send.
        Some(value.is_some_and(|v| v.parse::<u64>().is_ok_and(|v| v > 0)))
    } else if name == MAX_BPP {
        Some(value.is_some_and(|v| v.parse::<f64>().is_ok_and(|v| v > 0.0)))
    } else if name == DEPEND {
        Some(value.is_some())
    } else {
        None
    }
}

/// What a media section says with `a=rid` and `a=simulcast`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SectionRids {
    /// The usable rids: the simulcast streams in the order of the `a=simulcast` line (RFC
    /// 8853 section 5.2: "a proposed order of preference"), then the rids the line does not
    /// name, in the order of their `a=rid` lines.
    pub(crate) rids: Vec<SimulcastRid>,
    /// More than one `a=simulcast` line: RFC 8853 section 5.3.2 has the answerer answer
    /// without simulcast.
    pub(crate) simulcast_lines: usize,
    /// The rid-ids of the `a=simulcast` line, usable or not (RFC 9429 section 5.8.3 wants
    /// each to have an `a=rid` line).
    pub(crate) referenced: Vec<String>,
    /// The rid-ids that have an `a=rid` line, usable or not.
    pub(crate) declared: HashSet<String>,
}

/// Reads the `a=rid` and `a=simulcast` lines of `media`.
///
/// RFC 8851 section 6.2.2, the steps an `a=rid`-aware answerer runs on each line, in order
/// (section 6.4 has the offerer treat an answer's lines alike):
/// 1. a line that is not well formed is discarded;
/// 2. a rid-id that occurs twice discards every line with it;
/// 3. a `pt=` loses the payload types the m= line does not list, and a line whose `pt=` is
///    then empty is discarded;
/// 4. a `recv` line with a restriction this endpoint does not support is discarded (a `send`
///    line may carry any: "the answerer does not need to understand every restriction
///    present in a 'send' line");
/// 5. a `depend` that names a rid-id the section does not have (or the line itself) discards
///    the line;
/// 6. a restriction no codec can meet (a limit of zero) discards the line.
///
/// RFC 8853 section 5.2: a simulcast stream is one of a `;`-separated list, given as
/// `,`-separated alternatives, of which the first usable one is taken (W3C webrtc-pc "set a
/// session description": "using only the first value if comma-separated alternatives
/// exist"); a rid-id whose `a=rid` line has the other direction is not used ("The direction
/// for the rid-id MUST be aligned with the direction specified for the corresponding RTP
/// stream identifier on the 'a=rid' line"), nor is one without a line.
/// RFC 8851 section 8: whether some size the section's `a=imageattr` lines allow for the
/// rid's formats (its `pt=` list, else every format of the m= line), in the rid's direction,
/// is within the rid's `max-width`, `max-height` and `max-fs`. A format no `a=imageattr`
/// line of that direction restricts (or `*`) admits any size.
fn admitted_by_imageattr(
    rid: &SimulcastRid,
    media: &MediaDescription,
    listed: &HashSet<u8>,
) -> bool {
    use sdp::attribute::{ImageAttrList, ImageAttrRange};
    let limits = rid.to_restrictions();
    if limits.max_width.is_none() && limits.max_height.is_none() && limits.max_fs.is_none() {
        return true;
    }
    let Ok(attributes) = media.imageattrs() else {
        return true;
    };
    let minimum = |range: &ImageAttrRange<u32>| -> u64 {
        u64::from(match range {
            ImageAttrRange::Value(v) => *v,
            ImageAttrRange::Range { min, .. } => *min,
            ImageAttrRange::List(values) => values.iter().copied().min().unwrap_or(0),
        })
    };
    let formats: Vec<u8> = if rid.formats.is_empty() {
        listed.iter().copied().collect()
    } else {
        rid.formats.clone()
    };
    formats.iter().any(|pt| {
        let sets = attributes
            .iter()
            .filter(|a| a.payload_type.is_none_or(|p| p == *pt))
            .filter_map(|a| match rid.direction {
                SimulcastDirection::Send => a.send.as_ref(),
                SimulcastDirection::Recv => a.recv.as_ref(),
            })
            .find_map(|list| match list {
                ImageAttrList::Sets(sets) => Some(sets),
                ImageAttrList::Any => None,
            });
        let Some(sets) = sets else {
            return true;
        };
        sets.iter().any(|set| {
            let (width, height) = (minimum(&set.x), minimum(&set.y));
            limits.max_width.is_none_or(|max| width <= max)
                && limits.max_height.is_none_or(|max| height <= max)
                && limits.max_fs.is_none_or(|max| width * height <= max)
        })
    })
}

///
/// Rid-ids are read with `rid_ids` (`SettingEngine::rid_id_grammar`): RFC 8851 section 10
/// as corrected by erratum 7132 by default, where a line whose rid-id has `-`, `_` or more
/// than 255 characters is a syntax error of step 1.
pub(crate) fn section_rids(media: &MediaDescription, rid_ids: RidIdGrammar) -> SectionRids {
    let listed: HashSet<u8> = media
        .media_name
        .formats
        .iter()
        .filter_map(|format| format.parse().ok())
        .collect();

    let mut section = SectionRids::default();
    let mut parsed: Vec<Rid> = vec![];
    let mut simulcast_value: Option<&str> = None;
    for attr in &media.attributes {
        if attr.key == SDP_ATTRIBUTE_RID {
            let Some(value) = attr.value.as_deref() else {
                continue;
            };
            if let Some(id) = value.split(' ').next() {
                section.declared.insert(id.to_owned());
            }
            // Step 1.
            match Rid::parse_with(value, rid_ids) {
                Ok(rid) => parsed.push(rid),
                Err(err) => log::warn!("a=rid:{value} is discarded: {err}"),
            }
        } else if attr.key == SDP_ATTRIBUTE_SIMULCAST {
            section.simulcast_lines += 1;
            simulcast_value = attr.value.as_deref();
        }
    }

    // Step 2.
    let mut occurrences: HashMap<&str, usize> = HashMap::new();
    for rid in &parsed {
        *occurrences.entry(rid.id.as_str()).or_default() += 1;
    }
    let duplicated: HashSet<String> = occurrences
        .into_iter()
        .filter(|(_, n)| *n > 1)
        .map(|(id, _)| id.to_owned())
        .collect();

    let mut rids: Vec<SimulcastRid> = vec![];
    for mut rid in parsed {
        if duplicated.contains(&rid.id) {
            continue;
        }
        // Step 3.
        if !rid.formats.is_empty() {
            rid.formats.retain(|pt| listed.contains(pt));
            if rid.formats.is_empty() {
                continue;
            }
        }
        // Steps 4 and 6.
        let receives = rid.direction == RidDirection::Recv;
        let usable =
            rid.restrictions
                .iter()
                .all(|(name, value)| match understood(name, value.as_deref()) {
                    Some(valid) => valid,
                    None => !receives,
                });
        if !usable {
            continue;
        }
        let rid = SimulcastRid::from_rid(rid);
        // Step 6 and RFC 8851 section 8: the line's restrictions "combined with other
        // restrictions on the media stream, are expected to result in a non-empty
        // intersection"; one whose limits no `a=imageattr` set of its formats admits ("if
        // image attributes are used to indicate that a PT has a minimum width of 640, then
        // specification of "max-width=320" ... is nonsensical") is discarded.
        if !admitted_by_imageattr(&rid, media, &listed) {
            log::warn!(
                "a=rid:{} is discarded: no a=imageattr set of its formats admits its limits \
                 (RFC 8851 section 8)",
                rid.id
            );
            continue;
        }
        rids.push(rid);
    }
    // Step 5, until no line is discarded any more: a line may depend on a discarded one.
    loop {
        let known: HashSet<(String, SimulcastDirection)> = rids
            .iter()
            .map(|rid| (rid.id.clone(), rid.direction))
            .collect();
        let before = rids.len();
        rids.retain(|rid| {
            rid.depend()
                .iter()
                .all(|id| *id != rid.id && known.contains(&((*id).to_owned(), rid.direction)))
        });
        if rids.len() == before {
            break;
        }
    }

    let simulcast = match (section.simulcast_lines, simulcast_value) {
        (1, Some(value)) => match Simulcast::parse_with(value, rid_ids) {
            Ok(simulcast) => Some(simulcast),
            Err(err) => {
                log::warn!("a=simulcast:{value} is ignored: {err}");
                None
            }
        },
        _ => None,
    };
    let Some(simulcast) = simulcast else {
        section.rids = rids;
        return section;
    };
    section.referenced = simulcast.rids().map(str::to_owned).collect();

    let index: HashMap<(String, SimulcastDirection), usize> = rids
        .iter()
        .enumerate()
        .map(|(i, rid)| ((rid.id.clone(), rid.direction), i))
        .collect();
    let mut order: Vec<usize> = vec![];
    let mut alternatives: HashSet<usize> = HashSet::new();
    let mut take = |streams: &[Vec<SimulcastId>], direction: SimulcastDirection| {
        for stream in streams {
            let mut chosen = false;
            for alternative in stream {
                let Some(&i) = index.get(&(alternative.rid.clone(), direction)) else {
                    continue;
                };
                if chosen || rids[i].simulcast {
                    // Another alternative of a stream that has one, or a rid-id listed twice.
                    if !rids[i].simulcast {
                        alternatives.insert(i);
                    }
                    continue;
                }
                rids[i].simulcast = true;
                rids[i].paused = alternative.paused;
                order.push(i);
                chosen = true;
            }
        }
    };
    if simulcast.recv_first {
        take(&simulcast.recv, SimulcastDirection::Recv);
        take(&simulcast.send, SimulcastDirection::Send);
    } else {
        take(&simulcast.send, SimulcastDirection::Send);
        take(&simulcast.recv, SimulcastDirection::Recv);
    }

    let listed: HashSet<usize> = order.iter().copied().collect();
    let rest = (0..rids.len()).filter(|i| !listed.contains(i) && !alternatives.contains(i));
    let positions: Vec<usize> = order.iter().copied().chain(rest).collect();
    let mut slots: Vec<Option<SimulcastRid>> = rids.into_iter().map(Some).collect();
    section.rids = positions
        .into_iter()
        .filter_map(|i| slots[i].take())
        .collect();
    section
}

/// The usable rids of `media`: see [`section_rids`].
pub(crate) fn get_rids(media: &MediaDescription, rid_ids: RidIdGrammar) -> Vec<SimulcastRid> {
    section_rids(media, rid_ids).rids
}

/// RFC 9429 section 5.8: "if any line is not well formed ... the entire session description
/// MUST be rejected". The error of the first `a=simulcast` line of `media` that is not: one
/// that does not parse, or names a rid-id twice (RFC 8853 section 5.2: "a single rid-id MUST
/// NOT occur more than once per 'a=simulcast' line"), or a direction twice.
pub(crate) fn malformed_simulcast_line(
    media: &MediaDescription,
    rid_ids: RidIdGrammar,
) -> Option<String> {
    media
        .attributes
        .iter()
        .filter(|attr| attr.key == SDP_ATTRIBUTE_SIMULCAST)
        .find_map(|attr| {
            let value = attr.value.as_deref().unwrap_or_default();
            Simulcast::parse_with(value, rid_ids)
                .err()
                .map(|err| format!("a=simulcast:{value}: {err}"))
        })
}

/// W3C webrtc-pc `createAnswer` (section 4.4.2): identically named rids of an `a=simulcast`
/// line are reduced to the first. The value with each rid-id after its first occurrence taken
/// out (with the stream it leaves empty); `None` when nothing is repeated.
pub(crate) fn without_repeated_rids(value: &str) -> Option<String> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut repeated = false;
    let mut parts: Vec<String> = vec![];
    let mut tokens = value.split_ascii_whitespace();
    while let Some(direction) = tokens.next() {
        let Some(list) = tokens.next() else {
            parts.push(direction.to_owned());
            break;
        };
        let streams: Vec<String> = list
            .split(';')
            .filter_map(|stream| {
                let alternatives: Vec<&str> = stream
                    .split(',')
                    .filter(|alternative| {
                        let id = alternative.trim_start_matches('~');
                        if seen.insert(id) {
                            true
                        } else {
                            repeated = true;
                            false
                        }
                    })
                    .collect();
                (!alternatives.is_empty()).then(|| alternatives.join(","))
            })
            .collect();
        parts.push(direction.to_owned());
        parts.push(streams.join(";"));
    }
    repeated.then(|| parts.join(" "))
}

/// RFC 9429 section 5.8.3: "All rid-ids referenced in an 'a=simulcast' line MUST exist as
/// 'a=rid' lines", or the description is refused. The first rid-id of `media` that has
/// none.
pub(crate) fn simulcast_rid_without_line(
    media: &MediaDescription,
    rid_ids: RidIdGrammar,
) -> Option<String> {
    let section = section_rids(media, rid_ids);
    section
        .referenced
        .into_iter()
        .find(|id| !section.declared.contains(id))
}

/// The format a payload type of `media` stands for: its `a=rtpmap` value (case-insensitive,
/// RFC 4855 section 3) and its `a=fmtp` value. A payload type without `a=rtpmap` is a static
/// one (RFC 3551 section 6), the format of its number.
fn format_of(media: &MediaDescription, pt: u8) -> (String, Option<String>) {
    let value = |key: &str| -> Option<String> {
        media.attributes.iter().find_map(|attr| {
            let value = attr.value.as_deref()?;
            let (number, rest) = value.split_once(' ')?;
            (attr.key == key && number.parse::<u8>().ok() == Some(pt)).then(|| rest.to_owned())
        })
    };
    let rtpmap = value("rtpmap").map_or_else(|| pt.to_string(), |v| v.to_ascii_lowercase());
    (rtpmap, value("fmtp"))
}

/// The `same_format` of [`answered_rid_is_valid`] for an answer section `answer` to the
/// offer section `offer`: whether the answer's payload type `pt` has the format of one of the
/// offered payload types `offered`.
pub(crate) fn same_format<'a>(
    offer: &'a MediaDescription,
    answer: &'a MediaDescription,
) -> impl Fn(u8, &[u8]) -> bool + 'a {
    move |pt, offered| {
        let answered = format_of(answer, pt);
        offered
            .iter()
            .any(|&offered_pt| format_of(offer, offered_pt) == answered)
    }
}

/// RFC 8851 section 6.4: whether the offerer keeps the `a=rid` line `answered`, given the
/// line `offered` it wrote with that rid-id.
///
/// - step 2: no restriction the offer did not have;
/// - step 3: a changed restriction is more restrictive (a lower limit; `depend` unchanged);
/// - step 4: no `pt=` when the offer had none;
/// - step 5: with a `pt=` on both, each of the answer's payload types is one of the offer's
///   by its format (`same_format` says whether the answer's payload type `pt` is the format
///   of one of the offered payload types).
pub(crate) fn answered_rid_is_valid(
    offered: &SimulcastRid,
    answered: &SimulcastRid,
    same_format: impl Fn(u8, &[u8]) -> bool,
) -> bool {
    if offered.direction != answered.direction.reversed() {
        return false;
    }
    if !answered.formats.is_empty()
        && (offered.formats.is_empty()
            || !answered
                .formats
                .iter()
                .all(|pt| same_format(*pt, &offered.formats)))
    {
        return false;
    }
    answered.restrictions.iter().all(|(name, value)| {
        let Some(offered_value) = offered.restriction(name) else {
            return false;
        };
        let (value, offered_value) = (value.as_deref(), offered_value);
        if value == offered_value {
            return true;
        }
        let (Some(value), Some(offered_value)) = (value, offered_value) else {
            return false;
        };
        if INTEGER_RESTRICTIONS.contains(&name.as_str()) {
            matches!(
                (value.parse::<u64>(), offered_value.parse::<u64>()),
                (Ok(v), Ok(o)) if v > 0 && v <= o
            )
        } else if name == MAX_BPP {
            matches!(
                (value.parse::<f64>(), offered_value.parse::<f64>()),
                (Ok(v), Ok(o)) if v > 0.0 && v <= o
            )
        } else {
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sdp::attribute::TypedAttribute;

    /// [`super::section_rids`] with the default (corrected) rid-id grammar.
    fn section_rids(media: &MediaDescription) -> SectionRids {
        super::section_rids(media, RidIdGrammar::Corrected)
    }

    /// [`super::simulcast_rid_without_line`] with the default (corrected) rid-id grammar.
    fn simulcast_rid_without_line(media: &MediaDescription) -> Option<String> {
        super::simulcast_rid_without_line(media, RidIdGrammar::Corrected)
    }

    fn video(formats: &[&str], lines: &[(&str, &str)]) -> MediaDescription {
        let mut media = MediaDescription::default();
        media.media_name.media = "video".to_owned();
        media.media_name.formats = formats.iter().map(|f| (*f).to_owned()).collect();
        for (key, value) in lines {
            media = media.with_value_attribute((*key).to_owned(), (*value).to_owned());
        }
        media
    }

    fn ids(section: &SectionRids) -> Vec<&str> {
        section.rids.iter().map(|rid| rid.id.as_str()).collect()
    }

    /// RFC 8851 section 6.2.2 step 1: "In the case of a syntax error, the 'a=rid' line is
    /// discarded"; the others stand.
    /// W3C webrtc-pc createAnswer: a rid-id named again is taken out, with a stream it
    /// leaves empty.
    #[test]
    fn a_repeated_rid_is_reduced_to_its_first_occurrence() {
        assert_eq!(without_repeated_rids("send a;b"), None);
        assert_eq!(
            without_repeated_rids("send a;b;a recv c;~b,d").as_deref(),
            Some("send a;b recv c;d")
        );
    }

    /// RFC 8851 sections 6.2.2 (step 6) and 8: a rid whose limits no `a=imageattr` set of its
    /// formats admits ("a minimum width of 640 ... "max-width=320" ... is nonsensical") is
    /// discarded, in the direction of the line; a format without a set of that direction, or
    /// with `*`, admits any size; `max-fs` counts the smallest picture of a set.
    #[test]
    fn a_rid_no_imageattr_set_admits_is_discarded() {
        let section = section_rids(&video(
            &["96", "97"],
            &[
                ("imageattr", "96 send [x=[640:1920],y=[360:1080]] recv *"),
                ("imageattr", "97 send [x=1280,y=720]"),
                ("rid", "small send pt=96,97;max-width=320"),
                ("rid", "wide send pt=96;max-width=1920"),
                ("rid", "tall send pt=96;max-height=320"),
                ("rid", "frame send pt=96;max-fs=230399"),
                ("rid", "frame2 send pt=96;max-fs=230400"),
                ("rid", "nopt send max-width=1000"),
                ("rid", "in recv pt=96;max-width=100"),
            ],
        ));
        assert_eq!(ids(&section), ["wide", "frame2", "nopt", "in"]);
    }

    #[test]
    fn a_malformed_rid_line_is_discarded() {
        let section = section_rids(&video(
            &["96"],
            &[
                ("rid", "a send"),
                ("rid", "b sideways"),
                ("rid", "c send max-width=abc"),
                ("rid", "d!d send"),
                ("rid", "e send max-fps=30;max-fps=15"),
                ("rid", "f recv max-fps=30;pt=96"),
            ],
        ));
        assert_eq!(ids(&section), ["a"]);
    }

    /// RFC 8851 section 6.2.2 step 2: "In the case of a duplicate, the entire 'a=rid' line,
    /// and all 'a=rid' lines with rid-ids that duplicate this line, are discarded".
    #[test]
    fn a_rid_id_that_occurs_twice_discards_every_line_with_it() {
        let section = section_rids(&video(
            &["96"],
            &[
                ("rid", "a send"),
                ("rid", "b send"),
                ("rid", "a send max-fps=15"),
                ("simulcast", "send a;b"),
            ],
        ));
        assert_eq!(ids(&section), ["b"]);
        assert!(section.rids[0].simulcast);
    }

    /// RFC 8851 section 6.2.2 step 3: "Any PT missing from the 'm=' line is discarded from
    /// the set of values in the 'pt='. If no values are left in the 'pt=' parameter after
    /// this processing, then the 'a=rid' line is discarded."
    #[test]
    fn a_pt_list_keeps_the_formats_of_the_m_line_only() {
        let section = section_rids(&video(
            &["96", "98"],
            &[
                ("rid", "a send pt=96,97"),
                ("rid", "b send pt=97,99"),
                ("rid", "c send pt=98;max-width=640"),
            ],
        ));
        assert_eq!(ids(&section), ["a", "c"]);
        assert_eq!(section.rids[0].formats, [96]);
        assert_eq!(section.rids[1].formats, [98]);
        assert_eq!(section.rids[1].to_restrictions().max_width, Some(640));
    }

    /// RFC 8851 section 6.2.2 step 4: a `recv` line with a restriction this endpoint does not
    /// support is discarded; a `send` line may carry one ("the answerer does not need to
    /// understand every restriction present in a 'send' line"). Step 6: a limit of zero is
    /// one no codec meets.
    #[test]
    fn a_recv_line_with_an_unknown_restriction_is_discarded() {
        let section = section_rids(&video(
            &["96"],
            &[
                ("rid", "a recv max-width=1280;max-height=720"),
                ("rid", "b recv max-sparkle=7"),
                ("rid", "c send max-sparkle=7"),
                ("rid", "d recv max-br"),
                ("rid", "e recv max-fs=0"),
                ("rid", "f recv max-bpp=0.0"),
            ],
        ));
        assert_eq!(ids(&section), ["a", "c"]);
        let restrictions = section.rids[0].to_restrictions();
        assert_eq!(restrictions.max_width, Some(1280));
        assert_eq!(restrictions.max_height, Some(720));
    }

    /// RFC 8851 section 6.2.2 step 5: "the listed rid-ids unambiguously match the rid-ids in
    /// the media description. Any 'depend' 'a=rid' lines that do not are discarded", and so
    /// is a line that depends on a discarded one.
    #[test]
    fn a_depend_on_a_rid_the_section_does_not_have_discards_the_line() {
        let section = section_rids(&video(
            &["96"],
            &[
                ("rid", "base send max-fps=15"),
                ("rid", "mid send depend=base"),
                ("rid", "top send depend=base,mid"),
                ("rid", "lost send depend=nothing"),
                ("rid", "chained send depend=lost"),
                ("rid", "self send depend=self"),
                ("rid", "other recv depend=base"),
            ],
        ));
        assert_eq!(ids(&section), ["base", "mid", "top"]);
        assert_eq!(section.rids[2].to_restrictions().depend, ["base", "mid"]);
    }

    /// RFC 8853 section 5.2: "The direction for the rid-id MUST be aligned with the
    /// direction specified for the corresponding RTP stream identifier on the 'a=rid'
    /// line", and a rid-id without an `a=rid` line is not used.
    #[test]
    fn a_simulcast_stream_needs_a_rid_line_of_its_direction() {
        let section = section_rids(&video(
            &["96"],
            &[
                ("rid", "a send"),
                ("rid", "b recv"),
                ("rid", "c send"),
                ("rid", "d recv"),
                ("simulcast", "send a;b;c;x recv d"),
            ],
        ));
        // b is declared `recv` and listed under `send`: a rid still, not a simulcast stream.
        let simulcast: Vec<(&str, SimulcastDirection)> = section
            .rids
            .iter()
            .filter(|rid| rid.simulcast)
            .map(|rid| (rid.id.as_str(), rid.direction))
            .collect();
        assert_eq!(
            simulcast,
            [
                ("a", SimulcastDirection::Send),
                ("c", SimulcastDirection::Send),
                ("d", SimulcastDirection::Recv)
            ]
        );
        assert_eq!(ids(&section), ["a", "c", "d", "b"]);
        assert_eq!(section.referenced, ["a", "b", "c", "x", "d"]);
        assert_eq!(
            simulcast_rid_without_line(&video(
                &["96"],
                &[("rid", "a send"), ("simulcast", "send a;x")]
            )),
            Some("x".to_owned())
        );
    }

    /// RFC 8853 section 5.2: of a stream's comma-separated alternatives one is used; the
    /// first usable one, and the others are not rids of the section any more. `recv` may
    /// come first.
    #[test]
    fn the_first_usable_alternative_of_a_stream_is_taken() {
        let section = section_rids(&video(
            &["96", "97"],
            &[
                ("rid", "1 recv pt=99"),
                ("rid", "2 recv pt=96"),
                ("rid", "3 recv pt=97"),
                ("rid", "4 recv"),
                ("rid", "5 send"),
                ("simulcast", "recv 1,2,3;~4 send 5"),
            ],
        ));
        assert_eq!(ids(&section), ["2", "4", "5"]);
        assert!(!section.rids[0].paused);
        assert!(section.rids[1].paused);
    }

    /// RFC 8853 section 5.3.2: "If multiple 'a=simulcast' attributes are present in a media
    /// description, the answerer SHALL disable simulcast": no rid is a simulcast stream.
    #[test]
    fn several_simulcast_lines_leave_no_simulcast_stream() {
        let section = section_rids(&video(
            &["96"],
            &[
                ("rid", "a send"),
                ("rid", "b send"),
                ("simulcast", "send a;b"),
                ("simulcast", "send a"),
            ],
        ));
        assert_eq!(section.simulcast_lines, 2);
        assert!(section.rids.iter().all(|rid| !rid.simulcast));
    }

    /// RFC 8851 section 6.4 steps 2 to 5.
    #[test]
    fn an_answered_rid_may_only_tighten_what_was_offered() {
        let rid = |line: &str| {
            section_rids(&video(&["96", "97", "98"], &[("rid", line)]))
                .rids
                .pop()
                .expect(line)
        };
        let same = |pt: u8, offered: &[u8]| offered.contains(&pt);
        let offered = rid("a send pt=96,97;max-width=1280;max-fps=30;max-bpp=0.5");

        for accepted in [
            "a recv",
            "a recv pt=96,97;max-width=1280;max-fps=30;max-bpp=0.5",
            "a recv pt=97;max-width=640",
            "a recv max-fps=15;max-bpp=0.25",
        ] {
            assert!(
                answered_rid_is_valid(&offered, &rid(accepted), same),
                "{accepted}"
            );
        }
        for refused in [
            // The direction is not reversed.
            "a send",
            // A restriction the offer did not have.
            "a recv max-height=720",
            // A looser value.
            "a recv max-width=1920",
            "a recv max-bpp=0.75",
            // A payload type the offer did not list.
            "a recv pt=98",
        ] {
            assert!(
                !answered_rid_is_valid(&offered, &rid(refused), same),
                "{refused}"
            );
        }
        // Step 4: "contains a 'pt=' but the offer did not".
        assert!(!answered_rid_is_valid(
            &rid("a send max-fps=30"),
            &rid("a recv pt=96;max-fps=30"),
            same
        ));
    }

    #[test]
    fn restrictions_are_written_as_they_were_given() {
        let restrictions = RTCRtpRidRestrictions {
            payload_types: vec![96, 98],
            max_width: Some(1280),
            max_height: Some(720),
            max_fps: Some(30),
            max_fs: Some(3600),
            max_br: Some(1_500_000),
            max_pps: Some(27_648_000),
            max_bpp: Some(0.25),
            depend: vec!["base".to_owned()],
        };
        let rid = SimulcastRid::from_restrictions("hi", SimulcastDirection::Send, &restrictions);
        let line = rid.line(SimulcastDirection::Send, rid.formats.clone());
        assert_eq!(
            line,
            "hi send pt=96,98;max-width=1280;max-height=720;max-fps=30;max-fs=3600;\
             max-br=1500000;max-pps=27648000;max-bpp=0.2500;depend=base"
        );
        let read = SimulcastRid::from_rid(Rid::parse(&line).unwrap());
        assert_eq!(read.to_restrictions(), restrictions);
    }
}

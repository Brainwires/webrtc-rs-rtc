//! `a=rid` (RFC 8851) and `a=simulcast` (RFC 8853, with the pause marker of RFC 7728).

use std::fmt;

use shared::error::Result;

use super::TypedAttribute;
use crate::grammar::{self, invalid, syntax};

/// `rid-dir`: which way the restrictions of an `a=rid` line apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RidDirection {
    /// `send`
    Send,
    /// `recv`
    Recv,
}

impl RidDirection {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "send" => Some(RidDirection::Send),
            "recv" => Some(RidDirection::Recv),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            RidDirection::Send => "send",
            RidDirection::Recv => "recv",
        }
    }
}

impl fmt::Display for RidDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The `rid-id` grammar a line is read with.
///
/// RFC 8851 section 10 as published has `rid-id = 1*(alpha-numeric / "-" / "_")`; erratum
/// 7132 (Verified 2022-10-13) corrects it to `rid-id = 1*255(alpha-numeric)`, "consistent with
/// the rules for the RtpStreamId/RepairedRtpStreamId SDES from RFC 8852 section 3". The
/// corrected grammar is the default; [`Rid::parse`], [`Simulcast::parse`] and [`Rid::new`]
/// use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RidIdGrammar {
    /// `1*255(alpha-numeric)` (erratum 7132).
    #[default]
    Corrected,
    /// `1*(alpha-numeric / "-" / "_")`, of any length: RFC 8851 as published.
    Published,
}

impl RidIdGrammar {
    /// Whether `id` is a rid-id in this grammar.
    pub fn admits(self, id: &str) -> bool {
        match self {
            RidIdGrammar::Corrected => grammar::is_rid_id(id),
            RidIdGrammar::Published => grammar::is_alnum_dash_underscore(id),
        }
    }
}

/// The restrictions whose value is `int-param-val = 1*DIGIT`.
const RID_INTEGER_RESTRICTIONS: [&str; 6] = [
    "max-width",
    "max-height",
    "max-fps",
    "max-fs",
    "max-br",
    "max-pps",
];

/// `a=rid:<rid-id> <direction> [pt=<fmt-list>;]<restriction>=<value>;...` (RFC 8851
/// section 10).
///
/// ```text
/// rid-syntax        = %s"a=rid:" rid-id SP rid-dir [ rid-pt-param-list / rid-param-list ]
/// rid-id            = 1*255(alpha-numeric)        ; erratum 7132 (see RidIdGrammar)
/// rid-pt-param-list = SP rid-fmt-list *(";" rid-param)
/// rid-param-list    = SP rid-param *(";" rid-param)
/// rid-fmt-list      = %s"pt=" fmt *( "," fmt )
/// ```
///
/// The restrictions RFC 8851 section 5 defines have accessors (`max_width()` and the
/// others); any other `name[=value]` is kept in [`Rid::restrictions`], in the order
/// written, so that it can be recognised or refused by whoever knows it (section 6.2: an
/// answerer discards an `a=rid` line with a restriction it does not understand).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rid {
    /// The RTP stream identifier: 1 to 255 letters and digits (`-` and `_` too, and any
    /// length, when read with [`RidIdGrammar::Published`]).
    pub id: String,
    /// The direction the restrictions apply in.
    pub direction: RidDirection,
    /// The `pt=` list: the payload types the stream may use. Empty when there is no `pt=`,
    /// which means any payload type of the media section.
    pub formats: Vec<u8>,
    /// Every restriction but `pt=`, as `(name, value)`, in order. No name occurs twice.
    pub restrictions: Vec<(String, Option<String>)>,
}

impl Rid {
    /// An `a=rid` line with no `pt=` and no restriction. `id` must be a rid-id of the
    /// corrected grammar ([`RidIdGrammar::Corrected`]).
    pub fn new(id: impl Into<String>, direction: RidDirection) -> Result<Self> {
        Self::new_in(id, direction, RidIdGrammar::Corrected)
    }

    fn new_in(
        id: impl Into<String>,
        direction: RidDirection,
        rid_ids: RidIdGrammar,
    ) -> Result<Self> {
        let id = id.into();
        if !rid_ids.admits(&id) {
            return Err(syntax("rid-id", &id));
        }
        Ok(Rid {
            id,
            direction,
            formats: vec![],
            restrictions: vec![],
        })
    }

    /// The value of the restriction `name`. The outer `None` is "not present"; the inner
    /// one is "present without a value".
    pub fn restriction(&self, name: &str) -> Option<Option<&str>> {
        self.restrictions
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_deref())
    }

    fn integer(&self, name: &str) -> Option<u64> {
        // Checked when the line was parsed; a hand-built one that does not parse is absent.
        self.restriction(name)??.parse().ok()
    }

    /// `max-width`, in pixels.
    pub fn max_width(&self) -> Option<u64> {
        self.integer("max-width")
    }

    /// `max-height`, in pixels.
    pub fn max_height(&self) -> Option<u64> {
        self.integer("max-height")
    }

    /// `max-fps`, in frames per second.
    pub fn max_fps(&self) -> Option<u64> {
        self.integer("max-fps")
    }

    /// `max-fs`, the frame size in pixels per frame.
    pub fn max_fs(&self) -> Option<u64> {
        self.integer("max-fs")
    }

    /// `max-br`, in bits per second.
    pub fn max_br(&self) -> Option<u64> {
        self.integer("max-br")
    }

    /// `max-pps`, in pixels per second.
    pub fn max_pps(&self) -> Option<u64> {
        self.integer("max-pps")
    }

    /// `max-bpp`, in bits per pixel.
    pub fn max_bpp(&self) -> Option<f64> {
        self.restriction("max-bpp")??.parse().ok()
    }

    /// `depend`: the rid-ids this stream depends on. Empty when there is none.
    pub fn depend(&self) -> Vec<&str> {
        match self.restriction("depend") {
            Some(Some(list)) => list.split(',').collect(),
            _ => vec![],
        }
    }
}

/// `float-param-val = 1*DIGIT "." 1*DIGIT`.
fn is_float_param(value: &str) -> bool {
    matches!(value.split_once('.'), Some((i, f)) if grammar::is_digits(i) && grammar::is_digits(f))
}

/// `param-val = *(%x20-3A / %x3C-7E)`: printable, no semicolon.
fn is_param_val(value: &str) -> bool {
    value
        .bytes()
        .all(|b| (0x20..=0x7e).contains(&b) && b != b';')
}

impl TypedAttribute for Rid {
    const NAME: &'static str = "rid";

    /// The line read with the corrected `rid-id` grammar ([`RidIdGrammar::Corrected`]).
    fn parse(value: &str) -> Result<Self> {
        Rid::parse_with(value, RidIdGrammar::Corrected)
    }
}

impl Rid {
    /// The value of an `a=rid` line, its rid-ids (its own and `depend=`'s) read with
    /// `rid_ids`.
    pub fn parse_with(value: &str, rid_ids: RidIdGrammar) -> Result<Self> {
        let mut parts = value.splitn(3, ' ');
        let (Some(id), Some(direction)) = (parts.next(), parts.next()) else {
            return Err(syntax("a=rid", value));
        };
        let Some(direction) = RidDirection::parse(direction) else {
            return Err(syntax("a=rid direction", value));
        };
        let mut rid = Rid::new_in(id, direction, rid_ids).map_err(|_| syntax("a=rid", value))?;

        let Some(params) = parts.next() else {
            return Ok(rid);
        };
        for (index, param) in params.split(';').enumerate() {
            let (name, param_value) = match param.split_once('=') {
                Some((name, v)) => (name, Some(v)),
                None => (param, None),
            };
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err(syntax("a=rid restriction", value));
            }

            if name == "pt" {
                // rid-fmt-list is the first parameter, and needs a value.
                let Some(list) = param_value.filter(|_| index == 0) else {
                    return Err(syntax("a=rid pt", value));
                };
                for fmt in list.split(',') {
                    let pt: u8 = grammar::digits_no_leading_zero("a=rid pt", fmt)?;
                    if pt > 127 || rid.formats.contains(&pt) {
                        return Err(invalid("a=rid pt", value));
                    }
                    rid.formats.push(pt);
                }
                continue;
            }

            let ok = match (name, param_value) {
                (n, v) if RID_INTEGER_RESTRICTIONS.contains(&n) => v.is_none_or(grammar::is_digits),
                ("max-bpp", v) => v.is_none_or(is_float_param),
                // rid-depend-param = %s"depend=" rid-list
                ("depend", Some(list)) => list.split(',').all(|id| rid_ids.admits(id)),
                ("depend", None) => false,
                (_, v) => v.is_none_or(is_param_val),
            };
            if !ok {
                return Err(syntax("a=rid restriction", value));
            }
            if rid.restriction(name).is_some() {
                return Err(invalid("a=rid: a restriction occurs twice", value));
            }
            rid.restrictions
                .push((name.to_owned(), param_value.map(str::to_owned)));
        }
        Ok(rid)
    }
}

impl fmt::Display for Rid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.id, self.direction)?;
        let mut separator = ' ';
        if !self.formats.is_empty() {
            write!(f, " pt=")?;
            for (i, pt) in self.formats.iter().enumerate() {
                if i > 0 {
                    f.write_str(",")?;
                }
                write!(f, "{pt}")?;
            }
            separator = ';';
        }
        for (name, value) in &self.restrictions {
            write!(f, "{separator}{name}")?;
            if let Some(value) = value {
                write!(f, "={value}")?;
            }
            separator = ';';
        }
        Ok(())
    }
}

/// One `sc-id` of an `a=simulcast` line: a rid-id, with `~` in front when the stream is
/// initially paused (RFC 8853 section 5.1, RFC 7728).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SimulcastId {
    /// The rid-id, naming an `a=rid` line of the same media section.
    pub rid: String,
    /// Whether the stream starts paused (`~`).
    pub paused: bool,
}

impl fmt::Display for SimulcastId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.paused {
            f.write_str("~")?;
        }
        f.write_str(&self.rid)
    }
}

/// `a=simulcast:<direction> <streams> [<direction> <streams>]` (RFC 8853 section 5.1).
///
/// ```text
/// sc-value     = ( sc-send [SP sc-recv] ) / ( sc-recv [SP sc-send] )
/// sc-send      = %s"send" SP sc-str-list
/// sc-recv      = %s"recv" SP sc-str-list
/// sc-str-list  = sc-alt-list *( ";" sc-alt-list )
/// sc-alt-list  = sc-id *( "," sc-id )
/// sc-id        = [sc-id-paused] rid-id
/// ```
///
/// A direction is a list of simulcast streams, separated by `;`; a stream is a list of
/// alternative formats, separated by `,`, of which one is used at a time. A rid-id occurs
/// once in the whole attribute (section 5.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Simulcast {
    /// The streams sent: one entry per stream, each a list of alternatives. Empty when the
    /// attribute has no `send` part.
    pub send: Vec<Vec<SimulcastId>>,
    /// The streams received, likewise.
    pub recv: Vec<Vec<SimulcastId>>,
    /// Whether `recv` was written before `send`. Both orders mean the same.
    pub recv_first: bool,
}

impl Simulcast {
    /// Every rid-id of the attribute, `send` first.
    pub fn rids(&self) -> impl Iterator<Item = &str> {
        self.send
            .iter()
            .chain(&self.recv)
            .flatten()
            .map(|id| id.rid.as_str())
    }
}

fn parse_stream_list(
    value: &str,
    list: &str,
    rid_ids: RidIdGrammar,
) -> Result<Vec<Vec<SimulcastId>>> {
    list.split(';')
        .map(|alternatives| {
            alternatives
                .split(',')
                .map(|id| {
                    let (rid, paused) = match id.strip_prefix('~') {
                        Some(rid) => (rid, true),
                        None => (id, false),
                    };
                    if !rid_ids.admits(rid) {
                        return Err(syntax("a=simulcast", value));
                    }
                    Ok(SimulcastId {
                        rid: rid.to_owned(),
                        paused,
                    })
                })
                .collect()
        })
        .collect()
}

impl TypedAttribute for Simulcast {
    const NAME: &'static str = "simulcast";

    /// The line read with the corrected `rid-id` grammar ([`RidIdGrammar::Corrected`]).
    fn parse(value: &str) -> Result<Self> {
        Simulcast::parse_with(value, RidIdGrammar::Corrected)
    }
}

impl Simulcast {
    /// The value of an `a=simulcast` line, its rid-ids read with `rid_ids`.
    pub fn parse_with(value: &str, rid_ids: RidIdGrammar) -> Result<Self> {
        let fields = grammar::fields("a=simulcast", value)?;
        if fields.len() != 2 && fields.len() != 4 {
            return Err(syntax("a=simulcast", value));
        }
        let mut simulcast = Simulcast::default();
        for (index, pair) in fields.chunks(2).enumerate() {
            let list = parse_stream_list(value, pair[1], rid_ids)?;
            let slot = match RidDirection::parse(pair[0]) {
                Some(RidDirection::Send) => &mut simulcast.send,
                Some(RidDirection::Recv) => {
                    simulcast.recv_first = index == 0;
                    &mut simulcast.recv
                }
                None => return Err(syntax("a=simulcast direction", value)),
            };
            // "each direction MUST NOT occur more than once on the same line"
            if !slot.is_empty() {
                return Err(syntax("a=simulcast: a direction occurs twice", value));
            }
            *slot = list;
        }
        // "a single rid-id MUST NOT occur more than once per 'a=simulcast' line"
        let mut seen: Vec<&str> = Vec::new();
        for rid in simulcast.rids() {
            if seen.contains(&rid) {
                return Err(invalid("a=simulcast: a rid-id occurs twice", value));
            }
            seen.push(rid);
        }
        Ok(simulcast)
    }
}

fn write_stream_list(f: &mut fmt::Formatter<'_>, streams: &[Vec<SimulcastId>]) -> fmt::Result {
    for (i, alternatives) in streams.iter().enumerate() {
        if i > 0 {
            f.write_str(";")?;
        }
        for (j, id) in alternatives.iter().enumerate() {
            if j > 0 {
                f.write_str(",")?;
            }
            write!(f, "{id}")?;
        }
    }
    Ok(())
}

impl fmt::Display for Simulcast {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let send = (RidDirection::Send, &self.send);
        let recv = (RidDirection::Recv, &self.recv);
        let order = if self.recv_first {
            [recv, send]
        } else {
            [send, recv]
        };
        let mut first = true;
        for (direction, streams) in order {
            if streams.is_empty() {
                continue;
            }
            if !first {
                f.write_str(" ")?;
            }
            first = false;
            write!(f, "{direction} ")?;
            write_stream_list(f, streams)?;
        }
        Ok(())
    }
}

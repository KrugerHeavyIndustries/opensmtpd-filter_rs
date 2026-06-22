/*
 * Copyright (c) 2026 Chris Kruger <montdidier@users.noreply.github.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::types::{Address, Direction, Event, FilterKind, Phase};

#[derive(Debug)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "protocol parse error: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

pub fn parse_event(line: &str) -> Result<(Event, &str), ParseError> {
    let mut parts = line.splitn(2, '|');
    let kind_str = parts
        .next()
        .ok_or_else(|| ParseError("missing type".into()))?;
    let rest = parts
        .next()
        .ok_or_else(|| ParseError("missing version".into()))?;

    let kind = match kind_str {
        "filter" => FilterKind::Filter,
        "report" => FilterKind::Report,
        _ => return Err(ParseError(format!("unknown type: {kind_str}"))),
    };

    let mut parts = rest.splitn(2, '|');
    let version_str = parts
        .next()
        .ok_or_else(|| ParseError("missing version".into()))?;
    let rest = parts
        .next()
        .ok_or_else(|| ParseError("missing timestamp".into()))?;

    let (version_major, version_minor) = parse_version(version_str)?;

    let mut parts = rest.splitn(2, '|');
    let timestamp_str = parts
        .next()
        .ok_or_else(|| ParseError("missing timestamp".into()))?;
    let rest = parts
        .next()
        .ok_or_else(|| ParseError("missing direction".into()))?;

    let timestamp = parse_timestamp(timestamp_str)?;

    let mut parts = rest.splitn(2, '|');
    let direction_str = parts
        .next()
        .ok_or_else(|| ParseError("missing direction".into()))?;
    let rest = parts
        .next()
        .ok_or_else(|| ParseError("missing phase".into()))?;

    let direction = match direction_str {
        "smtp-in" => Direction::Incoming,
        "smtp-out" => Direction::Outgoing,
        _ => return Err(ParseError(format!("unknown direction: {direction_str}"))),
    };

    let mut parts = rest.splitn(2, '|');
    let phase_str = parts
        .next()
        .ok_or_else(|| ParseError("missing phase".into()))?;
    let rest = parts
        .next()
        .ok_or_else(|| ParseError("missing reqid".into()))?;

    let phase =
        Phase::from_str(phase_str).ok_or_else(|| ParseError(format!("unknown phase: {phase_str}")))?;

    let (reqid, token, params) = if kind == FilterKind::Filter {
        let mut parts = rest.splitn(2, '|');
        let reqid_str = parts
            .next()
            .ok_or_else(|| ParseError("missing reqid".into()))?;
        let rest = parts
            .next()
            .ok_or_else(|| ParseError("missing token".into()))?;

        let reqid = u64::from_str_radix(reqid_str, 16)
            .map_err(|e| ParseError(format!("invalid reqid: {e}")))?;

        let mut parts = rest.splitn(2, '|');
        let token_str = parts
            .next()
            .ok_or_else(|| ParseError("missing token".into()))?;
        let params = parts.next().unwrap_or("");

        let token = u64::from_str_radix(token_str, 16)
            .map_err(|e| ParseError(format!("invalid token: {e}")))?;

        (reqid, Some(token), params)
    } else {
        let mut parts = rest.splitn(2, '|');
        let reqid_str = parts
            .next()
            .ok_or_else(|| ParseError("missing reqid".into()))?;
        let params = parts.next().unwrap_or("");

        let reqid = u64::from_str_radix(reqid_str, 16)
            .map_err(|e| ParseError(format!("invalid reqid: {e}")))?;

        (reqid, None, params)
    };

    let event = Event {
        kind,
        phase,
        version_major,
        version_minor,
        timestamp,
        direction,
        reqid,
        token,
    };

    Ok((event, params))
}

fn parse_version(s: &str) -> Result<(u32, u32), ParseError> {
    let mut parts = s.split('.');
    let major = parts
        .next()
        .ok_or_else(|| ParseError("missing major version".into()))?
        .parse::<u32>()
        .map_err(|e| ParseError(format!("invalid major version: {e}")))?;
    let minor = parts
        .next()
        .ok_or_else(|| ParseError("missing minor version".into()))?
        .parse::<u32>()
        .map_err(|e| ParseError(format!("invalid minor version: {e}")))?;
    Ok((major, minor))
}

fn parse_timestamp(s: &str) -> Result<SystemTime, ParseError> {
    let mut parts = s.splitn(2, '.');
    let secs_str = parts
        .next()
        .ok_or_else(|| ParseError("missing seconds".into()))?;
    let nsecs_str = parts
        .next()
        .ok_or_else(|| ParseError("missing nanoseconds".into()))?;

    let secs: u64 = secs_str
        .parse()
        .map_err(|e| ParseError(format!("invalid seconds: {e}")))?;

    let nsecs_digits = nsecs_str.len();
    let nsecs_raw: u64 = nsecs_str
        .parse()
        .map_err(|e| ParseError(format!("invalid nanoseconds: {e}")))?;

    let nsecs = if nsecs_digits < 9 {
        nsecs_raw * 10u64.pow(9 - nsecs_digits as u32)
    } else {
        nsecs_raw
    };

    Ok(UNIX_EPOCH + Duration::new(secs, nsecs as u32))
}

pub fn parse_address(s: &str, with_port: bool) -> Result<Address, ParseError> {
    if s.starts_with("unix:") {
        return Ok(Address::Unix(s.to_string()));
    }

    if s.starts_with('[') {
        let (addr_str, port) = if with_port {
            let colon_pos = s
                .rfind(':')
                .ok_or_else(|| ParseError(format!("missing port in address: {s}")))?;
            let bracket_pos = s[..colon_pos]
                .rfind(']')
                .ok_or_else(|| ParseError(format!("malformed IPv6 address: {s}")))?;
            let addr_part = &s[1..bracket_pos];
            let port_str = &s[colon_pos + 1..];
            let port: u16 = port_str
                .parse()
                .map_err(|e| ParseError(format!("invalid port: {e}")))?;
            (addr_part, port)
        } else {
            let end = s.len() - 1;
            if !s.ends_with(']') {
                return Err(ParseError(format!("malformed IPv6 address: {s}")));
            }
            (&s[1..end], 0)
        };

        let ip: Ipv6Addr = addr_str
            .parse()
            .map_err(|e| ParseError(format!("invalid IPv6 address: {e}")))?;
        Ok(Address::Ip(SocketAddr::new(IpAddr::V6(ip), port)))
    } else {
        let (addr_str, port) = if with_port {
            let colon_pos = s
                .rfind(':')
                .ok_or_else(|| ParseError(format!("missing port in address: {s}")))?;
            let addr_part = &s[..colon_pos];
            let port_str = &s[colon_pos + 1..];
            let port: u16 = port_str
                .parse()
                .map_err(|e| ParseError(format!("invalid port: {e}")))?;
            (addr_part, port)
        } else {
            (s, 0)
        };

        let ip: Ipv4Addr = addr_str
            .parse()
            .map_err(|e| ParseError(format!("invalid IPv4 address: {e}")))?;
        Ok(Address::Ip(SocketAddr::new(IpAddr::V4(ip), port)))
    }
}

pub fn format_filter_result(reqid: u64, token: u64, action: &str) -> String {
    format!("filter-result|{reqid:016x}|{token:016x}|{action}\n")
}

pub fn format_filter_dataline(reqid: u64, token: u64, line: &str) -> String {
    format!("filter-dataline|{reqid:016x}|{token:016x}|{line}\n")
}

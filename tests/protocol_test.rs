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

use opensmtpd_filter::protocol::{format_filter_dataline, format_filter_result, parse_address, parse_event};
use opensmtpd_filter::types::{Address, Direction, FilterKind, Phase};

#[test]
fn test_parse_filter_event() {
    let line = "filter|0.7|1234567890.123456789|smtp-in|mail-from|abc123|def456|user@example.com";
    let (event, params) = parse_event(line).unwrap();

    assert_eq!(event.kind, FilterKind::Filter);
    assert_eq!(event.phase, Phase::MailFrom);
    assert_eq!(event.version_major, 0);
    assert_eq!(event.version_minor, 7);
    assert_eq!(event.direction, Direction::Incoming);
    assert_eq!(event.reqid, 0xabc123);
    assert_eq!(event.token, Some(0xdef456));
    assert_eq!(params, "user@example.com");
}

#[test]
fn test_parse_report_event() {
    let line = "report|0.7|1234567890.100|smtp-in|link-disconnect|abc123";
    let (event, params) = parse_event(line).unwrap();

    assert_eq!(event.kind, FilterKind::Report);
    assert_eq!(event.phase, Phase::LinkDisconnect);
    assert_eq!(event.direction, Direction::Incoming);
    assert_eq!(event.reqid, 0xabc123);
    assert_eq!(event.token, None);
    assert_eq!(params, "");
}

#[test]
fn test_parse_ipv4_address_without_port() {
    let addr = parse_address("192.168.1.1", false).unwrap();
    match addr {
        Address::Ip(sa) => {
            assert_eq!(sa.ip().to_string(), "192.168.1.1");
            assert_eq!(sa.port(), 0);
        }
        _ => panic!("expected IP address"),
    }
}

#[test]
fn test_parse_ipv4_address_with_port() {
    let addr = parse_address("192.168.1.1:25", true).unwrap();
    match addr {
        Address::Ip(sa) => {
            assert_eq!(sa.ip().to_string(), "192.168.1.1");
            assert_eq!(sa.port(), 25);
        }
        _ => panic!("expected IP address"),
    }
}

#[test]
fn test_parse_ipv6_address_without_port() {
    let addr = parse_address("[::1]", false).unwrap();
    match addr {
        Address::Ip(sa) => {
            assert_eq!(sa.ip().to_string(), "::1");
            assert_eq!(sa.port(), 0);
        }
        _ => panic!("expected IP address"),
    }
}

#[test]
fn test_parse_ipv6_address_with_port() {
    let addr = parse_address("[::1]:25", true).unwrap();
    match addr {
        Address::Ip(sa) => {
            assert_eq!(sa.ip().to_string(), "::1");
            assert_eq!(sa.port(), 25);
        }
        _ => panic!("expected IP address"),
    }
}

#[test]
fn test_parse_unix_address() {
    let addr = parse_address("unix:/var/run/smtpd.sock", false).unwrap();
    match addr {
        Address::Unix(path) => assert_eq!(path, "unix:/var/run/smtpd.sock"),
        _ => panic!("expected unix address"),
    }
}

#[test]
fn test_format_filter_result() {
    let result = format_filter_result(0xabc123, 0xdef456, "proceed");
    assert_eq!(
        result,
        "filter-result|0000000000abc123|0000000000def456|proceed\n"
    );
}

#[test]
fn test_format_filter_dataline() {
    let result = format_filter_dataline(0xabc123, 0xdef456, "Subject: Hello");
    assert_eq!(
        result,
        "filter-dataline|0000000000abc123|0000000000def456|Subject: Hello\n"
    );
}

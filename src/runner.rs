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

use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::process::ExitCode;

use crate::filter::{Filter, FilterResponse};
use crate::protocol::{self, ParseError};
use crate::types::{Address, AuthStatus, Direction, FilterKind, Phase, Session, Status};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Registration {
    kind: FilterKind,
    phase: Phase,
    direction: Direction,
}

pub struct SmtpFilterRunner<F: Filter> {
    filter: F,
    sessions: HashMap<u64, Session>,
    registrations: Vec<Registration>,
}

impl<F: Filter> SmtpFilterRunner<F> {
    pub fn new(filter: F) -> Self {
        SmtpFilterRunner {
            filter,
            sessions: HashMap::new(),
            registrations: Vec::new(),
        }
    }

    pub fn register_filter_connect(&mut self) -> &mut Self {
        self.add_registration(FilterKind::Filter, Phase::Connect, Direction::Incoming);
        self.ensure_disconnect_report(Direction::Incoming);
        self
    }

    pub fn register_filter_helo(&mut self) -> &mut Self {
        self.add_registration(FilterKind::Filter, Phase::Helo, Direction::Incoming);
        self.ensure_disconnect_report(Direction::Incoming);
        self
    }

    pub fn register_filter_ehlo(&mut self) -> &mut Self {
        self.add_registration(FilterKind::Filter, Phase::Ehlo, Direction::Incoming);
        self.ensure_disconnect_report(Direction::Incoming);
        self
    }

    pub fn register_filter_starttls(&mut self) -> &mut Self {
        self.add_registration(FilterKind::Filter, Phase::StartTls, Direction::Incoming);
        self.ensure_disconnect_report(Direction::Incoming);
        self
    }

    pub fn register_filter_auth(&mut self) -> &mut Self {
        self.add_registration(FilterKind::Filter, Phase::Auth, Direction::Incoming);
        self.ensure_disconnect_report(Direction::Incoming);
        self
    }

    pub fn register_filter_mail_from(&mut self) -> &mut Self {
        self.add_registration(FilterKind::Filter, Phase::MailFrom, Direction::Incoming);
        self.ensure_disconnect_report(Direction::Incoming);
        self
    }

    pub fn register_filter_rcpt_to(&mut self) -> &mut Self {
        self.add_registration(FilterKind::Filter, Phase::RcptTo, Direction::Incoming);
        self.ensure_disconnect_report(Direction::Incoming);
        self
    }

    pub fn register_filter_data(&mut self) -> &mut Self {
        self.add_registration(FilterKind::Filter, Phase::Data, Direction::Incoming);
        self.ensure_disconnect_report(Direction::Incoming);
        self
    }

    pub fn register_filter_data_line(&mut self) -> &mut Self {
        self.add_registration(FilterKind::Filter, Phase::DataLine, Direction::Incoming);
        self.ensure_disconnect_report(Direction::Incoming);
        self
    }

    pub fn register_filter_reset(&mut self) -> &mut Self {
        self.add_registration(FilterKind::Filter, Phase::Reset, Direction::Incoming);
        self.ensure_disconnect_report(Direction::Incoming);
        self
    }

    pub fn register_filter_quit(&mut self) -> &mut Self {
        self.add_registration(FilterKind::Filter, Phase::Quit, Direction::Incoming);
        self.ensure_disconnect_report(Direction::Incoming);
        self
    }

    pub fn register_filter_noop(&mut self) -> &mut Self {
        self.add_registration(FilterKind::Filter, Phase::Noop, Direction::Incoming);
        self.ensure_disconnect_report(Direction::Incoming);
        self
    }

    pub fn register_filter_help(&mut self) -> &mut Self {
        self.add_registration(FilterKind::Filter, Phase::Help, Direction::Incoming);
        self.ensure_disconnect_report(Direction::Incoming);
        self
    }

    pub fn register_filter_wiz(&mut self) -> &mut Self {
        self.add_registration(FilterKind::Filter, Phase::Wiz, Direction::Incoming);
        self.ensure_disconnect_report(Direction::Incoming);
        self
    }

    pub fn register_filter_commit(&mut self) -> &mut Self {
        self.add_registration(FilterKind::Filter, Phase::Commit, Direction::Incoming);
        self.ensure_disconnect_report(Direction::Incoming);
        self
    }

    pub fn register_report_connect(&mut self, direction: Direction) -> &mut Self {
        self.add_registration(FilterKind::Report, Phase::LinkConnect, direction);
        self.ensure_disconnect_report(direction);
        self
    }

    pub fn register_report_disconnect(&mut self, direction: Direction) -> &mut Self {
        self.add_registration(FilterKind::Report, Phase::LinkDisconnect, direction);
        self
    }

    pub fn register_report_greeting(&mut self, direction: Direction) -> &mut Self {
        self.add_registration(FilterKind::Report, Phase::LinkGreeting, direction);
        self.ensure_disconnect_report(direction);
        self
    }

    pub fn register_report_identify(&mut self, direction: Direction) -> &mut Self {
        self.add_registration(FilterKind::Report, Phase::LinkIdentify, direction);
        self.ensure_disconnect_report(direction);
        self
    }

    pub fn register_report_tls(&mut self, direction: Direction) -> &mut Self {
        self.add_registration(FilterKind::Report, Phase::LinkTls, direction);
        self.ensure_disconnect_report(direction);
        self
    }

    pub fn register_report_auth(&mut self, direction: Direction) -> &mut Self {
        self.add_registration(FilterKind::Report, Phase::LinkAuth, direction);
        self.ensure_disconnect_report(direction);
        self
    }

    pub fn register_report_tx_begin(&mut self, direction: Direction) -> &mut Self {
        self.add_registration(FilterKind::Report, Phase::TxBegin, direction);
        self.ensure_disconnect_report(direction);
        self
    }

    pub fn register_report_tx_mail(&mut self, direction: Direction) -> &mut Self {
        self.add_registration(FilterKind::Report, Phase::TxMail, direction);
        self.ensure_disconnect_report(direction);
        self
    }

    pub fn register_report_tx_rcpt(&mut self, direction: Direction) -> &mut Self {
        self.add_registration(FilterKind::Report, Phase::TxRcpt, direction);
        self.ensure_disconnect_report(direction);
        self
    }

    pub fn register_report_tx_envelope(&mut self, direction: Direction) -> &mut Self {
        self.add_registration(FilterKind::Report, Phase::TxEnvelope, direction);
        self.ensure_disconnect_report(direction);
        self
    }

    pub fn register_report_tx_data(&mut self, direction: Direction) -> &mut Self {
        self.add_registration(FilterKind::Report, Phase::TxData, direction);
        self.ensure_disconnect_report(direction);
        self
    }

    pub fn register_report_tx_commit(&mut self, direction: Direction) -> &mut Self {
        self.add_registration(FilterKind::Report, Phase::TxCommit, direction);
        self.ensure_disconnect_report(direction);
        self
    }

    pub fn register_report_tx_rollback(&mut self, direction: Direction) -> &mut Self {
        self.add_registration(FilterKind::Report, Phase::TxRollback, direction);
        self.ensure_disconnect_report(direction);
        self
    }

    pub fn register_report_protocol_client(&mut self, direction: Direction) -> &mut Self {
        self.add_registration(FilterKind::Report, Phase::ProtocolClient, direction);
        self.ensure_disconnect_report(direction);
        self
    }

    pub fn register_report_protocol_server(&mut self, direction: Direction) -> &mut Self {
        self.add_registration(FilterKind::Report, Phase::ProtocolServer, direction);
        self.ensure_disconnect_report(direction);
        self
    }

    pub fn register_report_filter_response(&mut self, direction: Direction) -> &mut Self {
        self.add_registration(FilterKind::Report, Phase::FilterResponse, direction);
        self.ensure_disconnect_report(direction);
        self
    }

    pub fn register_report_timeout(&mut self, direction: Direction) -> &mut Self {
        self.add_registration(FilterKind::Report, Phase::Timeout, direction);
        self.ensure_disconnect_report(direction);
        self
    }

    pub fn run(&mut self) -> ExitCode {
        let stdin = io::stdin();
        let stdout = io::stdout();
        match self.run_with(stdin.lock(), stdout.lock()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("FATAL|{e}");
                ExitCode::FAILURE
            }
        }
    }

    pub fn run_with(&mut self, input: impl BufRead, mut output: impl Write) -> io::Result<()> {
        if self.registrations.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No events registered",
            ));
        }

        for reg in &self.registrations {
            let type_str = match reg.kind {
                FilterKind::Filter => "filter",
                FilterKind::Report => "report",
            };
            let dir_str = match reg.direction {
                Direction::Incoming => "smtp-in",
                Direction::Outgoing => "smtp-out",
            };
            writeln!(output, "register|{type_str}|{dir_str}|{}", reg.phase.as_str())?;
        }
        writeln!(output, "register|ready")?;
        output.flush()?;

        for line in input.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }

            self.handle_line(&line, &mut output)?;
            output.flush()?;
        }

        Ok(())
    }

    fn handle_line(&mut self, line: &str, out: &mut impl Write) -> Result<(), ParseError> {
        if line.starts_with("config|") {
            return self.handle_config(line);
        }

        let (event, params) = protocol::parse_event(line)?;

        let session = self
            .sessions
            .entry(event.reqid)
            .or_insert_with(|| Session::new(event.reqid));

        match (event.kind, event.phase) {
            (FilterKind::Filter, Phase::Connect) => {
                let (rdns, fcrdns, src, dst) = parse_filter_connect(params)?;
                session.rdns = Some(rdns.clone());
                session.fcrdns = fcrdns;
                session.src = Some(src.clone());
                session.dst = Some(dst.clone());
                let response =
                    self.filter
                        .on_filter_connect(session, &rdns, fcrdns, &src, &dst);
                write_filter_response(out, event.reqid, event.token.unwrap_or(0), &response)?;
            }
            (FilterKind::Filter, Phase::Helo) => {
                let response = self.filter.on_filter_helo(session, params);
                write_filter_response(out, event.reqid, event.token.unwrap_or(0), &response)?;
            }
            (FilterKind::Filter, Phase::Ehlo) => {
                let response = self.filter.on_filter_ehlo(session, params);
                write_filter_response(out, event.reqid, event.token.unwrap_or(0), &response)?;
            }
            (FilterKind::Filter, Phase::StartTls) => {
                let response = self.filter.on_filter_starttls(session);
                write_filter_response(out, event.reqid, event.token.unwrap_or(0), &response)?;
            }
            (FilterKind::Filter, Phase::Auth) => {
                let response = self.filter.on_filter_auth(session, params);
                write_filter_response(out, event.reqid, event.token.unwrap_or(0), &response)?;
            }
            (FilterKind::Filter, Phase::MailFrom) => {
                let response = self.filter.on_filter_mail_from(session, params);
                write_filter_response(out, event.reqid, event.token.unwrap_or(0), &response)?;
            }
            (FilterKind::Filter, Phase::RcptTo) => {
                let response = self.filter.on_filter_rcpt_to(session, params);
                write_filter_response(out, event.reqid, event.token.unwrap_or(0), &response)?;
            }
            (FilterKind::Filter, Phase::Data) => {
                let response = self.filter.on_filter_data(session);
                write_filter_response(out, event.reqid, event.token.unwrap_or(0), &response)?;
            }
            (FilterKind::Filter, Phase::DataLine) => {
                let lines = self.filter.on_filter_data_line(session, params);
                let reqid = event.reqid;
                let token = event.token.unwrap_or(0);
                for l in &lines {
                    let msg = protocol::format_filter_dataline(reqid, token, l);
                    out.write_all(msg.as_bytes())
                        .map_err(|e| ParseError(format!("write error: {e}")))?;
                }
            }
            (FilterKind::Filter, Phase::Reset) => {
                let response = self.filter.on_filter_reset(session);
                write_filter_response(out, event.reqid, event.token.unwrap_or(0), &response)?;
            }
            (FilterKind::Filter, Phase::Quit) => {
                let response = self.filter.on_filter_quit(session);
                write_filter_response(out, event.reqid, event.token.unwrap_or(0), &response)?;
            }
            (FilterKind::Filter, Phase::Noop) => {
                let response = self.filter.on_filter_noop(session);
                write_filter_response(out, event.reqid, event.token.unwrap_or(0), &response)?;
            }
            (FilterKind::Filter, Phase::Help) => {
                let response = self.filter.on_filter_help(session);
                write_filter_response(out, event.reqid, event.token.unwrap_or(0), &response)?;
            }
            (FilterKind::Filter, Phase::Wiz) => {
                let response = self.filter.on_filter_wiz(session);
                write_filter_response(out, event.reqid, event.token.unwrap_or(0), &response)?;
            }
            (FilterKind::Filter, Phase::Commit) => {
                let response = self.filter.on_filter_commit(session);
                write_filter_response(out, event.reqid, event.token.unwrap_or(0), &response)?;
            }
            (FilterKind::Report, Phase::LinkConnect) => {
                let (rdns, fcrdns, src, dst) = parse_report_link_connect(params)?;
                let session = self.sessions.get_mut(&event.reqid).unwrap();
                session.rdns = Some(rdns.clone());
                session.fcrdns = fcrdns;
                session.src = Some(src.clone());
                session.dst = Some(dst.clone());
                self.filter.on_report_link_connect(
                    session,
                    event.direction,
                    &rdns,
                    fcrdns,
                    &src,
                    &dst,
                );
            }
            (FilterKind::Report, Phase::LinkDisconnect) => {
                let session = self.sessions.get(&event.reqid).unwrap();
                self.filter
                    .on_report_link_disconnect(session, event.direction);
                self.sessions.remove(&event.reqid);
            }
            (FilterKind::Report, Phase::LinkGreeting) => {
                let session = self.sessions.get_mut(&event.reqid).unwrap();
                session.greeting = Some(params.to_string());
                self.filter
                    .on_report_link_greeting(session, event.direction, params);
            }
            (FilterKind::Report, Phase::LinkIdentify) => {
                let session = self.sessions.get_mut(&event.reqid).unwrap();
                session.identity = Some(params.to_string());
                self.filter
                    .on_report_link_identify(session, event.direction, params);
            }
            (FilterKind::Report, Phase::LinkTls) => {
                let session = self.sessions.get_mut(&event.reqid).unwrap();
                session.ciphers = Some(params.to_string());
                self.filter
                    .on_report_link_tls(session, event.direction, params);
            }
            (FilterKind::Report, Phase::LinkAuth) => {
                let (username, status) = parse_report_link_auth(params)?;
                let session = self.sessions.get_mut(&event.reqid).unwrap();
                if status == AuthStatus::Pass {
                    session.username = Some(username.clone());
                }
                self.filter
                    .on_report_link_auth(session, event.direction, &username, status);
            }
            (FilterKind::Report, Phase::TxBegin) => {
                let msgid = parse_msgid(params)?;
                let session = self.sessions.get_mut(&event.reqid).unwrap();
                session.msgid = Some(msgid);
                self.filter
                    .on_report_tx_begin(session, event.direction, msgid);
            }
            (FilterKind::Report, Phase::TxMail) => {
                let (msgid, address, status) =
                    parse_report_tx_mail(params, event.version_minor)?;
                let session = self.sessions.get_mut(&event.reqid).unwrap();
                session.mailfrom = Some(address.clone());
                self.filter
                    .on_report_tx_mail(session, event.direction, msgid, &address, status);
            }
            (FilterKind::Report, Phase::TxRcpt) => {
                let (msgid, address, status) =
                    parse_report_tx_rcpt(params, event.version_minor)?;
                let session = self.sessions.get_mut(&event.reqid).unwrap();
                session.rcptto.push(address.clone());
                self.filter
                    .on_report_tx_rcpt(session, event.direction, msgid, &address, status);
            }
            (FilterKind::Report, Phase::TxEnvelope) => {
                let (msgid, evpid) = parse_report_tx_envelope(params)?;
                let session = self.sessions.get_mut(&event.reqid).unwrap();
                session.evpid = Some(evpid);
                self.filter
                    .on_report_tx_envelope(session, event.direction, msgid, evpid);
            }
            (FilterKind::Report, Phase::TxData) => {
                let (msgid, status) = parse_report_tx_data(params)?;
                let session = self.sessions.get(&event.reqid).unwrap();
                self.filter
                    .on_report_tx_data(session, event.direction, msgid, status);
            }
            (FilterKind::Report, Phase::TxCommit) => {
                let (msgid, msg_size) = parse_report_tx_commit(params)?;
                let session = self.sessions.get_mut(&event.reqid).unwrap();
                self.filter
                    .on_report_tx_commit(session, event.direction, msgid, msg_size);
                session.clear_transaction();
            }
            (FilterKind::Report, Phase::TxRollback) => {
                let msgid = parse_msgid(params)?;
                let session = self.sessions.get_mut(&event.reqid).unwrap();
                self.filter
                    .on_report_tx_rollback(session, event.direction, msgid);
                session.clear_transaction();
            }
            (FilterKind::Report, Phase::ProtocolClient) => {
                let session = self.sessions.get(&event.reqid).unwrap();
                self.filter
                    .on_report_protocol_client(session, event.direction, params);
            }
            (FilterKind::Report, Phase::ProtocolServer) => {
                let session = self.sessions.get(&event.reqid).unwrap();
                self.filter
                    .on_report_protocol_server(session, event.direction, params);
            }
            (FilterKind::Report, Phase::FilterResponse) => {
                let session = self.sessions.get(&event.reqid).unwrap();
                self.filter
                    .on_report_filter_response(session, event.direction, params);
            }
            (FilterKind::Report, Phase::Timeout) => {
                let session = self.sessions.get(&event.reqid).unwrap();
                self.filter.on_report_timeout(session, event.direction);
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_config(&mut self, line: &str) -> Result<(), ParseError> {
        let rest = &line["config|".len()..];
        if rest == "ready" {
            self.filter.on_config_ready();
            return Ok(());
        }
        if let Some((key, value)) = rest.split_once('|') {
            self.filter.on_config(key, value);
        }
        Ok(())
    }

    fn add_registration(&mut self, kind: FilterKind, phase: Phase, direction: Direction) {
        let reg = Registration {
            kind,
            phase,
            direction,
        };
        if !self.registrations.contains(&reg) {
            self.registrations.push(reg);
        }
    }

    fn ensure_disconnect_report(&mut self, direction: Direction) {
        self.add_registration(FilterKind::Report, Phase::LinkDisconnect, direction);
    }
}

fn write_filter_response(
    out: &mut impl Write,
    reqid: u64,
    token: u64,
    response: &FilterResponse,
) -> Result<(), ParseError> {
    let msg = match response {
        FilterResponse::Proceed => protocol::format_filter_result(reqid, token, "proceed"),
        FilterResponse::Junk => protocol::format_filter_result(reqid, token, "junk"),
        FilterResponse::Reject { code, message } => {
            protocol::format_filter_result(reqid, token, &format!("reject|{code} {message}"))
        }
        FilterResponse::RejectEnhanced {
            code,
            class,
            subject,
            detail,
            message,
        } => protocol::format_filter_result(
            reqid,
            token,
            &format!("reject|{code} {class}.{subject}.{detail} {message}"),
        ),
        FilterResponse::Disconnect { code, message } => {
            protocol::format_filter_result(reqid, token, &format!("disconnect|{code} {message}"))
        }
        FilterResponse::DisconnectEnhanced {
            code,
            class,
            subject,
            detail,
            message,
        } => protocol::format_filter_result(
            reqid,
            token,
            &format!("disconnect|{code} {class}.{subject}.{detail} {message}"),
        ),
        FilterResponse::Rewrite(value) => {
            protocol::format_filter_result(reqid, token, &format!("rewrite|{value}"))
        }
        FilterResponse::DataLine(_) => {
            return Err(ParseError(
                "DataLine response should not be used here".into(),
            ));
        }
    };
    out.write_all(msg.as_bytes())
        .map_err(|e| ParseError(format!("write error: {e}")))?;
    Ok(())
}

fn parse_filter_connect(params: &str) -> Result<(String, Status, Address, Address), ParseError> {
    let mut parts = params.splitn(4, '|');
    let rdns = parts
        .next()
        .ok_or_else(|| ParseError("missing rdns in connect".into()))?;
    let fcrdns_str = parts
        .next()
        .ok_or_else(|| ParseError("missing fcrdns in connect".into()))?;
    let src_str = parts
        .next()
        .ok_or_else(|| ParseError("missing src in connect".into()))?;
    let dst_str = parts
        .next()
        .ok_or_else(|| ParseError("missing dst in connect".into()))?;

    let fcrdns = Status::from_str(fcrdns_str)
        .ok_or_else(|| ParseError(format!("invalid fcrdns: {fcrdns_str}")))?;
    let src = protocol::parse_address(src_str, true)?;
    let dst = protocol::parse_address(dst_str, true)?;

    Ok((rdns.to_string(), fcrdns, src, dst))
}

fn parse_report_link_connect(
    params: &str,
) -> Result<(String, Status, Address, Address), ParseError> {
    let mut parts = params.splitn(4, '|');
    let rdns = parts
        .next()
        .ok_or_else(|| ParseError("missing rdns".into()))?;
    let fcrdns_str = parts
        .next()
        .ok_or_else(|| ParseError("missing fcrdns".into()))?;
    let src_str = parts
        .next()
        .ok_or_else(|| ParseError("missing src".into()))?;
    let dst_str = parts
        .next()
        .ok_or_else(|| ParseError("missing dst".into()))?;

    let fcrdns =
        Status::from_str(fcrdns_str).ok_or_else(|| ParseError(format!("invalid fcrdns: {fcrdns_str}")))?;
    let src = protocol::parse_address(src_str, true)?;
    let dst = protocol::parse_address(dst_str, true)?;

    Ok((rdns.to_string(), fcrdns, src, dst))
}

fn parse_report_link_auth(params: &str) -> Result<(String, AuthStatus), ParseError> {
    let pos = params
        .rfind('|')
        .ok_or_else(|| ParseError("missing auth status".into()))?;
    let username = &params[..pos];
    let status_str = &params[pos + 1..];
    let status = AuthStatus::from_str(status_str)
        .ok_or_else(|| ParseError(format!("invalid auth status: {status_str}")))?;
    Ok((username.to_string(), status))
}

fn parse_msgid(params: &str) -> Result<u32, ParseError> {
    u32::from_str_radix(params.trim(), 16).map_err(|e| ParseError(format!("invalid msgid: {e}")))
}

fn parse_report_tx_mail(
    params: &str,
    version_minor: u32,
) -> Result<(u32, String, Status), ParseError> {
    let (msgid_str, rest) = params
        .split_once('|')
        .ok_or_else(|| ParseError("missing address in tx-mail".into()))?;
    let msgid =
        u32::from_str_radix(msgid_str, 16).map_err(|e| ParseError(format!("invalid msgid: {e}")))?;

    let (first, second) = rest
        .split_once('|')
        .ok_or_else(|| ParseError("missing status in tx-mail".into()))?;

    let (address, status) = if version_minor < 6 {
        let s = Status::from_str(second)
            .ok_or_else(|| ParseError(format!("invalid status: {second}")))?;
        (first.to_string(), s)
    } else {
        let s = Status::from_str(first)
            .ok_or_else(|| ParseError(format!("invalid status: {first}")))?;
        (second.to_string(), s)
    };

    Ok((msgid, address, status))
}

fn parse_report_tx_rcpt(
    params: &str,
    version_minor: u32,
) -> Result<(u32, String, Status), ParseError> {
    parse_report_tx_mail(params, version_minor)
}

fn parse_report_tx_envelope(params: &str) -> Result<(u32, u64), ParseError> {
    let (msgid_str, evpid_str) = params
        .split_once('|')
        .ok_or_else(|| ParseError("missing evpid in tx-envelope".into()))?;
    let msgid =
        u32::from_str_radix(msgid_str, 16).map_err(|e| ParseError(format!("invalid msgid: {e}")))?;
    let evpid = u64::from_str_radix(evpid_str, 16)
        .map_err(|e| ParseError(format!("invalid evpid: {e}")))?;
    Ok((msgid, evpid))
}

fn parse_report_tx_data(params: &str) -> Result<(u32, Status), ParseError> {
    let (msgid_str, status_str) = params
        .split_once('|')
        .ok_or_else(|| ParseError("missing status in tx-data".into()))?;
    let msgid =
        u32::from_str_radix(msgid_str, 16).map_err(|e| ParseError(format!("invalid msgid: {e}")))?;
    let status = Status::from_str(status_str)
        .ok_or_else(|| ParseError(format!("invalid status: {status_str}")))?;
    Ok((msgid, status))
}

fn parse_report_tx_commit(params: &str) -> Result<(u32, usize), ParseError> {
    let (msgid_str, size_str) = params
        .split_once('|')
        .ok_or_else(|| ParseError("missing size in tx-commit".into()))?;
    let msgid =
        u32::from_str_radix(msgid_str, 16).map_err(|e| ParseError(format!("invalid msgid: {e}")))?;
    let msg_size: usize = size_str
        .parse()
        .map_err(|e| ParseError(format!("invalid msg size: {e}")))?;
    Ok((msgid, msg_size))
}

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

use std::net::SocketAddr;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterKind {
    Filter,
    Report,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Connect,
    Helo,
    Ehlo,
    StartTls,
    Auth,
    MailFrom,
    RcptTo,
    Data,
    DataLine,
    Reset,
    Quit,
    Noop,
    Help,
    Wiz,
    Commit,
    LinkConnect,
    LinkDisconnect,
    LinkGreeting,
    LinkIdentify,
    LinkTls,
    LinkAuth,
    TxBegin,
    TxMail,
    TxRcpt,
    TxEnvelope,
    TxData,
    TxCommit,
    TxRollback,
    ProtocolClient,
    ProtocolServer,
    FilterResponse,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    TempFail,
    PermFail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStatus {
    Pass,
    Fail,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Incoming,
    Outgoing,
}

#[derive(Debug, Clone)]
pub enum Address {
    Ip(SocketAddr),
    Unix(String),
}

#[derive(Debug)]
pub struct Session {
    pub reqid: u64,
    pub src: Option<Address>,
    pub dst: Option<Address>,
    pub rdns: Option<String>,
    pub fcrdns: Status,
    pub identity: Option<String>,
    pub greeting: Option<String>,
    pub ciphers: Option<String>,
    pub msgid: Option<u32>,
    pub username: Option<String>,
    pub mailfrom: Option<String>,
    pub rcptto: Vec<String>,
    pub evpid: Option<u64>,
    pub local_session: Option<Box<dyn std::any::Any>>,
    pub local_message: Option<Box<dyn std::any::Any>>,
}

impl Session {
    pub(crate) fn new(reqid: u64) -> Self {
        Session {
            reqid,
            src: None,
            dst: None,
            rdns: None,
            fcrdns: Status::TempFail,
            identity: None,
            greeting: None,
            ciphers: None,
            msgid: None,
            username: None,
            mailfrom: None,
            rcptto: Vec::new(),
            evpid: None,
            local_session: None,
            local_message: None,
        }
    }

    pub(crate) fn clear_transaction(&mut self) {
        self.mailfrom = None;
        self.rcptto.clear();
        self.evpid = None;
        self.msgid = None;
        self.local_message = None;
    }
}

#[derive(Debug, Clone)]
pub struct Event {
    pub kind: FilterKind,
    pub phase: Phase,
    pub version_major: u32,
    pub version_minor: u32,
    pub timestamp: SystemTime,
    pub direction: Direction,
    pub reqid: u64,
    pub token: Option<u64>,
}

impl Phase {
    pub fn from_str(s: &str) -> Option<Phase> {
        match s {
            "connect" => Some(Phase::Connect),
            "helo" => Some(Phase::Helo),
            "ehlo" => Some(Phase::Ehlo),
            "starttls" => Some(Phase::StartTls),
            "auth" => Some(Phase::Auth),
            "mail-from" => Some(Phase::MailFrom),
            "rcpt-to" => Some(Phase::RcptTo),
            "data" => Some(Phase::Data),
            "data-line" => Some(Phase::DataLine),
            "rset" => Some(Phase::Reset),
            "quit" => Some(Phase::Quit),
            "noop" => Some(Phase::Noop),
            "help" => Some(Phase::Help),
            "wiz" => Some(Phase::Wiz),
            "commit" => Some(Phase::Commit),
            "link-connect" => Some(Phase::LinkConnect),
            "link-disconnect" => Some(Phase::LinkDisconnect),
            "link-greeting" => Some(Phase::LinkGreeting),
            "link-identify" => Some(Phase::LinkIdentify),
            "link-tls" => Some(Phase::LinkTls),
            "link-auth" => Some(Phase::LinkAuth),
            "tx-begin" => Some(Phase::TxBegin),
            "tx-mail" => Some(Phase::TxMail),
            "tx-rcpt" => Some(Phase::TxRcpt),
            "tx-envelope" => Some(Phase::TxEnvelope),
            "tx-data" => Some(Phase::TxData),
            "tx-commit" => Some(Phase::TxCommit),
            "tx-rollback" => Some(Phase::TxRollback),
            "protocol-client" => Some(Phase::ProtocolClient),
            "protocol-server" => Some(Phase::ProtocolServer),
            "filter-response" => Some(Phase::FilterResponse),
            "timeout" => Some(Phase::Timeout),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Phase::Connect => "connect",
            Phase::Helo => "helo",
            Phase::Ehlo => "ehlo",
            Phase::StartTls => "starttls",
            Phase::Auth => "auth",
            Phase::MailFrom => "mail-from",
            Phase::RcptTo => "rcpt-to",
            Phase::Data => "data",
            Phase::DataLine => "data-line",
            Phase::Reset => "rset",
            Phase::Quit => "quit",
            Phase::Noop => "noop",
            Phase::Help => "help",
            Phase::Wiz => "wiz",
            Phase::Commit => "commit",
            Phase::LinkConnect => "link-connect",
            Phase::LinkDisconnect => "link-disconnect",
            Phase::LinkGreeting => "link-greeting",
            Phase::LinkIdentify => "link-identify",
            Phase::LinkTls => "link-tls",
            Phase::LinkAuth => "link-auth",
            Phase::TxBegin => "tx-begin",
            Phase::TxMail => "tx-mail",
            Phase::TxRcpt => "tx-rcpt",
            Phase::TxEnvelope => "tx-envelope",
            Phase::TxData => "tx-data",
            Phase::TxCommit => "tx-commit",
            Phase::TxRollback => "tx-rollback",
            Phase::ProtocolClient => "protocol-client",
            Phase::ProtocolServer => "protocol-server",
            Phase::FilterResponse => "filter-response",
            Phase::Timeout => "timeout",
        }
    }
}

impl Status {
    pub fn from_str(s: &str) -> Option<Status> {
        match s {
            "ok" | "pass" => Some(Status::Ok),
            "tempfail" | "error" => Some(Status::TempFail),
            "permfail" | "fail" => Some(Status::PermFail),
            _ => None,
        }
    }
}

impl AuthStatus {
    pub fn from_str(s: &str) -> Option<AuthStatus> {
        match s {
            "pass" => Some(AuthStatus::Pass),
            "fail" => Some(AuthStatus::Fail),
            "error" => Some(AuthStatus::Error),
            _ => None,
        }
    }
}

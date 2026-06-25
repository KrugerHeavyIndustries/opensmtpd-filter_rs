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

use crate::types::{Address, AuthStatus, Direction, Session, Status};

pub enum FilterResponse {
    Proceed,
    Reject { code: u16, message: String },
    RejectEnhanced {
        code: u16,
        class: u8,
        subject: u16,
        detail: u16,
        message: String,
    },
    Disconnect { message: String },
    DisconnectEnhanced {
        class: u8,
        subject: u16,
        detail: u16,
        message: String,
    },
    Rewrite(String),
    DataLine(String),
}

#[allow(unused_variables)]
pub trait Filter {
    fn on_filter_connect(
        &mut self,
        session: &Session,
        rdns: &str,
        fcrdns: Status,
        src: &Address,
        dst: &Address,
    ) -> FilterResponse {
        FilterResponse::Proceed
    }

    fn on_filter_helo(&mut self, session: &Session, identity: &str) -> FilterResponse {
        FilterResponse::Proceed
    }

    fn on_filter_ehlo(&mut self, session: &Session, identity: &str) -> FilterResponse {
        FilterResponse::Proceed
    }

    fn on_filter_starttls(&mut self, session: &Session) -> FilterResponse {
        FilterResponse::Proceed
    }

    fn on_filter_auth(&mut self, session: &Session, auth: &str) -> FilterResponse {
        FilterResponse::Proceed
    }

    fn on_filter_mail_from(&mut self, session: &Session, from: &str) -> FilterResponse {
        FilterResponse::Proceed
    }

    fn on_filter_rcpt_to(&mut self, session: &Session, to: &str) -> FilterResponse {
        FilterResponse::Proceed
    }

    fn on_filter_data(&mut self, session: &Session) -> FilterResponse {
        FilterResponse::Proceed
    }

    fn on_filter_data_line(&mut self, session: &Session, line: &str) -> Vec<String> {
        vec![line.to_string()]
    }

    fn on_filter_rset(&mut self, session: &Session) -> FilterResponse {
        FilterResponse::Proceed
    }

    fn on_filter_quit(&mut self, session: &Session) -> FilterResponse {
        FilterResponse::Proceed
    }

    fn on_filter_noop(&mut self, session: &Session) -> FilterResponse {
        FilterResponse::Proceed
    }

    fn on_filter_help(&mut self, session: &Session) -> FilterResponse {
        FilterResponse::Proceed
    }

    fn on_filter_wiz(&mut self, session: &Session) -> FilterResponse {
        FilterResponse::Proceed
    }

    fn on_filter_commit(&mut self, session: &Session) -> FilterResponse {
        FilterResponse::Proceed
    }

    fn on_report_link_connect(
        &mut self,
        session: &Session,
        direction: Direction,
        rdns: &str,
        fcrdns: Status,
        src: &Address,
        dst: &Address,
    ) {
    }

    fn on_report_link_disconnect(&mut self, session: &Session, direction: Direction) {}

    fn on_report_link_greeting(
        &mut self,
        session: &Session,
        direction: Direction,
        hostname: &str,
    ) {
    }

    fn on_report_link_identify(
        &mut self,
        session: &Session,
        direction: Direction,
        identity: &str,
    ) {
    }

    fn on_report_link_tls(&mut self, session: &Session, direction: Direction, ciphers: &str) {}

    fn on_report_link_auth(
        &mut self,
        session: &Session,
        direction: Direction,
        username: &str,
        result: AuthStatus,
    ) {
    }

    fn on_report_tx_begin(&mut self, session: &Session, direction: Direction, msgid: u32) {}

    fn on_report_tx_mail(
        &mut self,
        session: &Session,
        direction: Direction,
        msgid: u32,
        from: &str,
        status: Status,
    ) {
    }

    fn on_report_tx_rcpt(
        &mut self,
        session: &Session,
        direction: Direction,
        msgid: u32,
        to: &str,
        status: Status,
    ) {
    }

    fn on_report_tx_envelope(
        &mut self,
        session: &Session,
        direction: Direction,
        msgid: u32,
        evpid: u64,
    ) {
    }

    fn on_report_tx_data(
        &mut self,
        session: &Session,
        direction: Direction,
        msgid: u32,
        status: Status,
    ) {
    }

    fn on_report_tx_commit(
        &mut self,
        session: &Session,
        direction: Direction,
        msgid: u32,
        msg_size: usize,
    ) {
    }

    fn on_report_tx_rollback(&mut self, session: &Session, direction: Direction, msgid: u32) {}

    fn on_report_protocol_client(
        &mut self,
        session: &Session,
        direction: Direction,
        command: &str,
    ) {
    }

    fn on_report_protocol_server(
        &mut self,
        session: &Session,
        direction: Direction,
        response: &str,
    ) {
    }

    fn on_report_filter_response(
        &mut self,
        session: &Session,
        direction: Direction,
        response: &str,
    ) {
    }

    fn on_report_timeout(&mut self, session: &Session, direction: Direction) {}

    fn on_config(&mut self, key: &str, value: &str) {}

    fn on_config_ready(&mut self) {}
}

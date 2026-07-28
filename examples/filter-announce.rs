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

use opensmtpd_filter::{
    AuthStatus, Status, Address, Direction, Filter, FilterResponse, Session, SmtpFilterRunner, 
};

struct AnnounceFilter;

impl Filter for AnnounceFilter {
    fn on_report_link_connect(
        &mut self,
        session: &Session,
        _direction: Direction,
        rdns: &str,
        fcrdns: Status,
        src: &Address,
        dst: &Address,
    ) {
        eprintln!(
            "{:x}: link-connect: {}|{:?}|{:?}|{:?}",
            session.reqid, rdns, fcrdns, src, dst
        );
    }

    fn on_report_link_disconnect(
        &mut self,
        session: &Session,
        _direction: Direction
    ) {
        eprintln!(
            "{:x}: link-disconnect",
            session.reqid
        );
    }

    fn on_report_link_greeting(
        &mut self,
        session: &Session,
        _direction: Direction,
        hostname: &str
    ) {
        eprintln!(
            "{:x}: link-greeting: {}",
            session.reqid, hostname
        )
    }

    fn on_report_link_identify(
        &mut self,
        session: &Session,
        _direction: Direction,
        identity: &str,
    ) {
        eprintln!(
            "{:x}: link-identify: {}",
            session.reqid, identity
        )
    }

    fn on_report_link_auth(
        &mut self,
        session: &Session,
        _direction: Direction,
        username: &str,
        result: AuthStatus,
    ) {
        eprintln!(
            "{:x}: link-auth: {:?}|{}",
            session.reqid, result, username
        )
    }

    fn on_report_link_tls(
        &mut self,
        session: &Session,
        _direction: Direction,
        ciphers: &str
    ) {
        eprintln!(
            "{:x}: link-tls: {}",
            session.reqid, ciphers
        )
    }


    fn on_report_tx_begin(
        &mut self, session: &Session,
        _direction: Direction,
        msgid: u32
    ) {
        eprintln!(
            "{:x}: tx-begin: {}",
            session.reqid, msgid
        )
    }

    fn on_report_tx_mail(
        &mut self,
        session: &Session,
        _direction: Direction,
        msgid: u32,
        from: &str,
        status: Status,
    ) {
        eprintln!(
            "{:x}: tx-mail: {}|{:?}|{}",
            session.reqid, msgid, status, from
        )
    }

    fn on_report_tx_rcpt(
        &mut self,
        session: &Session,
        _direction: Direction,
        msgid: u32,
        to: &str,
        status: Status,
    ) {
        eprintln!(
            "{:x}: tx-rcpt: {}|{:?}|{}",
            session.reqid, msgid, status, to
        )
    }

    fn on_report_tx_envelope(
        &mut self,
        session: &Session,
        _direction: Direction,
        msgid: u32,
        evpid: u64,
    ) {
        eprintln!(
            "{:x}: tx-envelope: {}|{}",
            session.reqid, msgid, evpid
        )
    }

    fn on_report_tx_data(
        &mut self,
        session: &Session,
        _direction: Direction,
        msgid: u32,
        status: Status,
    ) {
        eprintln!(
            "{:x}: tx-data: {}|{:?}",
            session.reqid, msgid, status
        )
    }

    fn on_report_tx_commit(
        &mut self,
        session: &Session,
        _direction: Direction,
        msgid: u32,
        msg_size: usize,
    ) {
        eprintln!(
            "{:x}: tx-commit: {}|{}",
            session.reqid, msgid, msg_size
        )
    }

    fn on_report_tx_rollback(
        &mut self,
        session: &Session,
        _direction: Direction,
        msgid: u32
    ) {
        eprintln!(
            "{:x}: tx-rollback: {}",
            session.reqid, msgid
        )
    }

    fn on_report_protocol_client(
        &mut self,
        session: &Session,
        _direction: Direction,
        command: &str,
    ) {
        eprintln!(
            "{:x}: protocol-client: {}",
            session.reqid, command
        )
    }

    fn on_report_protocol_server(
        &mut self,
        session: &Session,
        _direction: Direction,
        response: &str,
    ) {
        eprintln!(
            "{:x}: protocol-server: {}",
            session.reqid, response
        )
    }

    fn on_report_filter_response(
        &mut self,
        session: &Session,
        _direction: Direction,
        response: &str,
    ) {
        eprintln!(
            "{:x}: filter-response: {}",
            session.reqid, response
        )
    }

    fn on_report_timeout(
        &mut self,
        session: &Session,
        _direction: Direction
    ) {
        eprintln!(
            "{:x}: timeout",
            session.reqid
        )
    }

    fn on_filter_connect(
        &mut self,
        session: &Session,
        rdns: &str,
        _fcrdns: Status,
        src: &Address,
        dst: &Address,
    ) -> FilterResponse {
        eprintln!(
            "{:x}: filter-connect: {}|{:?}{:?}",
            session.reqid, rdns, src, dst
        );
        FilterResponse::Proceed
    }

    fn on_filter_helo(
        &mut self,
        session: &Session,
        identity: &str
    ) -> FilterResponse {
        eprintln!(
            "{:x}: filter-helo: {}",
            session.reqid, identity
        );
        FilterResponse::Proceed
    }

    fn on_filter_ehlo(
        &mut self,
        session: &Session,
        identity: &str
    ) -> FilterResponse {
        eprintln!(
            "{:x}: filter-ehlo: {}",
            session.reqid, identity
        );
        FilterResponse::Proceed
    }

    fn on_filter_starttls(
        &mut self,
        session: &Session
    ) -> FilterResponse {
        eprintln!(
            "{:x}: filter-starttls",
            session.reqid
        );
        FilterResponse::Proceed
    }

    fn on_filter_auth(
        &mut self,
        session: &Session,
        auth: &str
    ) -> FilterResponse {
        eprintln!(
            "{:x}: filter-auth: {}",
            session.reqid, auth
        );
        FilterResponse::Proceed
    }

    fn on_filter_mail_from(
        &mut self,
        session: &Session,
        from: &str
    ) -> FilterResponse {
        eprintln!(
            "{:x}: filter-mail-from: {}",
            session.reqid, from
        );
        FilterResponse::Proceed
    }

    fn on_filter_rcpt_to(&mut self, session: &Session, to: &str) -> FilterResponse {
        eprintln!(
            "{:x}: filter-rcpt-to: {}",
            session.reqid, to 
        );
        FilterResponse::Proceed
    }

    fn on_filter_data(&mut self, session: &Session) -> FilterResponse {
        eprintln!(
            "{:x}: filter-data",
            session.reqid
        );
        FilterResponse::Proceed
    }

    fn on_filter_commit(
        &mut self, 
        session: &Session
    ) -> FilterResponse {
        eprintln!(
            "{:x}: filter-commit",
            session.reqid
        );
        FilterResponse::Proceed
    }

    fn on_filter_data_line(
        &mut self, 
        session: &Session,
        line: &str
    ) -> Vec<String> {
        eprintln!(
            "{:x}: filter-data-line: {}",
            session.reqid, line
        );
        vec![line.to_string()]
    }

    fn on_filter_noop(
        &mut self,
        session: &Session
    ) -> FilterResponse {
        eprintln!(
            "{:x}: filter-noop",
            session.reqid
        );
        FilterResponse::Proceed
    }

    fn on_filter_reset(
        &mut self,
        session: &Session
    ) -> FilterResponse {
        eprintln!(
            "{:x}: filter-rset",
            session.reqid
        );
        FilterResponse::Proceed
    }

    fn on_filter_help(
        &mut self,
        session: &Session
    ) -> FilterResponse {
        eprintln!(
            "{:x}: filter-help",
            session.reqid
        );
        FilterResponse::Proceed
    }

    fn on_filter_wiz(
        &mut self,
        session: &Session
    ) -> FilterResponse {
        eprintln!(
            "{:x}: filter-wiz",
            session.reqid
        );
        FilterResponse::Proceed
    }

    fn on_filter_quit(
        &mut self,
        session: &Session
    ) -> FilterResponse {
        eprintln!(
            "{:x}: filter-quit",
            session.reqid
        );
        FilterResponse::Proceed
    }
}

fn main() -> std::process::ExitCode {
    let filter = AnnounceFilter;
    let mut runner = SmtpFilterRunner::new(filter);
    runner
        .register_filter_auth()
        .register_filter_connect()
        .register_filter_connect()
        .register_filter_data()
        .register_filter_data_line()
        .register_filter_ehlo()
        .register_filter_helo()
        .register_filter_mail_from()
        .register_filter_quit()
        .register_filter_rcpt_to()
        .register_filter_starttls()
        .register_filter_reset()
        .register_report_connect(Direction::Incoming)
        .register_report_disconnect(Direction::Incoming)
        .register_report_protocol_client(Direction::Incoming)
        .register_report_protocol_server(Direction::Incoming);

    runner.run()
}

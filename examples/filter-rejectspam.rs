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
    Direction, Filter, FilterResponse, Session, SmtpFilterRunner,
};

struct SpamFilter;

impl Filter for SpamFilter {
    fn on_filter_mail_from(&mut self, _session: &Session, from: &str) -> FilterResponse {
        if from.contains("spammer.example.com") {
            FilterResponse::Reject {
                code: 550,
                message: "Rejected".to_string(),
            }
        } else {
            FilterResponse::Proceed
        }
    }

    fn on_filter_data_line(&mut self, _session: &Session, line: &str) -> Vec<String> {
        // Add a header to all messages
        if line == "." {
            vec![
                "X-Filtered-By: opensmtpd-filter-rs".to_string(),
                ".".to_string(),
            ]
        } else {
            vec![line.to_string()]
        }
    }

    fn on_report_link_connect(
        &mut self,
        session: &Session,
        _direction: Direction,
        rdns: &str,
        _fcrdns: opensmtpd_filter::Status,
        _src: &opensmtpd_filter::Address,
        _dst: &opensmtpd_filter::Address,
    ) {
        eprintln!(
            "New connection: reqid={:016x} rdns={}",
            session.reqid, rdns
        );
    }
}

fn main() -> std::process::ExitCode {
    let filter = SpamFilter;
    let mut runner = SmtpFilterRunner::new(filter);
    runner
        .register_filter_mail_from()
        .register_filter_data_line()
        .register_report_connect(Direction::Incoming);

    runner.run()
}

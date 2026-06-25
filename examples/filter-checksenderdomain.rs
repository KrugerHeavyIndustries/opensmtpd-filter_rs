use opensmtpd_filter::{
    Direction, Filter, FilterResponse, Session, SmtpFilterRunner,
};
use std::net::ToSocketAddrs;

struct CheckSenderDomainFilter;

impl Filter for CheckSenderDomainFilter {
    fn on_filter_mail_from(&mut self, _session: &Session, from: &str) -> FilterResponse {
        let domain = match from.rsplit_once('@') {
            Some((_, domain)) => domain,
            None => return FilterResponse::Proceed,
        };

        if format!("{}:443", domain).to_socket_addrs().is_err() {
            FilterResponse::Reject {
                code: 550,
                message: "unknown sender domain".to_string(),
            }
        } else {
            FilterResponse::Proceed
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
    let filter = CheckSenderDomainFilter;
    let mut runner = SmtpFilterRunner::new(filter);
    runner
        .register_filter_mail_from()
        .register_report_connect(Direction::Incoming);

    runner.run()
}

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

fn main() {
    let filter = SpamFilter;
    let mut runner = SmtpFilterRunner::new(filter);
    runner
        .register_filter_mail_from()
        .register_filter_data_line()
        .register_report_connect(Direction::Incoming);

    runner.run().expect("filter crashed");
}

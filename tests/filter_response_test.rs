use std::io::Cursor;

use opensmtpd_filter::{
    Address, Filter, FilterResponse, Session, SmtpFilterRunner, Status,
};

struct JunkFilter;

impl Filter for JunkFilter {
    fn on_filter_connect(
        &mut self,
        _session: &Session,
        _rdns: &str,
        _fcrdns: Status,
        _src: &Address,
        _dst: &Address,
    ) -> FilterResponse {
        FilterResponse::Junk
    }
}

struct DisconnectFilter {
    code: u16,
    message: String,
}

impl Filter for DisconnectFilter {
    fn on_filter_connect(
        &mut self,
        _session: &Session,
        _rdns: &str,
        _fcrdns: Status,
        _src: &Address,
        _dst: &Address,
    ) -> FilterResponse {
        FilterResponse::Disconnect {
            code: self.code,
            message: self.message.clone(),
        }
    }
}

const CONNECT_LINE: &str =
    "filter|0.7|1234567890.123456789|smtp-in|connect|abc123|def456|mail.example.com|pass|192.168.1.1:25|0.0.0.0:25\n";

fn run_filter(runner: &mut SmtpFilterRunner<impl Filter>, input: &str) -> String {
    let mut output = Vec::new();
    runner
        .run_with(Cursor::new(input.as_bytes()), &mut output)
        .unwrap();
    String::from_utf8(output).unwrap()
}

#[test]
fn test_junk_response() {
    let input = format!("config|ready\n{CONNECT_LINE}");
    let mut runner = SmtpFilterRunner::new(JunkFilter);
    runner.register_filter_connect();

    let output = run_filter(&mut runner, &input);
    let result_line = output.lines().find(|l| l.starts_with("filter-result|")).unwrap();

    assert!(
        result_line.ends_with("|junk"),
        "expected junk response, got: {result_line}"
    );
}

#[test]
fn test_disconnect_with_550() {
    let filter = DisconnectFilter {
        code: 550,
        message: "your IP reputation is too low for this MX".into(),
    };
    let input = format!("config|ready\n{CONNECT_LINE}");
    let mut runner = SmtpFilterRunner::new(filter);
    runner.register_filter_connect();

    let output = run_filter(&mut runner, &input);
    let result_line = output.lines().find(|l| l.starts_with("filter-result|")).unwrap();

    assert!(
        result_line.ends_with("|disconnect|550 your IP reputation is too low for this MX"),
        "expected disconnect with 550, got: {result_line}"
    );
}

#[test]
fn test_disconnect_with_421() {
    let filter = DisconnectFilter {
        code: 421,
        message: "service not available".into(),
    };
    let input = format!("config|ready\n{CONNECT_LINE}");
    let mut runner = SmtpFilterRunner::new(filter);
    runner.register_filter_connect();

    let output = run_filter(&mut runner, &input);
    let result_line = output.lines().find(|l| l.starts_with("filter-result|")).unwrap();

    assert!(
        result_line.ends_with("|disconnect|421 service not available"),
        "expected disconnect with 421, got: {result_line}"
    );
}

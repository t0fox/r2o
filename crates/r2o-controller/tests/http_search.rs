use r2o_controller::http_search::{
    Answer, D2K_HS_CANDS_MAX, add_candidate, candidate_key_from_plan_text, candidate_keys,
    candidate_text, judge, known_key, read_probe_response, stable_id,
};
use std::io::{self, Cursor, Read};
use std::time::{Duration, Instant};

const INJECTED: &[u8] = b"HTTP/1.1 302 Moved Temporarily\r\nLocation: http://lawfilter.ertelecom.ru\r\nConnection: close\r\nContent-Length: 13\r\n\r\nlawfilter.ru\n";
const REAL: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
const ID: [u8; 16] = [1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

struct TimeoutReader {
    bytes: Cursor<Vec<u8>>,
}

impl TimeoutReader {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: Cursor::new(bytes.to_vec()),
        }
    }
}

impl Read for TimeoutReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = self.bytes.read(out)?;
        if count == 0 {
            Err(io::Error::new(io::ErrorKind::TimedOut, "fixture timeout"))
        } else {
            Ok(count)
        }
    }
}

/// C-фикстура сравнивает `rtt_us=98000`, `reply_us=99000`: отправка была
/// примерно на 99 мс раньше, иначе настоящий `Instant` даёт EARLY.
fn donor_request_sent() -> Instant {
    Instant::now() - Duration::from_millis(99)
}

fn answer_name(answer: Answer) -> &'static str {
    match answer {
        Answer::Injected => "injected",
        Answer::Garbage => "garbage",
        Answer::Cut => "cut",
        Answer::Early => "early",
        Answer::Decoy => "decoy",
        Answer::Real => "real",
    }
}

#[test]
fn d2o_response_state_differential_preserves_portal_and_partial_head_outcomes() {
    const PORTAL_TRUNCATED: &[u8] = b"HTTP/1.1 302 Moved Temporarily\r\nLocation: http://lawfilter.ertelecom.ru/\r\nContent-Length: 100\r\n\r\nshort";
    const PARTIAL_HEAD: &[u8] =
        b"HTTP/1.1 302 Moved Temporarily\r\nLocation: http://lawfilter.ertelecom.ru";
    const BLOCKED_BODY: &[u8] =
        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 21\r\n\r\naccess blocked by rkn";
    const PORTAL_BODY: &[u8] =
        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 15\r\n\r\neais.rkn.gov.ru";
    const GZIP_BODY: &[u8] = b"HTTP/1.1 403 Forbidden\r\nContent-Encoding: gzip\r\nContent-Length: 21\r\n\r\naccess blocked by rkn";
    const UPGRADE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n";
    const INVALID_FRAMING: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Length: 1 2\r\nConnection: close\r\n\r\n";
    const BODY_DECOY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nsee disk.rzd.ru";

    let mut portal_reader = TimeoutReader::new(PORTAL_TRUNCATED);
    let portal = read_probe_response(
        &mut portal_reader,
        Some(b"rutracker.org"),
        98_000,
        donor_request_sent(),
    )
    .unwrap();
    let mut partial_reader = TimeoutReader::new(PARTIAL_HEAD);
    let partial = match read_probe_response(
        &mut partial_reader,
        Some(b"rutracker.org"),
        98_000,
        donor_request_sent(),
    ) {
        Ok(response) => answer_name(response.answer),
        Err(error) if error.kind() == io::ErrorKind::TimedOut => "timeout",
        Err(_) => "error",
    };
    let mut blocked_reader = TimeoutReader::new(BLOCKED_BODY);
    let blocked = read_probe_response(
        &mut blocked_reader,
        Some(b"rutracker.org"),
        98_000,
        donor_request_sent(),
    )
    .unwrap();
    let mut portal_body_reader = TimeoutReader::new(PORTAL_BODY);
    let portal_body = read_probe_response(
        &mut portal_body_reader,
        Some(b"rutracker.org"),
        98_000,
        donor_request_sent(),
    )
    .unwrap();
    let mut gzip_reader = TimeoutReader::new(GZIP_BODY);
    let gzip = read_probe_response(
        &mut gzip_reader,
        Some(b"rutracker.org"),
        98_000,
        donor_request_sent(),
    )
    .unwrap();
    let mut upgrade_reader = TimeoutReader::new(UPGRADE);
    let upgrade = read_probe_response(
        &mut upgrade_reader,
        Some(b"rutracker.org"),
        98_000,
        donor_request_sent(),
    )
    .unwrap();
    let mut invalid_reader = TimeoutReader::new(INVALID_FRAMING);
    let invalid = read_probe_response(
        &mut invalid_reader,
        Some(b"rutracker.org"),
        98_000,
        donor_request_sent(),
    )
    .unwrap();
    let mut decoy_reader = TimeoutReader::new(BODY_DECOY);
    let body_decoy = read_probe_response(
        &mut decoy_reader,
        Some(b"rutracker.org"),
        98_000,
        donor_request_sent(),
    )
    .unwrap();
    let output = format!(
        "portal_truncated={}\npartial_header_timeout={}\nblocked_body={}/{}\nportal_body={}/{}\ngzip_body={}/{}\nupgrade={}/{}\ninvalid_framing={}/{}\nbody_decoy={}/{}\n",
        answer_name(portal.answer),
        partial,
        answer_name(blocked.answer),
        u8::from(blocked.complete),
        answer_name(portal_body.answer),
        u8::from(portal_body.complete),
        answer_name(gzip.answer),
        u8::from(gzip.complete),
        answer_name(upgrade.answer),
        u8::from(upgrade.complete),
        answer_name(invalid.answer),
        u8::from(invalid.complete),
        answer_name(body_decoy.answer),
        u8::from(body_decoy.complete),
    );
    if let Ok(path) = std::env::var("R2O_HTTP_RESPONSE_DIFF_OUTPUT") {
        std::fs::write(path, &output).unwrap();
    }

    assert_eq!(
        output,
        "portal_truncated=injected\npartial_header_timeout=garbage\nblocked_body=injected/1\nportal_body=injected/1\ngzip_body=real/1\nupgrade=cut/0\ninvalid_framing=cut/0\nbody_decoy=decoy/1\n"
    );
    assert!(!portal.complete);
}

#[test]
fn identifies_explicit_provider_portal_redirects_before_timing_rules() {
    assert_eq!(
        judge(Some(b"rutracker.org"), INJECTED, 98_000, 120_000),
        Answer::Injected
    );
}

#[test]
fn classifies_a_complete_http_response_as_real_at_or_after_half_rtt() {
    assert_eq!(
        judge(Some(b"rutracker.org"), REAL, 98_000, 49_000),
        Answer::Real
    );
    assert_eq!(
        judge(Some(b"rutracker.org"), REAL, 98_000, 49_001),
        Answer::Real
    );
}

#[test]
fn classifies_a_response_before_half_rtt_as_early() {
    assert_eq!(
        judge(Some(b"rutracker.org"), REAL, 98_000, 1_000),
        Answer::Early
    );
}

#[test]
fn treats_cloudflare_challenge_header_like_any_other_server_response() {
    let challenge =
        b"HTTP/1.1 403 Forbidden\r\ncf-mitigated: challenge\r\nContent-Length: 0\r\n\r\n";
    let ordinary_forbidden = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";

    assert_eq!(
        judge(Some(b"rutracker.org"), challenge, 98_000, 99_000),
        Answer::Real
    );
    assert_eq!(
        judge(Some(b"rutracker.org"), ordinary_forbidden, 98_000, 99_000),
        Answer::Real
    );
}

#[test]
fn reads_the_body_of_a_cloudflare_challenge_response_and_reports_cut() {
    let response_head =
        b"HTTP/1.1 403 Forbidden\r\ncf-mitigated: challenge\r\nContent-Length: 100\r\n\r\n";
    let response = [response_head.as_slice(), b"captcha"].concat();
    let mut reader = Cursor::new(response.as_slice());
    let result = read_probe_response(
        &mut reader,
        Some(b"rutracker.org"),
        98_000,
        donor_request_sent(),
    )
    .unwrap();

    assert_eq!(result.answer, Answer::Cut);
    assert!(!result.complete);
    assert_eq!(result.body_bytes, 7);
    assert_eq!(reader.position() as usize, response.len());
}

#[test]
fn accepts_a_server_redirect_to_its_own_https_name_as_real() {
    let own_redirect = b"HTTP/1.1 301 Moved\r\nLocation: https://rutracker.org/\r\n\r\n";
    assert_eq!(
        judge(Some(b"rutracker.org"), own_redirect, 98_000, 99_000),
        Answer::Real
    );
}

#[test]
fn classifies_malformed_status_and_incomplete_headers_as_garbage() {
    assert_eq!(
        judge(
            Some(b"target.example"),
            b"HTTP/1.1 200 OK\r\nLocation: http://lawfilter.ertelecom.ru",
            1,
            5
        ),
        Answer::Garbage
    );
    assert_eq!(
        judge(Some(b"rutracker.org"), b"\x16\x03\x01", 98_000, 99_000),
        Answer::Garbage
    );
    assert_eq!(
        judge(Some(b"rutracker.org"), b"HTTP/1.1", 98_000, 99_000),
        Answer::Garbage
    );
}

#[test]
fn identifies_responses_to_the_decoy_instead_of_the_target() {
    let to_decoy = b"HTTP/1.1 301 Moved\r\nLocation: https://disk.rzd.ru/\r\n\r\n";
    let misdirected = b"HTTP/1.1 421 Misdirected Request\r\n\r\n";
    let bad_request = b"HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n\r\n";
    let responses: &[&[u8]] = &[to_decoy, misdirected, bad_request];
    for response in responses {
        assert_eq!(
            judge(Some(b"rutracker.org"), response, 98_000, 99_000),
            Answer::Decoy
        );
    }
}

#[test]
fn absent_host_does_not_infer_a_provider_portal() {
    assert_eq!(judge(None, INJECTED, 98_000, 99_000), Answer::Real);
}

#[test]
fn exposes_the_same_ordered_http_search_questions() {
    assert_eq!(
        candidate_keys(),
        [
            "split",
            "fake-badsum-whole",
            "fake-badsum",
            "disorder",
            "fake-seqshift"
        ]
    );
}

#[test]
fn add_candidate_dedups_and_caps_like_c() {
    let mut candidates = Vec::new();
    add_candidate(&mut candidates, "split");
    add_candidate(&mut candidates, "split");
    assert_eq!(candidates, ["split"]);

    for index in 0..D2K_HS_CANDS_MAX + 6 {
        add_candidate(&mut candidates, &format!("key-{index}"));
    }
    assert_eq!(candidates.len(), D2K_HS_CANDS_MAX);
    assert_eq!(candidates[1], "key-0");
    assert_eq!(
        candidates[D2K_HS_CANDS_MAX - 1],
        format!("key-{}", D2K_HS_CANDS_MAX - 2)
    );
}

#[test]
fn known_key_matches_c_predicate() {
    for accepted in [
        "split",
        "disorder",
        "fake-badsum",
        "fake-seqshift",
        "fake-badsum-whole",
        "fake:ttl=5+badsum",
        "fake:badsum+seqshift=-66000",
        "fake:ttl=255+badsum+seqshift=2147483647",
    ] {
        assert!(known_key(accepted), "rejected {accepted:?}");
    }
    for rejected in [
        "",
        "fake:",
        "fake:ttl=1",
        "fake:badsum+badsum",
        "fake:seqshift=0",
        "fake:badsum+ttl=1",
        "fake:ttl=0+badsum",
        "fake:ttl=256+badsum",
        "fake:seqshift=abc",
        "fake:ttl=1+badsum+seqshift=-2147483648",
        "unknown",
        "fake-badsum-whole2",
    ] {
        assert!(!known_key(rejected), "accepted {rejected:?}");
    }
    let too_long = format!("fake:ttl=1+badsum+{}", "x".repeat(30));
    assert!(!known_key(&too_long), "accepted {too_long:?}");
}

#[test]
fn recovers_only_exact_supported_keys_from_saved_plan_text() {
    for key in [
        "split",
        "fake-badsum-whole",
        "fake-badsum",
        "disorder",
        "fake-seqshift",
        "fake:ttl=5+badsum",
    ] {
        let text = candidate_text(key, Some(&ID)).unwrap();
        assert_eq!(candidate_key_from_plan_text(&text).as_deref(), Some(key));
    }
    assert!(candidate_key_from_plan_text("r2o-plan 1 11\nid invalid\n").is_none());
    assert!(candidate_key_from_plan_text("r2o-plan 1 11\nid éééééééééééééééé\n").is_none());
}

#[test]
fn builds_the_exact_split_candidate_text() {
    assert_eq!(
        candidate_text("split", Some(&ID)),
        Some("r2o-plan 1 11\nid 01020300000000000000000000000000\nproto tcp http\nsplit sni_middle +0\n".to_owned())
    );
}

#[test]
fn builds_the_exact_disorder_candidate_text() {
    assert_eq!(
        candidate_text("disorder", Some(&ID)),
        Some("r2o-plan 1 11\nid 01020300000000000000000000000000\nproto tcp http\nsplit sni_middle +0\norder reverse\npace 12000\n".to_owned())
    );
}

#[test]
fn builds_fake_candidates_with_the_reference_payload_and_poison() {
    let prefix = "r2o-plan 1 11\nid 01020300000000000000000000000000\nproto tcp http\npayload 1 474554202f20485454502f312e310d0a486f73743a206469736b2e727a642e72750d0a0d0a\n";
    assert_eq!(
        candidate_text("fake-badsum", Some(&ID)),
        Some(format!(
            "{prefix}poison 1 badsum\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before\nsplit sni_middle +0\n"
        ))
    );
    assert_eq!(
        candidate_text("fake-seqshift", Some(&ID)),
        Some(format!(
            "{prefix}poison 1 seqshift=-66000\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before\nsplit sni_middle +0\n"
        ))
    );
}

#[test]
fn builds_the_whole_fake_candidate_without_a_split() {
    assert_eq!(
        candidate_text("fake-badsum-whole", Some(&ID)),
        Some("r2o-plan 1 11\nid 01020300000000000000000000000000\nproto tcp http\npayload 1 474554202f20485454502f312e310d0a486f73743a206469736b2e727a642e72750d0a0d0a\npoison 1 badsum\nfake payload=1 poison=1 repeats=1 gap_us=0 place=before\n".to_owned())
    );
}

#[test]
fn accepts_only_measured_poison_keys_in_canonical_safe_combinations() {
    assert!(candidate_text("fake:ttl=5+badsum", None).is_some());
    assert_eq!(candidate_text("fake:ttl=5", None), None);
    assert_eq!(candidate_text("fake:badsum+ttl=5", None), None);
    assert_eq!(candidate_text("fake:badsum+badsum", None), None);
    assert_eq!(candidate_text("fake:seqshift=0", None), None);
    assert_eq!(candidate_text("fake:ttl=256+badsum", None), None);
    assert_eq!(candidate_text("unknown", None), None);
}

#[test]
fn derives_the_r2o_stable_id_for_a_candidate() {
    assert_eq!(
        stable_id("split"),
        [
            0xcf, 0x95, 0x77, 0xbf, 0x11, 0xc4, 0x84, 0xfe, 0x4b, 0x4b, 0x0f, 0xe0, 0x8b, 0x46,
            0x81, 0xf3,
        ]
    );
}

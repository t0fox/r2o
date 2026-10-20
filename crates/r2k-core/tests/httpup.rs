use r2k_core::httpup::{
    portal_location, portal_response, redirect_https, request_host_range, request_safe,
    request_target,
};

const REQUEST: &[u8] =
    b"GET /forum/index.php?q=1 HTTP/1.1\r\nHost: RuTracker.org:80\r\nConnection: close\r\n\r\n";
const PORTAL: &[u8] = b"HTTP/1.1 302 Found\r\nLocation: http://lawfilter.ertelecom.ru/deny?id=7\r\nContent-Length: 0\r\n\r\n";

#[test]
fn accepts_only_safe_bodyless_origin_form_get_and_head() {
    assert!(request_safe(REQUEST));
    assert!(request_safe(
        b"HEAD /path HTTP/1.0\r\nHost: example.org\r\n\r\n"
    ));
    assert!(!request_safe(
        b"POST /login HTTP/1.1\r\nHost: example.org\r\n\r\n"
    ));
    assert!(!request_safe(
        b"GET http://example.org/ HTTP/1.1\r\nHost: example.org\r\n\r\n"
    ));
    assert!(!request_safe(
        b"GET / HTTP/1.1\r\nHost: example.org\r\nContent-Length: 1\r\n\r\nx"
    ));
    assert!(!request_safe(
        b"GET / HTTP/1.1\r\nHost: example.org\r\nTransfer-Encoding: chunked\r\n\r\n"
    ));
}

#[test]
fn extracts_normalized_host_and_origin_target() {
    assert_eq!(
        request_target(b"GET /a?q=1 HTTP/1.1\r\nHost: Example.org.:80\r\n\r\n"),
        Some((b"Example.org".to_vec(), b"/a?q=1".to_vec()))
    );
}

#[test]
fn returns_the_normalized_host_range_for_tcp_split_anchors() {
    let request = b"GET /p?q=1 HTTP/1.1\r\nHost: example.test:80\r\n\r\n";
    assert_eq!(request_host_range(request), Some(27..39));
    assert_eq!(
        request_host_range(b"GET / HTTP/1.1\r\nHost: example.test\r\n"),
        None
    );
}

#[test]
fn upgrades_a_safe_request_only_after_an_explicit_provider_portal_redirect() {
    assert_eq!(
        portal_response(REQUEST, PORTAL),
        Some(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://RuTracker.org/forum/index.php?q=1\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: 0\r\nX-R2O-HTTP-Upgrade: provider-portal\r\n\r\n".to_vec())
    );
}

#[test]
fn leaves_non_portal_redirects_and_non_redirect_responses_unchanged() {
    let ordinary = b"HTTP/1.1 302 Found\r\nLocation: https://login.example.net/continue\r\n\r\n";
    let same_host = b"HTTP/1.1 302 Found\r\nLocation: https://rutracker.org/forum/\r\n\r\n";
    let deceptive = b"HTTP/1.1 302 Found\r\nLocation: https://unblocked.example/continue\r\n\r\n";
    let not_redirect = b"HTTP/1.1 200 OK\r\nLocation: https://lawfilter.example/\r\n\r\n";
    let responses: &[&[u8]] = &[ordinary, same_host, deceptive, not_redirect];
    for response in responses {
        assert_eq!(portal_response(REQUEST, response), None);
    }
}

#[test]
fn recognizes_the_same_portal_location_for_packet_by_packet_processing() {
    assert_eq!(
        portal_location(b"rutracker.org", PORTAL),
        Some(b"lawfilter.ertelecom.ru".to_vec())
    );
    assert_eq!(portal_location(b"lawfilter.ertelecom.ru", PORTAL), None);
}

#[test]
fn rejects_ambiguous_or_malformed_request_and_redirect_headers() {
    assert!(!request_safe(
        b"GET / HTTP/1.1\r\nHost: example.org\r\nHost: evil.org\r\n\r\n"
    ));
    assert!(!request_safe(
        b"GET / HTTP/1.1\r\nHost: -example.org\r\n\r\n"
    ));
    assert_eq!(
        portal_response(REQUEST, b"HTTP/1.1 302 Found\r\nLocation: /deny\r\n\r\n"),
        None
    );
    assert_eq!(
        portal_response(REQUEST, b"HTTP/1.1 302 Found\r\nLocation: http://lawfilter.example/\r\nLocation: http://blocked.example/\r\n\r\n"),
        None
    );
}

#[test]
fn builds_the_exact_https_redirect_for_a_valid_origin_target() {
    assert_eq!(
        redirect_https(b"rutracker.org", b"/forum/"),
        Some(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://rutracker.org/forum/\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: 0\r\nX-R2O-HTTP-Upgrade: provider-portal\r\n\r\n".to_vec())
    );
    assert_eq!(redirect_https(b"rutracker.org", b"not-origin-form"), None);
    assert_eq!(redirect_https(b"bad host", b"/"), None);
    assert_eq!(redirect_https(b"rutracker.org", b"/\r\nX-Evil: yes"), None);
}

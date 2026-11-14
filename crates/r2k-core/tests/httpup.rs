use r2k_core::httpup::{
    R2oHttpRequestStream, portal_location, portal_response, redirect_https, request_host_range,
    request_safe, request_target,
};

const REQUEST: &[u8] =
    b"GET /forum/index.php?q=1 HTTP/1.1\r\nHost: RuTracker.org:80\r\nConnection: close\r\n\r\n";
const PORTAL: &[u8] = b"HTTP/1.1 302 Found\r\nLocation: http://lawfilter.ertelecom.ru/deny?id=7\r\nContent-Length: 0\r\n\r\n";

#[test]
fn partial_header_keeps_known_host_like_c() {
    // C `d2k_http_request`: неполная строка после Host не отменяет Host.
    let partial = b"GET / HTTP/1.1\r\nHost: example.com\r\nX";
    let request = r2k_core::httpup::r2o_http_plan_request(partial).unwrap();
    assert_eq!(request.header_len, 0);
    assert_eq!(request.end_offset, None);
    assert_eq!(&partial[request.host_range.clone()], b"example.com");
    assert!(!request_safe(partial));

    let complete = b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n";
    let request = r2k_core::httpup::r2o_http_plan_request(complete).unwrap();
    assert_eq!(request.header_len, complete.len());
    assert_eq!(
        request.end_offset,
        Some(complete.len() + 5),
        "framing includes Content-Length"
    );
}

#[test]
fn request_feed_differential_matches_c() {
    fn dump(output: &mut String, label: &str, stream: &R2oHttpRequestStream) {
        let (client_next, next_known) = (stream.next, {
            stream.header_done && !stream.invalid && !stream.past_end && stream.next == stream.end
        });
        output.push_str(&format!(
            "{label} client_next={client_next} next_known={} next={} end={} hd={} invalid={} past={}\n",
            u8::from(next_known),
            stream.next,
            stream.end,
            u8::from(stream.header_done),
            u8::from(stream.invalid),
            u8::from(stream.past_end)
        ));
    }

    let mut output = String::new();
    let mut stream = R2oHttpRequestStream::new(1000);
    stream.feed_and_next_known(1000, b"GET / HTTP/1.1\r\nHost: ex");
    dump(&mut output, "split1", &stream);
    stream.feed_and_next_known(stream.next, b"ample.com\r\nContent-Length: 3\r\n\r\n");
    dump(&mut output, "split2", &stream);
    stream.feed_and_next_known(stream.next, b"abcd");
    dump(&mut output, "body", &stream);

    let mut te = R2oHttpRequestStream::new(2000);
    te.feed_and_next_known(
        2000,
        b"GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
    );
    dump(&mut output, "te", &te);

    let mut first = R2oHttpRequestStream::new(3000);
    first.feed_and_next_known(3000, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    dump(&mut output, "first", &first);
    first.feed_and_next_known(2999, b"x");
    dump(&mut output, "old", &first);
    first.feed_and_next_known(first.next.wrapping_add(3), b"y");
    dump(&mut output, "gap", &first);

    if let Ok(path) = std::env::var("R2O_REQUEST_FEED_DIFF_OUTPUT") {
        std::fs::write(path, &output).unwrap();
    }
    assert!(output.contains(
        "split2 client_next=1056 next_known=0 next=1056 end=1059 hd=1 invalid=0 past=0\n"
    ));
    assert!(output.contains(
        "first client_next=3027 next_known=1 next=3027 end=3027 hd=1 invalid=0 past=0\n"
    ));
    assert!(
        output.contains(
            "gap client_next=3027 next_known=0 next=3027 end=3027 hd=1 invalid=1 past=0\n"
        )
    );
}

#[test]
fn http_request_differential_matches_c() {
    let cases: &[(&str, &[u8])] = &[
        ("simple", b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        ("partial", b"GET / HTTP/1.1\r\nHost: example.com\r\nX"),
        ("host80", b"GET / HTTP/1.1\r\nHost: example.com:80\r\n\r\n"),
        (
            "host8080",
            b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n",
        ),
        ("no_host", b"GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n"),
        ("two_hosts", b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"),
        (
            "trailing_dot",
            b"GET / HTTP/1.1\r\nHost: example.com.\r\n\r\n",
        ),
        ("ipv4", b"GET / HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n"),
        ("lower_method", b"get / HTTP/1.1\r\nHost: a\r\n\r\n"),
        ("absolute", b"GET http://a/ HTTP/1.1\r\nHost: a\r\n\r\n"),
        ("bad_label", b"GET / HTTP/1.1\r\nHost: -bad\r\n\r\n"),
        (
            "te",
            b"GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n",
        ),
        (
            "duplicate_cl",
            b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
        ),
        (
            "cl",
            b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n",
        ),
        ("no_crlf", b"GET / HTTP/1.1\r\nHost: a\r\n"),
    ];
    let mut output = String::new();
    for (name, bytes) in cases {
        let request = r2k_core::httpup::r2o_http_plan_request(bytes);
        let rc = u8::from(request.is_some());
        output.push_str(&format!("{name} rc={rc} host="));
        if let Some(request) = &request {
            for byte in &bytes[request.host_range.clone()] {
                output.push_str(&format!("{byte:02x}"));
            }
        }
        if let Some(request) = request {
            output.push_str(&format!(
                " head={} end_known={} end={}\n",
                request.header_len,
                u8::from(request.end_offset.is_some()),
                request.end_offset.unwrap_or(0)
            ));
        } else {
            output.push_str(" head=0 end_known=0 end=0\n");
        }
    }
    if let Ok(path) = std::env::var("R2O_HTTP_REQUEST_DIFF_OUTPUT") {
        std::fs::write(path, &output).unwrap();
    }
    assert!(
        output.contains("simple rc=1 host=6578616d706c652e636f6d head=37 end_known=1 end=37\n")
    );
    assert!(output.contains("partial rc=1 host=6578616d706c652e636f6d head=0 end_known=0 end=0\n"));
    assert!(output.contains("host8080 rc=0 host= head=0 end_known=0 end=0\n"));
}

#[test]
fn http_request_stream_differential_matches_c() {
    fn dump(output: &mut String, label: &str, stream: &R2oHttpRequestStream) {
        output.push_str(&format!(
            "{label} start={} next={} head={} end={} length={} invalid={} hd={} past={}\n",
            stream.start,
            stream.next,
            stream.head_len,
            stream.end,
            stream.length,
            u8::from(stream.invalid),
            u8::from(stream.header_done),
            u8::from(stream.past_end)
        ));
    }

    let mut output = String::new();
    {
        let mut stream = R2oHttpRequestStream::new(1000);
        stream.feed(
            1000,
            b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\n",
        );
        dump(&mut output, "simple", &stream);
        stream.feed(stream.next, b"abcd");
        dump(&mut output, "past_end", &stream);
    }
    {
        let mut stream = R2oHttpRequestStream::new(2000);
        stream.feed(2000, b"GET / HTTP/1.1\r\nHost: ex");
        dump(&mut output, "split1", &stream);
        stream.feed(stream.next, b"ample.com\r\nContent-Length: 0\r\n\r\n");
        dump(&mut output, "split2", &stream);
    }
    for (label, sequence, request) in [
        (
            "no_host",
            3000,
            &b"GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n"[..],
        ),
        (
            "two_hosts",
            4000,
            &b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"[..],
        ),
        (
            "te",
            5000,
            &b"GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
        ),
        (
            "upgrade",
            6000,
            &b"GET / HTTP/1.1\r\nHost: a\r\nUpgrade: h2c\r\n\r\n"[..],
        ),
        (
            "duplicate_cl",
            7000,
            &b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n"[..],
        ),
        (
            "bad_cl",
            8000,
            &b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 1x\r\n\r\n"[..],
        ),
        (
            "control",
            9000,
            &b"GET / HTTP/1.1\r\nHost: a\r\nX: \x01\r\n\r\n"[..],
        ),
    ] {
        let mut stream = R2oHttpRequestStream::new(sequence);
        stream.feed(sequence, request);
        dump(&mut output, label, &stream);
    }
    {
        let mut stream = R2oHttpRequestStream::new(10_000);
        stream.feed(10_000, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        let old = stream.start;
        stream.feed(old, b"0123456789");
        dump(&mut output, "old_repeat", &stream);
        stream.feed(stream.next.wrapping_add(5), b"x");
        dump(&mut output, "gap", &stream);
    }

    if let Ok(path) = std::env::var("R2O_HTTP_REQUEST_STREAM_DIFF_OUTPUT") {
        std::fs::write(path, &output).unwrap();
    }
    assert!(
        output.contains(
            "simple start=1000 next=1056 head=56 end=1059 length=3 invalid=0 hd=1 past=0\n"
        )
    );
    assert!(
        output.contains(
            "split2 start=2000 next=2056 head=56 end=2056 length=0 invalid=0 hd=1 past=0\n"
        )
    );
    assert!(
        output
            .contains("no_host start=3000 next=3037 head=0 end=0 length=0 invalid=1 hd=0 past=0\n")
    );
}

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
        Some(22..34),
        "C d2k_http_request keeps a known Host on an incomplete header"
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
fn распознаёт_порталы_операторов_из_актуального_донора() {
    let hosts: [&[u8]; 6] = [
        b"eais.rkn.gov.ru",
        b"lawfilter.ertelecom.ru",
        b"blackhole.svyaztelecom.ru",
        b"warning.rt.ru",
        b"warn.beeline.ru",
        b"deny.megafon.ru",
    ];
    for host in hosts {
        let mut response = b"HTTP/1.1 302 Found\r\nLocation: http://".to_vec();
        response.extend_from_slice(host);
        response.extend_from_slice(b"/blocked\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(
            portal_location(b"example.org", &response),
            Some(host.to_vec()),
            "донорский портал {host:?} не распознан"
        );
    }
    let megafon = b"HTTP/1.1 302 Found\r\nLocation: https://m.megafonpro.ru/rkn-auth\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(
        portal_location(b"example.org", megafon),
        Some(b"m.megafonpro.ru".to_vec())
    );
    assert!(portal_response(b"GET /path HTTP/1.1\r\nHost: example.org\r\n\r\n", megafon).is_some());
    let unrelated = b"HTTP/1.1 302 Found\r\nLocation: https://isp.example.org/rkn-landing/rkn\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(portal_location(b"example.org", unrelated), None);
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

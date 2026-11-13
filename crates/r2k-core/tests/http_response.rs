use r2k_core::http_response::HttpResponseParser;

#[test]
fn http_response_feed_differential_matches_c() {
    let cases: &[(&str, &[u8])] = &[
        ("extension_suffix", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;foo=\"unterminated\r\nx\r\n0\r\n\r\n"),
        ("trailer_without_colon", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nnot-a-field\r\n\r\n"),
        ("colonless_header", b"HTTP/1.1 200 OK\r\nMalformed Header\r\nContent-Length: 1\r\n\r\nx"),
        ("control_extension", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;foo=\x01\r\nx\r\n0\r\n\r\n"),
        ("control_chunk_size", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\x01\r\nx\r\n0\r\n\r\n"),
        ("buffered_bytes_after_frame", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nextra"),
        ("control_header_value", b"HTTP/1.1 200 OK\r\nX: foo\x01bar\r\nContent-Length: 0\r\n\r\n"),
        ("bare_lf_header_value", b"HTTP/1.1 200 OK\r\nX: foo\nbar\r\nContent-Length: 0\r\n\r\n"),
        ("bare_cr_header_value", b"HTTP/1.1 200 OK\r\nX: foo\rbar\r\nContent-Length: 0\r\n\r\n"),
        ("bare_lf_swallows_next_header", b"HTTP/1.1 200 OK\r\nX: x\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n"),
        ("control_trailer", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: foo\x01bar\r\n\r\n"),
        ("nul_first_trailer", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\0ignored\r\n"),
        ("bodyless_204_buffered", b"HTTP/1.1 204 No Content\r\nContent-Length: 4\r\n\r\nbody"),
        ("bodyless_304_buffered", b"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\nnot-a-chunk"),
        ("status12", b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n"),
        ("duplicate_cl", b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 01\r\n\r\nx"),
        ("chunk_bare_space", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1 \r\nx\r\n0\r\n\r\n"),
        ("chunk_ext_ok", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;foo=\"bar\"\r\nx\r\n0\r\n\r\n"),
        ("chunk_ows_ext_ok", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1 ;foo\r\nx\r\n0\r\n\r\n"),
    ];
    let mut output = String::new();
    for (name, bytes) in cases {
        let mut response = HttpResponseParser::new(false);
        response.feed(bytes, false);
        output.push_str(&format!(
            "{name} status={} complete={} body_bytes={} invalid={}\n",
            response.status(),
            u8::from(response.is_complete()),
            response.body_bytes(),
            u8::from(response.is_invalid())
        ));
    }
    if let Ok(path) = std::env::var("R2O_HTTP_RESPONSE_FEED_DIFF_OUTPUT") {
        std::fs::write(path, &output).unwrap();
    }
    assert!(
        output
            .contains("buffered_bytes_after_frame status=200 complete=0 body_bytes=0 invalid=1\n")
    );
    assert!(output.contains("duplicate_cl status=200 complete=0 body_bytes=0 invalid=1\n"));
    assert!(output.contains("chunk_ext_ok status=200 complete=1 body_bytes=1 invalid=0\n"));
}

#[test]
fn parses_a_fixed_length_body_across_interim_response_and_segments() {
    let mut response = HttpResponseParser::new(false);
    response.feed(
        b"HTTP/1.1 103 Early Hints\r\nLink: /x\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab",
        false,
    );
    assert!(response.headers_complete());
    assert_eq!(response.status(), 200);
    assert_eq!(response.body_bytes(), 2);
    assert!(!response.is_complete());
    assert!(!response.is_invalid());

    response.feed(b"cd", false);
    assert!(response.is_complete());
    assert!(!response.is_invalid());
    assert_eq!(response.body_bytes(), 4);
}

#[test]
fn parses_chunked_body_and_trailers_at_every_segment_boundary() {
    let bytes = b"HTTP/1.1 103 Early Hints\r\nLink: /x\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;foo=\"bar\"\r\nx\r\n0\r\nX-Trailer: yes\r\n\r\n";
    for split in 0..=bytes.len() {
        let mut response = HttpResponseParser::new(false);
        response.feed(&bytes[..split], false);
        response.feed(&bytes[split..], false);
        assert!(response.is_complete(), "split={split}");
        assert!(!response.is_invalid(), "split={split}");
        assert_eq!(response.status(), 200, "split={split}");
        assert_eq!(response.body_bytes(), 1, "split={split}");
    }
}

#[test]
fn matches_d2o_http_header_and_chunk_framing() {
    // C `char line[512]`: строка с CRLF до 511 байт, 512-й отвергается.
    let mut line_at_limit = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;".to_vec();
    line_at_limit.extend_from_slice(&[b'a'; 507]);
    line_at_limit.extend_from_slice(b"\r\nx\r\n0\r\n\r\n");

    let mut line_over_limit = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;".to_vec();
    line_over_limit.extend_from_slice(&[b'a'; 508]);
    line_over_limit.extend_from_slice(b"\r\nx\r\n0\r\n\r\n");

    let mut response = HttpResponseParser::new(false);
    response.feed(&line_at_limit, false);
    assert!(response.is_complete());
    assert!(!response.is_invalid());
    assert_eq!(response.status(), 200);
    assert_eq!(response.body_bytes(), 1);

    let mut response = HttpResponseParser::new(false);
    response.feed(&line_over_limit, false);
    assert!(!response.is_complete());
    assert!(response.is_invalid());
}

#[test]
fn rejects_chunk_size_line_beyond_d2o_buffer_limit() {
    let mut bytes = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;".to_vec();
    bytes.extend_from_slice(&[b'a'; 508]);
    bytes.extend_from_slice(b"\r\nx\r\n0\r\n\r\n");

    let mut response = HttpResponseParser::new(false);
    response.feed(&bytes, false);

    assert_eq!(response.status(), 200);
    assert!(response.headers_complete());
    assert!(response.is_invalid());
    assert!(!response.is_complete());
}

#[test]
fn rejects_malformed_or_ambiguous_response_framing() {
    let cases: [&[u8]; 9] = [
        b"HTTP/1.1 000 Unknown\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 600 Unknown\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 O\rK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000000\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1 \r\nx\r\n0\r\n\r\n",
    ];
    for bytes in cases {
        let mut response = HttpResponseParser::new(false);
        response.feed(bytes, false);
        response.feed(b"", true);
        assert!(response.is_invalid(), "response was accepted: {bytes:?}");
        assert!(!response.is_complete());
    }
}

#[test]
fn rejects_repeated_content_length_fields_like_c() {
    let mut response = HttpResponseParser::new(false);
    response.feed(
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 01\r\n\r\nx",
        false,
    );
    assert!(!response.is_complete());
    assert!(response.is_invalid());
}

#[test]
fn preserves_valid_status_when_header_framing_is_invalid() {
    let mut response = HttpResponseParser::new(false);
    response.feed(
        b"HTTP/1.1 451 Unavailable\r\nContent-Length: invalid\r\n\r\n",
        false,
    );
    assert!(response.is_invalid());
    assert!(!response.headers_complete());
    assert_eq!(response.status(), 451);
}

#[test]
fn close_delimited_response_completes_only_on_fin() {
    let mut response = HttpResponseParser::new(false);
    response.feed(b"HTTP/1.1 200 OK\r\n\r\nbody", false);
    assert!(!response.is_complete());
    assert_eq!(response.body_bytes(), 4);

    response.feed(b"", true);
    assert!(response.is_complete());
    assert!(!response.is_invalid());
}

#[test]
fn rejects_extra_bytes_after_a_framed_response_is_complete() {
    let mut response = HttpResponseParser::new(false);
    response.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", false);
    assert!(response.is_complete());
    response.feed(b"extra", false);
    assert!(!response.is_complete());
    assert!(response.is_invalid());
}

#[test]
fn head_and_bodyless_statuses_complete_at_the_header_boundary() {
    let mut head = HttpResponseParser::new(true);
    head.feed(b"HTTP/1.1 200 OK\r\n\r\n", false);
    assert!(head.is_complete());
    assert_eq!(head.body_bytes(), 0);

    let mut no_content = HttpResponseParser::new(false);
    no_content.feed(b"HTTP/1.1 204 No Content\r\n\r\n", false);
    assert!(no_content.is_complete());
    assert_eq!(no_content.body_bytes(), 0);
}

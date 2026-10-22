use r2k_core::http_response::HttpResponseParser;

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
fn rejects_malformed_or_ambiguous_response_framing() {
    let cases: [&[u8]; 13] = [
        b"HTTP/1.1 200 OK\r\nX: x\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 000 Unknown\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 600 Unknown\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 O\rK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;foo=\"unterminated\r\nx\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n:\r\n\r\n",
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
fn accepts_repeated_identical_content_length_fields() {
    let mut response = HttpResponseParser::new(false);
    response.feed(
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 01\r\n\r\nx",
        false,
    );
    assert!(response.is_complete());
    assert!(!response.is_invalid());
    assert_eq!(response.body_bytes(), 1);
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
fn invalidates_extra_bytes_after_a_framed_response_is_complete() {
    let mut response = HttpResponseParser::new(false);
    response.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nextra", false);
    assert!(response.is_invalid());
    assert!(!response.is_complete());
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

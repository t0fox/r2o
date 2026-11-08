//! CL14: Rust trace HTTP/3 helpers и httpup-логики.

use r2k_core::h3;
use r2k_core::httpup;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn normalized_hex(bytes: &[u8]) -> String {
    let product = b"X-R2O-HTTP-Upgrade";
    let normalized = b"X-UPGRADE";
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(product) {
            output.extend_from_slice(normalized);
            index += product.len();
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    hex(&output)
}

fn status_case(name: &str, frame: &[u8]) {
    match h3::status(frame) {
        Some(status) => println!("h3status {name} rc=0 st={status}"),
        None => println!("h3status {name} rc=-1 st=0"),
    }
}

fn main() {
    let mut output = [0_u8; 512];
    for cap in [0_usize, 2, 3, 16] {
        let length = h3::control(&mut output[..cap]);
        println!(
            "h3control cap={cap} n={length} hex={}",
            hex(&output[..length])
        );
    }

    let requests = [
        ("root", "example.com".to_string(), "/".to_string(), 512),
        (
            "nonroot",
            "example.com".to_string(),
            "/big.css".to_string(),
            512,
        ),
        ("empty-path", "example.com".to_string(), "".to_string(), 512),
        ("empty-host", "".to_string(), "/".to_string(), 512),
        ("cap-1", "example.com".to_string(), "/".to_string(), 1),
        ("cap-5", "example.com".to_string(), "/".to_string(), 5),
        ("cap-20", "example.com".to_string(), "/".to_string(), 20),
    ];
    for (name, host, path, cap) in requests {
        let length = h3::request(&host, &path, &mut output[..cap]);
        println!("h3req {name} n={length} hex={}", hex(&output[..length]));
    }
    let long_host = "a".repeat(255);
    let length = h3::request(&long_host, "/", &mut output);
    println!("h3req long-host n={length} hex={}", hex(&output[..length]));
    let too_long_host = "a".repeat(256);
    let length = h3::request(&too_long_host, "/", &mut output);
    println!(
        "h3req long-host-256 n={length} hex={}",
        hex(&output[..length])
    );

    let statuses = [
        ("static24", vec![0x01, 0x03, 0x00, 0x00, 0xd8]),
        ("static25", vec![0x01, 0x03, 0x00, 0x00, 0xd9]),
        ("static28", vec![0x01, 0x03, 0x00, 0x00, 0xdc]),
        ("static63", vec![0x01, 0x04, 0x00, 0x00, 0xff, 0x00]),
        ("static71", vec![0x01, 0x04, 0x00, 0x00, 0xff, 0x08]),
        (
            "huff404",
            vec![0x01, 0x08, 0x00, 0x00, 0x5f, 0x0c, 0x83, 0x68, 0x0d, 0x7f],
        ),
        (
            "plain201",
            vec![0x01, 0x08, 0x00, 0x00, 0x5f, 0x0c, 0x03, b'2', b'0', b'1'],
        ),
        (
            "unknown-frame",
            vec![0x21, 0x02, 0xaa, 0xbb, 0x01, 0x03, 0x00, 0x00, 0xd9],
        ),
        ("truncated", vec![0x01, 0x10, 0x00, 0x00]),
        (
            "literal-name",
            vec![
                0x01, 0x09, 0x00, 0x00, 0x23, b'x', b'-', b'a', 0x01, b'1', 0xd9,
            ],
        ),
        (
            "post-base",
            vec![0x01, 0x07, 0x00, 0x00, 0x11, 0x02, 0x01, b'1', 0xd9],
        ),
    ];
    for (name, frame) in statuses {
        status_case(name, &frame);
    }
    for (value, status) in [
        (vec![0x64_u8, 0x01], 301_u16),
        (vec![0x6c, 0x0c, 0xff], 503),
        (vec![0x10, 0x01], 200),
    ] {
        let mut frame = vec![
            0x01,
            0x00,
            0x00,
            0x00,
            0x5f,
            24 - 15,
            0x80 | value.len() as u8,
        ];
        frame.extend_from_slice(&value);
        frame[1] = (frame.len() - 2) as u8;
        status_case(&format!("literal-{status}"), &frame);
    }

    let requests = [
        (
            "safe-get",
            "GET /forum/index.php?q=1 HTTP/1.1\r\nHost: RuTracker.org:80\r\nConnection: close\r\n\r\n",
        ),
        (
            "post",
            "POST /login HTTP/1.1\r\nHost: rutracker.org\r\n\r\n",
        ),
        ("no-host", "GET / HTTP/1.1\r\nConnection: close\r\n\r\n"),
        (
            "absolute",
            "GET http://rutracker.org/ HTTP/1.1\r\nHost: rutracker.org\r\n\r\n",
        ),
        (
            "body",
            "GET / HTTP/1.1\r\nHost: rutracker.org\r\nContent-Length: 1\r\n\r\nx",
        ),
        (
            "unframed-tail",
            "GET / HTTP/1.1\r\nHost: rutracker.org\r\n\r\nx",
        ),
        ("http10", "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"),
        ("head", "HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    ];
    for (name, request) in requests {
        println!(
            "httpup {name} safe={}",
            u8::from(httpup::request_safe(request.as_bytes()))
        );
    }
    let request = "GET /forum/index.php?q=1 HTTP/1.1\r\nHost: RuTracker.org:80\r\n\r\n";
    if let Some((host, target)) = httpup::request_target(request.as_bytes()) {
        println!(
            "httpup target safe-get ok=1 host={} target={}",
            hex(&host),
            hex(&target)
        );
    } else {
        println!("httpup target safe-get ok=0 host= target=");
    }

    let responses = [
        (
            "portal",
            "HTTP/1.1 302 Found\r\nLocation: http://lawfilter.ertelecom.ru/deny?id=7\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "megafon",
            "HTTP/1.1 302 Found\r\nLocation: https://m.megafonpro.ru/rkn-auth?channel=2m\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "rt",
            "HTTP/1.1 302 Found\r\nLocation: http://warning.rt.ru/\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "beeline",
            "HTTP/1.1 302 Found\r\nLocation: http://warn.beeline.ru/\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "megafon-deny",
            "HTTP/1.1 302 Found\r\nLocation: http://deny.megafon.ru/blocked\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "blackhole",
            "HTTP/1.1 302 Found\r\nLocation: http://blackhole.svyaztelecom.ru/\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "ordinary",
            "HTTP/1.1 302 Found\r\nLocation: https://login.example.net/continue\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "same-host",
            "HTTP/1.1 302 Found\r\nLocation: https://rutracker.org/forum/\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "deceptive",
            "HTTP/1.1 302 Found\r\nLocation: https://unblocked.example/continue\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "not-redirect",
            "HTTP/1.1 200 OK\r\nLocation: https://lawfilter.example/\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "rkn-path",
            "HTTP/1.1 302 Found\r\nLocation: http://isp.example.org/rkn-landing/rkn?id=1\r\nContent-Length: 0\r\n\r\n",
        ),
    ];
    for (name, response) in responses {
        match httpup::portal_response(request.as_bytes(), response.as_bytes()) {
            Some(response) => println!(
                "httpup response {name} ok=1 hex={}",
                normalized_hex(&response)
            ),
            None => println!("httpup response {name} ok=0 hex="),
        }
    }
    let response =
        "HTTP/1.1 302 Found\r\nLocation: http://lawfilter.ertelecom.ru/deny?id=7\r\n\r\n";
    match httpup::portal_location(b"rutracker.org", response.as_bytes()) {
        Some(portal) => println!("httpup location ok=1 hex={}", hex(&portal)),
        None => println!("httpup location ok=0 hex="),
    }
    match httpup::redirect_https(b"rutracker.org", b"/forum/index.php?q=1") {
        Some(response) => println!(
            "httpup redirect n={} hex={}",
            response.len(),
            normalized_hex(&response)
        ),
        None => println!("httpup redirect n=0 hex="),
    }
}

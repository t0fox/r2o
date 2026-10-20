use r2o_controller::domain::{is_member, normalize, registrable_domain};

#[test]
fn normalizes_ascii_dns_names_and_rejects_invalid_hostnames() {
    assert_eq!(normalize("WWW.Example.COM.").unwrap(), "www.example.com");
    for invalid in [
        "",
        "localhost",
        "127.0.0.1",
        "123.45.67.89",
        "a..example.com",
        "-a.example.com",
        "a-.example.com",
        "a_1.example.com",
        "é.example.com",
        "a.{}.com",
    ] {
        assert!(normalize(invalid).is_err(), "accepted {invalid:?}");
    }
    assert_eq!(registrable_domain("a.123"), None);
    assert!(normalize(&format!("{}.com", "a".repeat(64))).is_err());
}

#[test]
fn finds_registrable_domains_using_private_wildcard_and_exception_rules() {
    assert_eq!(
        registrable_domain("a.b.googlevideo.com").as_deref(),
        Some("googlevideo.com")
    );
    assert_eq!(
        registrable_domain("a.b.example.co.uk").as_deref(),
        Some("example.co.uk")
    );
    assert_eq!(
        registrable_domain("x.foo.blogspot.com").as_deref(),
        Some("foo.blogspot.com")
    );
    assert_eq!(
        registrable_domain("www.city.kawasaki.jp").as_deref(),
        Some("city.kawasaki.jp")
    );
    assert_eq!(registrable_domain("x.example.not-a-real-tld"), None);
}

#[test]
fn membership_requires_a_label_boundary_and_a_registrable_suffix() {
    assert!(is_member("www.example.co.uk", "example.co.uk"));
    assert!(is_member("example.co.uk", "example.co.uk"));
    assert!(!is_member("badexample.co.uk", "example.co.uk"));
    assert!(!is_member("example.co.uk", "co.uk"));
    assert!(!is_member("bad..example.co.uk", "example.co.uk"));
}

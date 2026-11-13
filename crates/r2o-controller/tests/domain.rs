use r2o_controller::domain::{is_member, normalize, registrable_domain};

#[test]
fn normalizes_ascii_dns_names_and_rejects_invalid_hostnames() {
    assert_eq!(normalize("WWW.Example.COM.").unwrap(), "www.example.com");
    // C `d2k_domain_normalize` принимает односоставное нечисловое имя.
    assert_eq!(normalize("LOCALHOST.").unwrap(), "localhost");
    for invalid in [
        "",
        "127.0.0.1",
        "123.45.67.89",
        "123",
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

#[test]
fn matches_c_psl_snapshot_on_replit_and_aws_edges() {
    // Оракул D2O `d2k_domain_base` (core/domain.c, снимок PSL 257b298d…).
    assert_eq!(
        registrable_domain("a.b.replit.dev").as_deref(),
        Some("b.replit.dev")
    );
    assert_eq!(
        registrable_domain("x.teams.replit.dev").as_deref(),
        Some("x.teams.replit.dev")
    );
    assert_eq!(
        registrable_domain("a.us-east-1.cs.amazonlightsail.com").as_deref(),
        Some("amazonlightsail.com")
    );
    assert_eq!(
        registrable_domain("x.ap-southeast-5.cs.amazonlightsail.com").as_deref(),
        Some("amazonlightsail.com")
    );
    assert_eq!(
        registrable_domain("a.elasticbeanstalk.com").as_deref(),
        Some("a.elasticbeanstalk.com")
    );
    assert_eq!(
        registrable_domain("x.ap-southeast-4.elasticbeanstalk.com").as_deref(),
        Some("ap-southeast-4.elasticbeanstalk.com")
    );
    assert_eq!(
        registrable_domain("x.retool.app").as_deref(),
        Some("retool.app")
    );
    assert_eq!(
        registrable_domain("x.auth.ap-east-2.amazoncognito.com").as_deref(),
        Some("amazoncognito.com")
    );
}

#[test]
fn membership_matches_c_on_psl_edges() {
    assert!(!is_member("a.b.replit.dev", "replit.dev"));
    assert!(is_member("a.b.replit.dev", "b.replit.dev"));
    assert!(!is_member("x.teams.replit.dev", "teams.replit.dev"));
    assert!(is_member(
        "a.us-east-1.cs.amazonlightsail.com",
        "us-east-1.cs.amazonlightsail.com"
    ));
    assert!(!is_member("localhost", "localhost"));
}

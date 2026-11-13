//! C/Rust differential: domain normalize/base/member.

use r2o_controller::domain::{is_member, normalize, registrable_domain};

const NAMES: &[&str] = &[
    "WWW.Example.COM.",
    "localhost",
    "LOCALHOST.",
    "127.0.0.1",
    "123",
    "a..example.com",
    "-a.example.com",
    "a-.example.com",
    "a_1.example.com",
    "a.example.com",
    "a.b.example.co.uk",
    "co.uk",
    "x.foo.blogspot.com",
    "www.city.kawasaki.jp",
    "city.kawasaki.jp",
    "a.b.googlevideo.com",
    "a.b.replit.dev",
    "replit.dev",
    "x.teams.replit.dev",
    "a.us-east-1.cs.amazonlightsail.com",
    "us-east-1.cs.amazonlightsail.com",
    "x.ap-southeast-5.cs.amazonlightsail.com",
    "x.example.not-a-real-tld",
    "a.123",
    "example.com..",
    "a-b.example.com",
    "-",
    "a.-b.com",
    "a.b-.com",
    "a.b.c.d.e.f.g.h",
    "a.elasticbeanstalk.com",
    "x.ap-southeast-4.elasticbeanstalk.com",
    "x.retool.app",
    "x.auth.ap-east-2.amazoncognito.com",
];

const PAIRS: &[(&str, &str)] = &[
    ("www.example.co.uk", "example.co.uk"),
    ("example.co.uk", "example.co.uk"),
    ("badexample.co.uk", "example.co.uk"),
    ("example.co.uk", "co.uk"),
    ("bad..example.co.uk", "example.co.uk"),
    ("localhost", "localhost"),
    ("a.b.replit.dev", "replit.dev"),
    ("a.b.replit.dev", "b.replit.dev"),
    ("x.teams.replit.dev", "teams.replit.dev"),
    (
        "a.us-east-1.cs.amazonlightsail.com",
        "us-east-1.cs.amazonlightsail.com",
    ),
];

fn main() {
    for name in NAMES {
        println!("case norm {name}");
        match normalize(name) {
            Ok(value) => println!("result ok {value}"),
            Err(_) => println!("result err"),
        }
        println!("case base {name}");
        match registrable_domain(name) {
            Some(value) => println!("result ok {value}"),
            None => println!("result err"),
        }
    }
    for (name, suffix) in PAIRS {
        println!("case member {name} {suffix}");
        println!("result {}", u8::from(is_member(name, suffix)));
    }
}

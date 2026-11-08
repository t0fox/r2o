//! CL15: Rust trace d2k_resource_* (HTML/CSS hints).

use r2o_controller::r2o_resource::R2oResourceScan;

fn run(name: &str, input: &str) {
    let mut scan = R2oResourceScan::default();
    scan.feed(input.as_bytes());
    let resources = scan.resources();
    println!("case {name}\ncount={}", resources.len());
    for (index, resource) in resources.iter().enumerate() {
        println!("res {index} host={} path={}", resource.host, resource.path);
    }
}

fn main() {
    run(
        "link-basic",
        "<link rel=\"stylesheet\" href=\"https://example.com/style.css\">",
    );
    run(
        "link-protocol-relative",
        "<link rel=\"stylesheet\" href=\"//cdn.example.com/a.css\">",
    );
    run(
        "link-relative",
        "<link rel=\"stylesheet\" href=\"/local.css\">",
    );
    run(
        "link-non-css",
        "<link rel=\"stylesheet\" href=\"https://example.com/app.js\">",
    );
    run(
        "link-query",
        "<link rel=\"stylesheet\" href=\"https://example.com/style.css?x=1\">",
    );
    run(
        "link-parent",
        "<link rel=\"stylesheet\" href=\"https://example.com/../a.css\">",
    );
    run(
        "link-uppercase",
        "<LINK REL=\"stylesheet\" HREF=\"HTTPS://Example.COM/Style.CSS\">",
    );
    run(
        "two-hosts",
        "<link rel=\"stylesheet\" href=\"https://a.example/a.css\">\
         <link rel=\"stylesheet\" href=\"https://b.example/b.css\">",
    );
    run(
        "same-host",
        "<link rel=\"stylesheet\" href=\"https://a.example/a.css\">\
         <link rel=\"stylesheet\" href=\"https://a.example/b.css\">",
    );
    run(
        "capacity",
        "<link rel=\"stylesheet\" href=\"https://a.example/a.css\">\
         <link rel=\"stylesheet\" href=\"https://b.example/b.css\">\
         <link rel=\"stylesheet\" href=\"https://c.example/c.css\">",
    );
    run(
        "css-url",
        "<style>body{background:url(https://cdn.example.com/bg.css)}</style>",
    );
    run(
        "css-import",
        "<style>@import \"https://cdn.example.com/imp.css\";</style>",
    );
    run(
        "script-raw",
        "<script>var x = \"https://bad.example/x.css\";</script>",
    );
    run(
        "comment",
        "<!-- <link rel=\"stylesheet\" href=\"https://example.com/a.css\"> -->",
    );
    run(
        "unquoted",
        "<link rel=stylesheet href=https://example.com/a.css>",
    );
    run(
        "single-quoted",
        "<link rel='stylesheet' href='https://example.com/a.css'>",
    );
    run(
        "host-underscore",
        "<link rel=\"stylesheet\" href=\"https://bad_host/a.css\">",
    );
    run(
        "host-trailing-dot",
        "<link rel=\"stylesheet\" href=\"https://example.com./a.css\">",
    );
    run(
        "http",
        "<link rel=\"stylesheet\" href=\"http://example.com/a.css\">",
    );
    run(
        "path-dot",
        "<link rel=\"stylesheet\" href=\"https://example.com/a.b.css\">",
    );
    run(
        "path-dot-segment",
        "<link rel=\"stylesheet\" href=\"https://example.com/./a.css\">",
    );
    run("empty", "");
}

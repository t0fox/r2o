use r2o_controller::r2o_resource::{R2oResourceBodyTap, R2oResourceScan, r2o_resource_path_ok};

#[test]
fn r2o_сканер_находит_только_публичные_css_ссылки() {
    let mut scanner = R2oResourceScan::default();
    for part in [
        b"<LINK href='https://cdn.test/styles/main.CSS' rel='StyleSheet'>".as_slice(),
        b"<body><link rel='stylesheet' href='https://late.test/c.css'>".as_slice(),
    ] {
        scanner.feed(part);
    }

    let resources = scanner.resources();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].host, "cdn.test");
    assert_eq!(resources[0].path, "/styles/main.CSS");
}

#[test]
fn r2o_сканер_распознаёт_css_url_и_не_добавляет_один_хост_дважды() {
    let mut scanner = R2oResourceScan::default();
    scanner.feed(
        b"url(https://same.test/first.css); @import url(https://same.test/second.css); url(https://other.test/site.css)",
    );

    let resources = scanner.resources();
    assert_eq!(resources.len(), 2);
    assert_eq!(resources[0].path, "/first.css");
    assert_eq!(resources[1].host, "other.test");
}

#[test]
fn r2o_путь_css_запрещает_запросы_каталоги_и_чужие_расширения() {
    assert!(r2o_resource_path_ok("/assets/app.CSS"));
    assert!(!r2o_resource_path_ok("//evil.test/app.css"));
    assert!(!r2o_resource_path_ok("/assets/../app.css"));
    assert!(!r2o_resource_path_ok("/assets/app.css?token=secret"));
    assert!(!r2o_resource_path_ok("/assets/app.js"));
}

#[test]
fn r2o_сканирование_chunked_объединяет_границы_чанков() {
    let html = b"<link rel=stylesheet href='https://cdn.test/site.css'>";
    let mut encoded = Vec::new();
    for part in html.chunks(7) {
        encoded.extend_from_slice(format!("{:X}\r\n", part.len()).as_bytes());
        encoded.extend_from_slice(part);
        encoded.extend_from_slice(b"\r\n");
    }
    encoded.extend_from_slice(b"0\r\n\r\n");

    let mut tap = R2oResourceBodyTap::new(true);
    for part in encoded.chunks(5) {
        tap.feed(part);
    }

    let resources = tap.resources();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].host, "cdn.test");
    assert_eq!(resources[0].path, "/site.css");
}

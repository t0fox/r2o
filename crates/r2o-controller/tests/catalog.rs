use r2o_controller::catalog::Catalog;
use serde_json::Value;
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn accepts_old_catalogs_and_null_arrays_without_inventing_measurements() {
    let input = br#"{"boxes":[{"id":"box-1","created":"2026-09-06T04:08:02Z","updated":"2026-09-07T07:13:56Z","fingerprint":{"method":1,"signals":[]},"plans":null,"bindings":[{"kind":"name","target":"example.org","plan_id":"plan-1","confirmed":"2026-09-06T04:09:29.08957744Z"}]}]}"#;
    let catalog = Catalog::parse(input).unwrap();
    assert_eq!(catalog.boxes.len(), 1);
    assert!(catalog.boxes[0].plans.is_empty());
    assert_eq!(catalog.boxes[0].bindings[0].transport, 0);
    assert_eq!(catalog.boxes[0].bindings[0].shape, 0);
    assert_eq!(catalog.boxes[0].bindings[0].verified_by, 0);
    assert_eq!(catalog.boxes[0].bindings[0].confirmed, 1_788_667_769);
}

#[test]
fn null_top_level_boxes_means_an_empty_catalog() {
    let catalog = Catalog::parse(br#"{"schema":1,"boxes":null,"unknown":true}"#).unwrap();
    assert!(catalog.boxes.is_empty());
}

#[test]
fn rejects_float_integer_overlong_string_and_ninth_signal() {
    let float = minimal_with_plan("\"successes\":3.14,");
    assert!(Catalog::parse(float.as_bytes()).is_err());

    let long_id = "x".repeat(40);
    let long = format!(r#"{{"boxes":[{{"id":"{long_id}","fingerprint":{{"signals":[]}}}}]}}"#);
    assert!(Catalog::parse(long.as_bytes()).is_err());

    let nine = (0..9)
        .map(|_| r#"{"kind":"rst","seen":1}"#)
        .collect::<Vec<_>>()
        .join(",");
    let too_many =
        format!(r#"{{"boxes":[{{"id":"box-1","fingerprint":{{"signals":[{nine}]}}}}]}}"#);
    assert!(Catalog::parse(too_many.as_bytes()).is_err());
}

#[test]
fn skips_unknown_fields_and_round_trips_known_measurement_context() {
    let input = br#"{
      "schema":1,
      "unknown":{"deep":[1,true,null]},
      "boxes":[{
        "id":"box-1","created":"2026-09-06T04:08:02Z","updated":"2026-09-07T07:13:56Z",
        "fingerprint":{"method":2,"signals":[{"kind":"rx-volume","ttl":126,"ttl_delta":-3,"tos":136,"ipid":54321,"volume":16,"seen":2,"packets":45,"future":1}]},
        "plans":[{"id":"plan-1","proto":"tls","text":"payload \u2603","added":"2026-09-06T04:09:29Z","successes":4,"enabled":true}],
        "bindings":[{"kind":"name","target":"example.org","plan_id":"plan-1","level":3,"confirmed":"2026-09-06T04:09:29Z","successes":2,"enabled":true,"transport":6,"family":4,"shape":1,"verified_by":1,"input":2,"probe_path":"/main.css","ech_origin":"edge.example","recheck_since":"2026-09-07T07:13:56Z","budget":3}]
      }]
    }"#;
    let catalog = Catalog::parse(input).unwrap();
    let serialized = catalog.to_json_at(1_788_765_236).unwrap();
    let value: Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(value["schema"], 1);
    assert_eq!(value["updated"], "2026-09-07T07:13:56Z");
    assert_eq!(
        value["boxes"][0]["fingerprint"]["signals"][0]["ttl_delta"],
        -3
    );
    assert_eq!(value["boxes"][0]["bindings"][0]["transport"], 6);
    assert_eq!(value["boxes"][0]["bindings"][0]["input"], 2);
    assert_eq!(value["boxes"][0]["bindings"][0]["probe_path"], "/main.css");
    assert_eq!(value["boxes"][0]["bindings"][0]["budget"], 3);
}

#[test]
fn rejects_trailing_garbage_and_excessive_nesting() {
    assert!(Catalog::parse(br#"{"boxes":[]} trailing"#).is_err());
    let nested = format!(
        "{{\"boxes\":[],\"unknown\":{}}}",
        "[".repeat(70) + "0" + &"]".repeat(70)
    );
    assert!(Catalog::parse(nested.as_bytes()).is_err());
}

#[test]
fn atomic_save_replaces_the_file_and_leaves_no_temporary_file() {
    let catalog = Catalog::parse(br#"{"boxes":null}"#).unwrap();
    let dir = temp_dir();
    let path = dir.join("catalog.json");
    fs::write(&path, b"old").unwrap();
    catalog.save_atomic(&path, 1_788_765_236).unwrap();
    let written = fs::read_to_string(&path).unwrap();
    let round_trip = Catalog::parse(written.as_bytes()).unwrap();
    assert!(round_trip.boxes.is_empty());
    assert!(!dir.join("catalog.json.new").exists());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn fingerprint_matching_uses_partial_evidence_and_all_same_kind_signals() {
    let catalog = Catalog::parse(
        br#"{"boxes":[{"id":"box-1","fingerprint":{"method":2,"signals":[
          {"kind":"rst","ttl":90,"tos":1,"ipid":1},
          {"kind":"rst","ttl":126,"tos":136,"ipid":54321},
          {"kind":"volume","volume":20}
        ]}}]}"#,
    )
    .unwrap();
    let observed = r2o_controller::catalog::Fingerprint {
        method: 2,
        signals: vec![
            r2o_controller::catalog::Signal {
                kind: "rst".into(),
                ttl: 127,
                tos: 136,
                ipid: 54321,
                ..Default::default()
            },
            r2o_controller::catalog::Signal {
                kind: "new-observation".into(),
                ..Default::default()
            },
        ],
    };
    assert_eq!(catalog.match_fingerprint(&observed), Some(0));
}

#[test]
fn fingerprint_match_requires_one_agreement_and_rejects_known_conflicts() {
    let catalog = Catalog::parse(
        br#"{"boxes":[{"id":"box-1","fingerprint":{"method":2,"signals":[
          {"kind":"rst","ttl":126,"tos":136,"ipid":54321}
        ]}},{"id":"box-2","fingerprint":{"method":1,"signals":[
          {"kind":"rst","ttl":126,"tos":136,"ipid":54321}
        ]}}]}"#,
    )
    .unwrap();
    let no_overlap = r2o_controller::catalog::Fingerprint {
        method: 2,
        signals: vec![r2o_controller::catalog::Signal {
            kind: "volume".into(),
            volume: 20,
            ..Default::default()
        }],
    };
    assert_eq!(catalog.match_fingerprint(&no_overlap), None);
    let conflict = r2o_controller::catalog::Fingerprint {
        method: 2,
        signals: vec![r2o_controller::catalog::Signal {
            kind: "rst".into(),
            ttl: 70,
            tos: 1,
            ipid: 2,
            ..Default::default()
        }],
    };
    assert_eq!(catalog.match_fingerprint(&conflict), None);
}

#[test]
fn derived_domain_groups_are_ignored_and_learning_observations_are_saved() {
    let forged = Catalog::parse(
        br#"{"boxes":[],"domain_groups":[{"suffix":"example.org","plan_id":"forged"}]}"#,
    )
    .unwrap();
    assert!(forged.domain_state.is_none());

    let learned = Catalog::parse(
        br#"{"boxes":[],"domain_observations":[{"name":"one.example.org","plan_id":"plan-1","transport":6,"family":4,"shape":1,"evidence":1,"at":"2026-09-07T07:13:56Z"}],"domain_groups_frozen":true,"domain_groups_disabled":false}"#,
    )
    .unwrap();
    let serialized = learned.to_json_at(1_788_765_236).unwrap();
    let value: Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(value["domain_groups"], serde_json::json!([]));
    assert_eq!(value["domain_observations"][0]["name"], "one.example.org");
    assert_eq!(value["domain_groups_frozen"], true);
}

#[test]
fn rejects_unknown_schema_versions_and_embedded_nuls() {
    assert!(Catalog::parse(br#"{"schema":2,"boxes":[]}"#).is_err());
    assert!(Catalog::parse(br#"{"boxes":[{"id":"box\u00001"}]}"#).is_err());
}

#[test]
fn imports_donor_catalog_and_converts_every_saved_plan_to_r2o() {
    let dir = temp_dir();
    let donor = dir.join("donor-catalog.json");
    let destination = dir.join("state/catalog.json");
    let source = include_bytes!("fixtures/donor/catalog-real.json");
    fs::write(&donor, source).unwrap();

    assert!(Catalog::import_donor_file(&donor, &destination, 1_792_440_000).unwrap());
    let migrated = Catalog::load(&destination).unwrap();
    assert_eq!(migrated.boxes.len(), 5);
    assert_eq!(
        migrated
            .boxes
            .iter()
            .flat_map(|record| &record.bindings)
            .filter(|binding| binding.enabled)
            .count(),
        318
    );
    let plans = migrated
        .boxes
        .iter()
        .flat_map(|record| &record.plans)
        .collect::<Vec<_>>();
    assert_eq!(plans.len(), 18);
    for plan in plans {
        assert!(plan.text.starts_with("r2o-plan "));
        r2o_controller::plan_text::compile_text(&plan.text)
            .unwrap_or_else(|error| panic!("план {} не прошёл проверку: {error}", plan.id));
    }
    let serialized = fs::read_to_string(&destination).unwrap();
    assert!(!serialized.contains("d2k-plan"));
    assert_eq!(fs::read(&donor).unwrap(), source);

    let before = fs::read(&destination).unwrap();
    assert!(!Catalog::import_donor_file(&donor, &destination, 1_792_440_001).unwrap());
    assert_eq!(fs::read(&destination).unwrap(), before);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn invalid_donor_plan_does_not_create_a_catalog() {
    let dir = temp_dir();
    let donor = dir.join("donor-catalog.json");
    let destination = dir.join("state/catalog.json");
    fs::write(
        &donor,
        br#"{"schema":1,"boxes":[{"id":"box-1","created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z","fingerprint":{"signals":[]},"plans":[{"id":"plan-1","proto":"tls","text":"d2k-plan 1 1\nunknown-directive 1\n","added":"2026-01-01T00:00:00Z"}]}]}"#,
    )
    .unwrap();

    assert!(Catalog::import_donor_file(&donor, &destination, 1_792_440_000).is_err());
    assert!(!destination.exists());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn donor_catalog_import_cli_reports_and_publishes_the_migration() {
    let dir = temp_dir();
    let donor = dir.join("donor-catalog.json");
    let destination = dir.join("state/catalog.json");
    fs::write(&donor, include_bytes!("fixtures/donor/catalog-real.json")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args([
            "--import-donor-catalog",
            donor.to_str().unwrap(),
            destination.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "импорт не выполнен: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("каталог донора перенесён"));
    let imported = Catalog::load(&destination).unwrap();
    assert_eq!(imported.boxes.len(), 5);
    assert_eq!(
        imported
            .boxes
            .iter()
            .flat_map(|record| &record.plans)
            .count(),
        18
    );
    assert_eq!(
        fs::read(&donor).unwrap().as_slice(),
        include_bytes!("fixtures/donor/catalog-real.json").as_slice()
    );
    fs::remove_dir_all(dir).unwrap();
}

fn minimal_with_plan(extra: &str) -> String {
    format!(
        r#"{{"boxes":[{{"id":"box-1","fingerprint":{{"signals":[]}},"plans":[{{"id":"plan-1","proto":"tls","text":"x","added":"2026-01-01T00:00:00Z",{extra}"enabled":true}}]}}]}}"#
    )
}

fn temp_dir() -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("r2o-catalog-test-{}-{nonce}", std::process::id()));
    fs::create_dir(&path).unwrap();
    path
}

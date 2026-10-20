use std::process::Command;

#[test]
fn lists_the_five_http_plan_texts_with_stable_ids() {
    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .arg("--http-candidates")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for key in [
        "split",
        "fake-badsum-whole",
        "fake-badsum",
        "disorder",
        "fake-seqshift",
    ] {
        assert!(stdout.contains(&format!("кандидат: {key}\n")));
    }
    assert_eq!(stdout.matches("r2o-plan 1 11\n").count(), 5);
    assert!(stdout.contains("id cf9577bf11c484fe4b4b0fe08b4681f3\n"));
    assert!(stdout.contains("poison 1 badsum\n"));
    assert!(stdout.contains("poison 1 seqshift=-66000\n"));

    let ids: Vec<_> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("id "))
        .collect();
    let mut unique = ids.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(ids.len(), 5);
    assert_eq!(unique.len(), 5);
}

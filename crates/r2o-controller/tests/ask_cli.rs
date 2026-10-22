use std::process::Command;

#[test]
fn ask_help_exposes_snapshot_and_saved_hello_inputs() {
    let output = Command::new(env!("CARGO_BIN_EXE_r2o-controller"))
        .args(["--ask", "--help"])
        .output()
        .expect("r2o-controller should start");

    assert!(
        output.status.success(),
        "ask help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let help = String::from_utf8(output.stdout).expect("help should be UTF-8");
    assert!(help.contains("--control"));
    assert!(help.contains("--hello-hex"));
    assert!(help.contains("--arm-wait-ms"));
    assert!(help.contains("--control-hex"));
}

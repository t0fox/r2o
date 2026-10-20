use std::process::Command;

fn r2o_run_fetch(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_r2o-fetch"))
        .args(args)
        .output()
        .expect("r2o-fetch должен запускаться")
}

#[test]
fn r2o_help_показывает_бюджет_quic_и_значение_по_умолчанию() {
    let output = r2o_run_fetch(&["--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("[--quic-budget N]"));
    assert!(help.contains("--quic-budget N"));
    assert!(help.contains("по умолчанию N=25"));
    assert!(help.contains("0 отключает бюджет"));
    assert!(!help.contains("пока нет донорского пакетного бюджета"));
}

#[test]
fn r2o_budget_quic_без_quic_завершается_ошибкой_аргумента() {
    let output = r2o_run_fetch(&["--name", "example.com", "--quic-budget", "1"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("требует --quic"));
}

#[test]
fn r2o_budget_quic_принимает_целое_и_отклоняет_tls12_до_сети() {
    let output = r2o_run_fetch(&[
        "--name",
        "example.com",
        "--quic",
        "--quic-budget",
        "1",
        "--tls12",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("QUIC использует TLS 1.3"));
}

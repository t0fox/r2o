use std::process::Command;

#[test]
fn help_uses_r2o_telegram_command_name() {
    let output = Command::new(env!("CARGO_BIN_EXE_r2o-telegram"))
        .arg("--help")
        .output()
        .expect("Telegram proxy help should start");
    assert!(output.status.success());

    let help = String::from_utf8_lossy(&output.stdout);
    assert!(
        help.contains("Использование: r2o-telegram"),
        "unexpected help output:\n{help}"
    );
    assert!(
        help.contains("Параметры:"),
        "help header is not localized:\n{help}"
    );
    assert!(
        help.contains("Показать эту справку"),
        "help flag is not localized:\n{help}"
    );
    assert!(
        help.contains("Показать версию"),
        "version flag is not localized:\n{help}"
    );
    assert!(
        !help.contains("OpenWrt"),
        "the standalone component still identifies itself as OpenWrt-only:\n{help}"
    );
}

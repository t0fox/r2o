use clap::Parser;
use r2o_telegram::config::Config;

#[test]
fn generic_proxy_arguments_are_rejected_by_the_transparent_configuration() {
    for arguments in [
        vec!["r2o-telegram", "--transparent"],
        vec!["r2o-telegram", "--link-ip", "192.0.2.1"],
        vec![
            "r2o-telegram",
            "--secret",
            "11111111111111111111111111111111",
        ],
        vec!["r2o-telegram", "--listen-faketls-domain", "example.com"],
        vec!["r2o-telegram", "--pool-size", "0"],
        vec!["r2o-telegram", "--dc-ip", "2:149.154.167.51"],
        vec![
            "r2o-telegram",
            "--mtproto-proxy",
            "proxy.example:443:secret",
        ],
        vec!["r2o-telegram", "--no-outbound-proxy"],
    ] {
        let result = Config::try_parse_from(arguments.clone());
        assert!(
            result.is_err(),
            "legacy arguments were accepted: {arguments:?}"
        );
    }
}

#[test]
fn help_exposes_only_the_transparent_listener_and_connection_controls() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_r2o-telegram"))
        .arg("--help")
        .output()
        .expect("r2o-telegram help should start");
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    for option in [
        "--port",
        "--max-connections",
        "--transparent-ports",
        "--transparent-cidrs",
    ] {
        assert!(help.contains(option), "missing listener option {option}");
    }
    for option in [
        "--transparent ",
        "--link-ip",
        "--secret",
        "--listen-faketls-domain",
        "--pool-size",
        "--mtproto-proxy",
        "--dc-ip",
    ] {
        assert!(
            !help.contains(option),
            "legacy option remains in help: {option}"
        );
    }
}

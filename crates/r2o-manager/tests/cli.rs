use flate2::Compression;
use flate2::write::GzEncoder;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("r2o-manager-cli-{}-{sequence}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn make_bundle(parent: &Path, name: &str) -> PathBuf {
    let bundle = parent.join(name);
    let builds = bundle.join("builds");
    fs::create_dir_all(&builds).unwrap();
    for component in [
        "r2o-datapath",
        "r2o-controller",
        "r2o-panel",
        "r2o-telegram",
        "r2o-manager",
        "r2o-fetch",
    ] {
        let path = builds.join(format!("{component}-linux-mipsel"));
        fs::write(&path, format!("{name}:{component}")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    bundle
}

fn invoke(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_r2o-manager"))
        .args(args)
        .output()
        .unwrap()
}

fn json_output(output: Output) -> Value {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn signed_archive() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for component in [
        "r2o-datapath",
        "r2o-controller",
        "r2o-panel",
        "r2o-telegram",
        "r2o-manager",
        "r2o-fetch",
    ] {
        let path = format!("builds/{component}-linux-mipsel");
        let content = format!("fixture:{component}");
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(content.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, path, content.as_bytes())
            .unwrap();
    }
    builder.finish().unwrap();
    let archive = builder.into_inner().unwrap().finish().unwrap();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let digest = format!("{:x}", Sha256::digest(&archive));
    let manifest = format!(
        r#"{{"release_id":"r2o-cli-archive","version":"0.1.0","notes":"cli","assets":{{"mipsel":{{"sha256":"{digest}"}}}}}}"#
    )
    .into_bytes();
    let signature = key_pair.sign(&manifest).as_ref().to_vec();
    let public_key = key_pair.public_key().as_ref().to_vec();
    (archive, manifest, signature, public_key)
}

#[test]
fn local_activation_and_rollback_work_through_cli() {
    let temp = TestDir::new();
    let root = temp.0.join("install");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("config"), "operator setting\n").unwrap();
    let first_bundle = make_bundle(&temp.0, "bundle-one");
    let second_bundle = make_bundle(&temp.0, "bundle-two");

    let first = json_output(invoke(&[
        "install-local",
        "--root",
        root.to_str().unwrap(),
        "--bundle",
        first_bundle.to_str().unwrap(),
        "--release-id",
        "r2o-1",
        "--architecture",
        "mipsel",
    ]));
    assert_eq!(first["current"], "r2o-1");
    assert!(first["previous"].is_null());

    let second = json_output(invoke(&[
        "install-local",
        "--root",
        root.to_str().unwrap(),
        "--bundle",
        second_bundle.to_str().unwrap(),
        "--release-id",
        "r2o-2",
        "--architecture",
        "mipsel",
    ]));
    assert_eq!(second["current"], "r2o-2");
    assert_eq!(second["previous"], "r2o-1");

    let rolled_back = json_output(invoke(&["rollback", "--root", root.to_str().unwrap()]));
    assert_eq!(rolled_back["current"], "r2o-1");
    assert_eq!(rolled_back["previous"], "r2o-2");
    assert_eq!(
        fs::read_to_string(root.join("config")).unwrap(),
        "operator setting\n"
    );
}

#[test]
fn manager_version_is_available_for_router_smoke_checks() {
    let output = invoke(&["--version"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "r2o-manager 0.1.0\n"
    );
}

#[test]
fn update_mark_bad_previous_cli_records_runtime_failure_after_rollback() {
    let temp = TestDir::new();
    let root = temp.0.join("install");
    for release in ["r2o-good", "r2o-bad"] {
        let path = root.join("releases").join(release);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("release-architecture"), "mipsel").unwrap();
    }
    fs::write(
        root.join("release-slots"),
        "R2O-RELEASE-SLOTS-1\nr2o-good\nr2o-bad\n",
    )
    .unwrap();

    let recorded = json_output(invoke(&[
        "update-mark-bad-previous",
        "--root",
        root.to_str().unwrap(),
    ]));
    assert_eq!(recorded["current"], "r2o-good");
    assert_eq!(recorded["bad_release"], "r2o-bad");
    let state: Value =
        serde_json::from_slice(&fs::read(root.join("state/update.json")).unwrap()).unwrap();
    assert_eq!(state["current"], "r2o-good");
    assert_eq!(state["bad_release"], "r2o-bad");
    assert_eq!(state["last_ok"], false);
    assert_eq!(state["last_release"], "r2o-bad");
}

#[test]
fn router_config_default_matches_d2o_panel_bind_default() {
    let defaults = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../router/config.default");
    let config = fs::read_to_string(defaults).unwrap();
    let d2o_default = include_str!("../../r2o-panel/tests/fixtures/d2o-panel-listen-default.txt")
        .lines()
        .find_map(|line| line.strip_prefix("PANEL_LISTEN="))
        .unwrap();
    assert!(
        config
            .lines()
            .any(|line| line == format!("PANEL_LISTEN={d2o_default}"))
    );
}

#[test]
fn first_config_initialization_imports_supported_settings_without_evaluating_donor_file() {
    let temp = TestDir::new();
    let root = temp.0.join("install");
    let defaults = temp.0.join("config.default");
    let donor = temp.0.join("donor-config");
    fs::write(
        &defaults,
        "SCHEMA=1\nMODE=apply\nSTATE_DIR=/opt/r2o/state\nQUEUE_NUM=2000\nQUEUE_NUM6=2001\nR2O_FLOW_CAPACITY=2048\nIPV6_ENABLED=1\nMARK=45\nAUTOUPDATE=1\nLOGMAX=2097152\nLOGKEEP=1048576\nLOG_EVERY=60\nFW_BACKEND=auto\nPORTS=0:65535\nCONNBYTES=0:8\nVOICE_PORTS=50000:50099,1400,3478:3481,5349,19294:19344\nVOICE_CONNBYTES=0:4\nHTTP_KEEPALIVE_PORTS=80\nDNS_PORTS=53,853\nPANEL_LISTEN=127.0.0.1:8090\nTG_ENABLED=1\nTG_MODE=local\nTG_PORT=1443\nR2O_PPE_DEOFFLOAD=1\n",
    )
    .unwrap();
    let donor_text = "SCHEMA=1\nMODE=observe # preserve a documented mode\nSTATE_DIR=/opt/d2k/state # migrate state path\nQUEUE_NUM=1234 # documented queue\nQUEUE_NUM6=1235\nFLOWS=64\nMARK=0x2f\nLOGMAX=4194304\nLOGKEEP=2097152\nLOG_EVERY=120\nPORTS=80,443\nCONNBYTES=0:12\nVOICE_PORTS=3478:3481\nVOICE_CONNBYTES=0:6\nHTTP_KEEPALIVE_PORTS=8080\nDNS_PORTS=53,853,5353\nPANEL_LISTEN=\"127.0.0.1:8091\" # quoted setting with comment\nTG_ENABLED=0\nTG_MODE=relay\nTG_PORT=1445\nCONTROL_SOCKET=/opt/d2k/run/d2kd.sock\nD2K_PPE_DEOFFLOAD=0\nUNKNOWN=$(touch SHOULD_NOT_RUN)\n";
    fs::write(&donor, donor_text).unwrap();

    let output = invoke(&[
        "config-init",
        "--root",
        root.to_str().unwrap(),
        "--defaults",
        defaults.to_str().unwrap(),
        "--donor-config",
        donor.to_str().unwrap(),
    ]);
    let result = json_output(output);
    let config = fs::read_to_string(root.join("config")).unwrap();

    assert_eq!(result["created"], true);
    assert_eq!(result["state_dir"], "/opt/r2o/state");
    assert_eq!(result["donor_state_dir"], "/opt/d2k/state");
    assert!(config.contains("MODE=observe\n"));
    assert!(config.contains("STATE_DIR=/opt/r2o/state\n"));
    assert!(config.contains("QUEUE_NUM=1234\n"));
    assert!(config.contains("QUEUE_NUM6=1235\n"));
    assert!(config.contains("PANEL_LISTEN=127.0.0.1:8091\n"));
    assert!(config.contains("R2O_FLOW_CAPACITY=64\n"));
    assert!(config.contains("MARK=0x2f\n"));
    assert!(config.contains("LOGMAX=4194304\n"));
    assert!(config.contains("LOGKEEP=2097152\n"));
    assert!(config.contains("LOG_EVERY=120\n"));
    assert!(config.contains("PORTS=80,443\n"));
    assert!(config.contains("CONNBYTES=0:12\n"));
    assert!(config.contains("VOICE_PORTS=3478:3481\n"));
    assert!(config.contains("VOICE_CONNBYTES=0:6\n"));
    assert!(config.contains("HTTP_KEEPALIVE_PORTS=8080\n"));
    assert!(config.contains("DNS_PORTS=53,853,5353\n"));
    assert!(config.contains("TG_ENABLED=0\n"));
    assert!(config.contains("TG_MODE=local\n"));
    assert!(config.contains("TG_PORT=1445\n"));
    assert!(config.contains("R2O_PPE_DEOFFLOAD=0\n"));
    assert!(!config.contains("d2k"));
    assert!(!config.contains("CONTROL_SOCKET"));
    assert!(!config.contains("D2K_PPE_DEOFFLOAD"));
    assert!(!temp.0.join("SHOULD_NOT_RUN").exists());
    assert_eq!(fs::read_to_string(donor).unwrap(), donor_text);
    assert!(
        result["unsupported"]
            .as_array()
            .unwrap()
            .iter()
            .all(|key| key != "D2K_PPE_DEOFFLOAD")
    );
}

#[test]
fn donor_firewall_settings_reject_invalid_port_lists_and_connbytes_windows() {
    let defaults = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../router/config.default");
    let temp = TestDir::new();
    for (key, value) in [
        ("PORTS", "80:80"),
        ("PORTS", "443;$(touch SHOULD_NOT_RUN)"),
        ("PORTS", "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16"),
        ("CONNBYTES", "0:8:9"),
        ("VOICE_PORTS", "0:65536"),
        ("VOICE_CONNBYTES", "8:4"),
        ("HTTP_KEEPALIVE_PORTS", "80,,443"),
        ("DNS_PORTS", "53, 853"),
        ("TG_PORT", "0"),
        ("TG_PORT", "65536"),
        ("D2K_PPE_DEOFFLOAD", "2"),
    ] {
        let root = temp.0.join(format!("install-{key}"));
        let donor = temp.0.join(format!("donor-{key}"));
        fs::write(&donor, format!("{key}={value}\n")).unwrap();
        let output = invoke(&[
            "config-init",
            "--root",
            root.to_str().unwrap(),
            "--defaults",
            defaults.to_str().unwrap(),
            "--donor-config",
            donor.to_str().unwrap(),
        ]);
        assert!(
            !output.status.success(),
            "accepted unsafe donor setting {key}={value}"
        );
        assert!(!root.join("config").exists());
    }
    assert!(!temp.0.join("SHOULD_NOT_RUN").exists());
}

#[test]
fn shipped_openwrt_defaults_initialize() {
    let temp = TestDir::new();
    let root = temp.0.join("install");
    let defaults = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../router/config.default");

    let output = invoke(&[
        "config-init",
        "--root",
        root.to_str().unwrap(),
        "--defaults",
        defaults.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "shipped defaults were rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config = fs::read_to_string(root.join("config")).unwrap();
    assert!(config.contains("R2O_MEASUREMENT_LIMIT=64\n"));
    assert!(config.contains("PROBE_MARK=46\n"));
    assert!(config.contains("MEASURE_MARK=47\n"));
    assert!(config.contains("ONLY_MARK=\n"));
    assert!(config.contains("TG_PORT=1443\n"));
    assert!(config.contains("D2K_GATE=\n"));
}

#[test]
fn config_init_preserves_only_a_safe_d2k_gate_endpoint() {
    let temp = TestDir::new();
    let defaults = temp.0.join("config.default");
    fs::write(&defaults, "SCHEMA=1\nD2K_GATE=\n").unwrap();
    let donor = temp.0.join("donor");
    fs::write(&donor, "D2K_GATE=http://203.0.113.9:8443/update\n").unwrap();
    let root = temp.0.join("valid");
    let output = invoke(&[
        "config-init",
        "--root",
        root.to_str().unwrap(),
        "--defaults",
        defaults.to_str().unwrap(),
        "--donor-config",
        donor.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(root.join("config")).unwrap(),
        "SCHEMA=1\nD2K_GATE=http://203.0.113.9:8443/update\n"
    );

    for (index, invalid) in [
        "http://203.0.113.9:8443;touch x",
        "http://256.0.0.1:8443",
        "http://203.0.113.9:65536",
    ]
    .into_iter()
    .enumerate()
    {
        fs::write(&donor, format!("D2K_GATE={invalid}\n")).unwrap();
        let root = temp.0.join(format!("invalid-{index}"));
        let output = invoke(&[
            "config-init",
            "--root",
            root.to_str().unwrap(),
            "--defaults",
            defaults.to_str().unwrap(),
            "--donor-config",
            donor.to_str().unwrap(),
        ]);
        assert!(!output.status.success(), "accepted unsafe gate {invalid}");
        assert!(!root.join("config").exists());
    }
}

#[test]
fn defaults_reject_invalid_probe_and_only_mark_values() {
    let temp = TestDir::new();
    let root = temp.0.join("install");
    let defaults = temp.0.join("config.default");
    for (probe_mark, only_mark) in [("4294967296", ""), ("0", "7/0"), ("0", "7/8/1")] {
        fs::write(
            &defaults,
            format!("MODE=apply\nPROBE_MARK={probe_mark}\nONLY_MARK={only_mark}\n"),
        )
        .unwrap();
        let output = invoke(&[
            "config-init",
            "--root",
            root.to_str().unwrap(),
            "--defaults",
            defaults.to_str().unwrap(),
        ]);
        assert!(
            !output.status.success(),
            "accepted PROBE_MARK={probe_mark}, ONLY_MARK={only_mark}"
        );
        assert!(!root.join("config").exists());
    }
}

#[test]
fn defaults_reject_invalid_measure_mark_values() {
    let temp = TestDir::new();
    let root = temp.0.join("install");
    let defaults = temp.0.join("config.default");
    for measure_mark in ["4294967296", "0x", "-1", "mark"] {
        fs::write(
            &defaults,
            format!("MODE=apply\nMARK=45\nPROBE_MARK=46\nMEASURE_MARK={measure_mark}\n"),
        )
        .unwrap();
        let output = invoke(&[
            "config-init",
            "--root",
            root.to_str().unwrap(),
            "--defaults",
            defaults.to_str().unwrap(),
        ]);
        assert!(
            !output.status.success(),
            "accepted MEASURE_MARK={measure_mark}"
        );
        assert!(!root.join("config").exists());
    }
}

#[test]
fn config_initialization_preserves_existing_operator_configuration() {
    let temp = TestDir::new();
    let root = temp.0.join("install");
    let defaults = temp.0.join("config.default");
    let donor = temp.0.join("donor-config");
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("config"),
        "MODE=off\nSTATE_DIR=/var/lib/r2o/state\n# настройки владельца\n",
    )
    .unwrap();
    fs::write(&defaults, "MODE=apply\n").unwrap();
    fs::write(&donor, "MODE=observe\n").unwrap();

    let output = invoke(&[
        "config-init",
        "--root",
        root.to_str().unwrap(),
        "--defaults",
        defaults.to_str().unwrap(),
        "--donor-config",
        donor.to_str().unwrap(),
    ]);
    let result = json_output(output);

    assert_eq!(result["created"], false);
    assert_eq!(result["state_dir"], "/var/lib/r2o/state");
    assert_eq!(
        fs::read_to_string(root.join("config")).unwrap(),
        "MODE=off\nSTATE_DIR=/var/lib/r2o/state\n# настройки владельца\n"
    );
}

#[test]
fn invalid_donor_config_does_not_create_partial_configuration() {
    let temp = TestDir::new();
    let root = temp.0.join("install");
    let defaults = temp.0.join("config.default");
    let donor = temp.0.join("donor-config");
    fs::write(&defaults, "MODE=apply\n").unwrap();
    fs::write(&donor, "MODE=$(touch SHOULD_NOT_RUN)\n").unwrap();

    let output = invoke(&[
        "config-init",
        "--root",
        root.to_str().unwrap(),
        "--defaults",
        defaults.to_str().unwrap(),
        "--donor-config",
        donor.to_str().unwrap(),
    ]);

    assert!(!output.status.success());
    assert!(!root.join("config").exists());
    assert!(!temp.0.join("SHOULD_NOT_RUN").exists());
}

#[test]
fn signed_archive_install_works_through_cli() {
    let temp = TestDir::new();
    let archive_path = temp.0.join("release.tar.gz");
    let manifest_path = temp.0.join("latest.json");
    let signature_path = temp.0.join("latest.json.sig");
    let public_key_path = temp.0.join("release-public.key");
    let (archive, manifest, signature, public_key) = signed_archive();
    fs::write(&archive_path, archive).unwrap();
    fs::write(&manifest_path, manifest).unwrap();
    fs::write(&signature_path, signature).unwrap();
    fs::write(&public_key_path, public_key).unwrap();
    let root = temp.0.join("install");

    let installed = json_output(invoke(&[
        "install-archive",
        "--root",
        root.to_str().unwrap(),
        "--archive",
        archive_path.to_str().unwrap(),
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--signature",
        signature_path.to_str().unwrap(),
        "--public-key",
        public_key_path.to_str().unwrap(),
        "--architecture",
        "mipsel",
    ]));
    assert!(installed["installed"].as_bool().unwrap_or(false));
    assert_eq!(installed["current"], "r2o-cli-archive");
    assert!(
        root.join("releases/r2o-cli-archive/builds/r2o-telegram-linux-mipsel")
            .is_file()
    );
}

#[cfg(unix)]
#[test]
fn stable_manager_exec_runs_only_a_component_from_the_active_slot() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TestDir::new();
    let root = temp.0.join("install");
    let bundle = make_bundle(&temp.0, "exec-bundle");
    let component = bundle.join("builds/r2o-datapath-linux-mipsel");
    fs::write(&component, "#!/bin/sh\nprintf 'active:%s\\n' \"$1\"\n").unwrap();
    fs::set_permissions(&component, fs::Permissions::from_mode(0o755)).unwrap();
    let fetch = bundle.join("builds/r2o-fetch-linux-mipsel");
    fs::write(&fetch, "#!/bin/sh\nprintf 'fetch:%s\\n' \"$1\"\n").unwrap();
    fs::set_permissions(&fetch, fs::Permissions::from_mode(0o755)).unwrap();
    json_output(invoke(&[
        "install-local",
        "--root",
        root.to_str().unwrap(),
        "--bundle",
        bundle.to_str().unwrap(),
        "--release-id",
        "r2o-exec",
        "--architecture",
        "mipsel",
    ]));

    let output = Command::new(env!("CARGO_BIN_EXE_r2o-manager"))
        .args([
            "exec",
            "--root",
            root.to_str().unwrap(),
            "--component",
            "r2o-datapath",
            "--",
            "argument",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exec failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "active:argument\n"
    );

    let output = Command::new(env!("CARGO_BIN_EXE_r2o-manager"))
        .args([
            "exec",
            "--root",
            root.to_str().unwrap(),
            "--component",
            "r2o-fetch",
            "--",
            "--version",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "exec fetch failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "fetch:--version\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("r2o-manager")).unwrap(),
        "exec-bundle:r2o-manager"
    );
}

#[test]
fn update_auto_cli_changes_only_the_auto_setting() {
    let temp = TestDir::new();
    let root = temp.0.join("install");
    let state_dir = root.join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let state_path = state_dir.join("update.json");
    fs::write(
        &state_path,
        br#"{"busy":"","auto":true,"current":"r2o-1","checked_utc":123,"latest":{"release_id":"r2o-2"}}"#,
    )
    .unwrap();

    let updated = json_output(invoke(&[
        "update-auto",
        "--root",
        root.to_str().unwrap(),
        "--enabled",
        "0",
    ]));
    assert_eq!(updated["auto"], false);
    let state: Value = serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(state["auto"], false);
    assert_eq!(state["current"], "r2o-1");
    assert_eq!(state["checked_utc"], 123);
    assert_eq!(state["latest"]["release_id"], "r2o-2");

    let enabled = json_output(invoke(&[
        "update-auto",
        "--root",
        root.to_str().unwrap(),
        "--enabled",
        "1",
    ]));
    assert_eq!(enabled["auto"], true);
    let state: Value = serde_json::from_slice(&fs::read(state_path).unwrap()).unwrap();
    assert_eq!(state["auto"], true);
    assert_eq!(state["current"], "r2o-1");
}

#[test]
fn router_update_recovery_clears_staged_rollback_before_journal() {
    let temp = TestDir::new();
    let root = temp.0.join("install");
    let state = root.join("state");
    fs::create_dir_all(&state).unwrap();
    let bundle = make_bundle(&temp.0, "bundle");
    for release in ["r2o-base", "r2o-next"] {
        json_output(invoke(&[
            "install-local",
            "--root",
            root.to_str().unwrap(),
            "--bundle",
            bundle.to_str().unwrap(),
            "--release-id",
            release,
            "--architecture",
            "mipsel",
        ]));
    }
    let staged = state.join("update-stage.json");
    fs::write(
        &staged,
        br#"{"release_id":"r2o-base","architecture":"mipsel","kind":"previous"}"#,
    )
    .unwrap();
    let slots = fs::read(root.join("release-slots")).unwrap();
    let recover = ["update-recover", "--root", root.to_str().unwrap()];
    assert!(invoke(&recover).status.success());
    assert!(!staged.exists());
    assert_eq!(fs::read(root.join("release-slots")).unwrap(), slots);
    let status = state.join("update.json");
    let recovered = fs::read(&status).unwrap();
    let parsed: Value = serde_json::from_slice(&recovered).unwrap();
    assert_eq!(parsed["busy"], "");
    assert_eq!(parsed["last_ok"], false);
    assert!(invoke(&recover).status.success());
    assert_eq!(fs::read(&status).unwrap(), recovered);
}

#[test]
fn router_update_recovery_frees_unjournaled_extraction_space() {
    let temp = TestDir::new();
    let root = temp.0.join("install");
    let orphan = root.join(".install-123-0");
    let state = root.join("state");
    fs::create_dir_all(&orphan).unwrap();
    fs::create_dir_all(&state).unwrap();
    fs::write(orphan.join("partial-file"), b"interrupted extraction").unwrap();
    fs::write(
        state.join("update.json"),
        br#"{"format":1,"busy":"installing","phase":"verify"}"#,
    )
    .unwrap();
    fs::write(root.join("config"), b"MODE=observe\n").unwrap();
    let cache = state.join("update-download");
    fs::create_dir(&cache).unwrap();
    let partial = cache.join("4".repeat(64));
    fs::write(&partial, b"resumable data").unwrap();
    assert!(
        invoke(&["update-recover", "--root", root.to_str().unwrap()])
            .status
            .success()
    );
    assert!(!orphan.exists());
    assert_eq!(fs::read(root.join("config")).unwrap(), b"MODE=observe\n");
    assert_eq!(fs::read(partial).unwrap(), b"resumable data");
}

#[cfg(unix)]
#[test]
fn router_update_recovers_after_kill_and_preserves_operator_data() {
    use std::os::unix::fs::PermissionsExt;
    use std::thread;
    use std::time::{Duration, Instant};

    let temp = TestDir::new();
    let root = temp.0.join("install");
    fs::create_dir_all(root.join("state")).unwrap();
    fs::write(root.join("config"), "MODE=observe\n").unwrap();
    fs::write(
        root.join("state/catalog.json"),
        r#"{"schema":1,"boxes":[],"note":"данные пользователя"}"#,
    )
    .unwrap();
    for (id, name) in [("r2o-base", "base"), ("r2o-next", "next")] {
        let bundle = make_bundle(&temp.0, name);
        fs::create_dir(bundle.join("router")).unwrap();
        fs::write(bundle.join("router/update-schema"), "R2O-STATE-1\n").unwrap();
        json_output(invoke(&[
            "install-local",
            "--root",
            root.to_str().unwrap(),
            "--bundle",
            bundle.to_str().unwrap(),
            "--release-id",
            id,
            "--architecture",
            "mipsel",
        ]));
    }

    let service = temp.0.join("service");
    fs::write(
        &service,
        format!(
            r#"#!/bin/sh
if [ -n "${{R2O_FIXTURE_PPE:-}}" ]; then
    [ -z "${{R2O_FIREWALL+x}}" ] || exit 3
    [ "$R2O_PPE_ADAPTER" = "$R2O_FIXTURE_PPE" ] || exit 4
fi
printf '%s %s\n' "$1" "$(sed -n '2p' '{root}/release-slots')" >> '{dir}/events'
case "$1" in
    update-start)
        if [ -e '{dir}/hold' ]; then
            : > '{dir}/started'
            exec sleep 90
        fi
        if [ -e '{dir}/fail-base' ] && [ "$(sed -n '2p' '{root}/release-slots')" = r2o-base ]; then
            exit 1
        fi
        ;;
    update-stop)
        if [ -e '{dir}/fail-stop-base' ] && [ "$(sed -n '2p' '{root}/release-slots')" = r2o-base ]; then
            exit 1
        fi
        ;;
    update-health) ;;
    *) exit 2 ;;
esac
"#,
            dir = temp.0.display(),
            root = root.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&service, fs::Permissions::from_mode(0o700)).unwrap();
    let args = [
        "update-rollback",
        "--root",
        root.to_str().unwrap(),
        "--service",
        service.to_str().unwrap(),
    ];

    fs::write(temp.0.join("fail-stop-base"), []).unwrap();
    fs::write(temp.0.join("hold"), []).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_r2o-manager"))
        .args(args)
        .env("R2O_FIREWALL", root.join("releases/r2o-pruned/router/r2o-firewall.sh"))
        .env("R2O_PPE_ADAPTER", temp.0.join("custom-ppe"))
        .env("R2O_FIXTURE_PPE", temp.0.join("custom-ppe"))
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !temp.0.join("started").exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "обновлятор завершился до запуска службы"
        );
        assert!(Instant::now() < deadline, "служба не начала запуск");
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        r2o_manager::read_install_slots(&root)
            .unwrap()
            .unwrap()
            .current,
        "r2o-base"
    );
    assert!(!invoke(&args).status.success());
    assert!(
        !invoke(&["update-cancel", "--root", root.to_str().unwrap()])
            .status
            .success()
    );
    assert_eq!(
        fs::read_to_string(temp.0.join("events")).unwrap(),
        "update-stop r2o-next\nupdate-start r2o-base\n"
    );
    child.kill().unwrap();
    child.wait().unwrap();
    fs::remove_file(temp.0.join("hold")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while root.join("state/update-pending.json").exists()
        || !fs::read_to_string(temp.0.join("events"))
            .unwrap()
            .contains("update-start r2o-next")
    {
        assert!(
            Instant::now() < deadline,
            "независимая служба восстановления не завершилась"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if invoke(&["update-recover", "--root", root.to_str().unwrap()])
            .status
            .success()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "не снята блокировка восстановления"
        );
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        r2o_manager::read_install_slots(&root)
            .unwrap()
            .unwrap()
            .current,
        "r2o-next"
    );
    assert!(!root.join("state/update-pending.json").exists());

    fs::write(temp.0.join("fail-base"), []).unwrap();
    assert!(!invoke(&args).status.success());
    assert_eq!(
        r2o_manager::read_install_slots(&root)
            .unwrap()
            .unwrap()
            .current,
        "r2o-next"
    );
    fs::remove_file(temp.0.join("fail-base")).unwrap();
    fs::remove_file(temp.0.join("fail-stop-base")).unwrap();

    json_output(invoke(&args));
    assert_eq!(
        r2o_manager::read_install_slots(&root)
            .unwrap()
            .unwrap()
            .current,
        "r2o-base"
    );
    json_output(invoke(&args));
    assert_eq!(
        r2o_manager::read_install_slots(&root)
            .unwrap()
            .unwrap()
            .current,
        "r2o-next"
    );
    assert_eq!(
        fs::read_to_string(root.join("config")).unwrap(),
        "MODE=observe\n"
    );
    assert_eq!(
        fs::read_to_string(root.join("state/catalog.json")).unwrap(),
        r#"{"schema":1,"boxes":[],"note":"данные пользователя"}"#
    );
}

#[cfg(unix)]
#[test]
fn router_update_refuses_incompatible_state_before_service_changes() {
    let temp = TestDir::new();
    let root = temp.0.join("root");
    let bundle = make_bundle(&temp.0, "base");
    fs::create_dir_all(bundle.join("router")).unwrap();
    fs::write(bundle.join("router/update-schema"), "R2O-STATE-1\n").unwrap();
    json_output(invoke(&[
        "install-local",
        "--root",
        root.to_str().unwrap(),
        "--bundle",
        bundle.to_str().unwrap(),
        "--release-id",
        "r2o-base",
        "--architecture",
        "mipsel",
    ]));
    fs::create_dir_all(root.join("state")).unwrap();
    let catalog = root.join("state/catalog.json");
    fs::write(&catalog, r#"{"schema":2,"boxes":[]}"#).unwrap();
    let result = invoke(&[
        "update-install",
        "--root",
        root.to_str().unwrap(),
        "--service",
        "/no-adapter",
    ]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("версия обученного каталога"));
    assert_eq!(
        fs::read_to_string(catalog).unwrap(),
        r#"{"schema":2,"boxes":[]}"#
    );
    let status: Value =
        serde_json::from_slice(&fs::read(root.join("state/update.json")).unwrap()).unwrap();
    assert_eq!(status["last_ok"], false);
    assert!(
        status["last_message"]
            .as_str()
            .unwrap()
            .contains("версия обученного каталога")
    );
    assert!(!root.join("state/update-pending.json").exists());
}

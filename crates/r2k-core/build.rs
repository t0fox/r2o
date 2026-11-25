fn main() {
    // option_env! не отслеживается Cargo: release ID должен попадать в
    // control-протокол даже при инкрементальной пересборке.
    println!("cargo:rerun-if-env-changed=R2O_RELEASE_ID");
    println!("cargo:rerun-if-env-changed=R2O_BUILD_TOOLCHAIN");
    println!("cargo:rerun-if-env-changed=R2O_BUILD_ALLOCATOR");
    println!(
        "cargo:rustc-env=R2O_BUILD_TARGET={}",
        std::env::var("TARGET").unwrap()
    );
    let rustc = std::env::var_os("RUSTC").unwrap();
    if let Ok(output) = std::process::Command::new(rustc).arg("--version").output()
        && output.status.success()
    {
        println!(
            "cargo:rustc-env=R2O_BUILD_RUSTC={}",
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
}

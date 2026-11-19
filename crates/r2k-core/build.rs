fn main() {
    // option_env! не отслеживается Cargo: release ID должен попадать в
    // control-протокол даже при инкрементальной пересборке.
    println!("cargo:rerun-if-env-changed=R2O_RELEASE_ID");
}

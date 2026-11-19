fn main() {
    // option_env! не отслеживается Cargo: без этих строк смена release-метаданных
    // не пересобирает бинарник и панель показывает устаревшую версию.
    for key in [
        "R2O_RELEASE_ID",
        "R2O_RELEASE_TITLE",
        "R2O_COMMIT",
        "R2O_BUILT",
    ] {
        println!("cargo:rerun-if-env-changed={key}");
    }
}

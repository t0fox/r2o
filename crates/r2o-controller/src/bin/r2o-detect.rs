//! `r2o-detect` — CLI, совместимый с C `d2k-detect classify`.
//!
//! Отдельный бинарник нужен для построчной сверки `print_json`/`print_human`
//! и кодов возврата с донором `detect/main.c`, не затрагивая CLI контроллера.

fn main() {
    let arguments: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut stdout = stdout.lock();
    let mut stderr = stderr.lock();
    let status = r2o_controller::detect_cli::run(&arguments, &mut stdout, &mut stderr);
    std::process::exit(status);
}

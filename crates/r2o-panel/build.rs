use flate2::{Compression, write::GzEncoder};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::path::PathBuf;

fn main() -> io::Result<()> {
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

    println!("cargo:rerun-if-changed=assets");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo передаёт OUT_DIR"));
    for entry in fs::read_dir("assets")? {
        let path = entry?.path();
        if !matches!(
            path.extension().and_then(OsStr::to_str),
            Some("html" | "css" | "js")
        ) {
            continue;
        }
        let name = path
            .file_name()
            .expect("ресурс имеет имя")
            .to_string_lossy();
        let mut output = GzEncoder::new(
            File::create(out.join(format!("{name}.gz")))?,
            Compression::best(),
        );
        io::copy(&mut File::open(&path)?, &mut output)?;
        output.finish()?;
    }
    Ok(())
}

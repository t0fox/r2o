//! Печатает load/install DC map в формате C `d2o_dc_map_store_trace.c`.

use r2o_telegram::dc_map::{DcMapStore, DcSnapshot};

fn file_count(path: &str, now: i64) -> usize {
    let Ok(bytes) = std::fs::read(path) else {
        return 0;
    };
    let Ok(snapshot) = serde_json::from_slice::<DcSnapshot>(&bytes) else {
        return 0;
    };
    if r2o_telegram::dc_map::validate_snapshot(&snapshot, now).is_err() {
        return 0;
    }
    snapshot.endpoints.len()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("cache path");
    let now: i64 = args.next().expect("now").parse().expect("now");
    let store = DcMapStore::load(path.clone());
    let loaded = store
        .current()
        .map_or(0, |snapshot| snapshot.endpoints.len());
    println!("load rc=0 count={loaded} file={}", file_count(&path, now));

    let bytes = std::fs::read(&path).expect("cache file");
    let incoming: DcSnapshot = serde_json::from_slice(&bytes).expect("cache json");
    let installed = store.install(incoming, now).expect("install");
    println!(
        "install rc=0 count={} file={}",
        installed.endpoints.len(),
        file_count(&path, now)
    );
}

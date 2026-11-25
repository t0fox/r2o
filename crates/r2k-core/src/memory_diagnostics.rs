//! Metadata and optional Rust heap accounting for the existing diagnostic recorder.

#[derive(Clone, Copy)]
pub struct Build {
    pub target: &'static str,
    pub rustc: Option<&'static str>,
    pub toolchain: Option<&'static str>,
    pub allocator: Option<&'static str>,
}

pub const BUILD: Build = Build {
    target: env!("R2O_BUILD_TARGET"),
    rustc: option_env!("R2O_BUILD_RUSTC"),
    toolchain: option_env!("R2O_BUILD_TOOLCHAIN"),
    allocator: option_env!("R2O_BUILD_ALLOCATOR"),
};

/// Resolves malloc to its provider at runtime for dynamically linked binaries.
pub fn linked_allocator() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        // dladdr borrows the loader's DSO filename for the lifetime of that module.
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        let malloc = libc::malloc as *const () as *const libc::c_void;
        if unsafe { libc::dladdr(malloc, &mut info) } != 0 && !info.dli_fname.is_null() {
            let path = unsafe { std::ffi::CStr::from_ptr(info.dli_fname) };
            if let Some(name) = path
                .to_str()
                .ok()
                .and_then(|path| std::path::Path::new(path).file_name()?.to_str())
                .filter(|name| name.contains(".so") && !name.contains(['\r', '\n']))
            {
                return Some(format!("DSO {name}"));
            }
        }
    }
    BUILD.allocator.map(str::to_owned)
}

#[derive(Clone, Copy)]
pub struct Heap {
    pub bytes: usize,
    pub objects: usize,
    pub peak_bytes: usize,
}

pub fn heap() -> Option<Heap> {
    #[cfg(feature = "memory-diagnostics")]
    return Some(allocator::snapshot());
    #[cfg(not(feature = "memory-diagnostics"))]
    None
}

#[cfg(unix)]
pub fn publish(path: &std::path::Path, start_ticks: u64) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let pid = std::process::id();
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(format!(".tmp.{pid}"));
    let temporary = std::path::PathBuf::from(temporary);
    let _ = std::fs::remove_file(&temporary);
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        let snapshot = heap();
        writeln!(file, "{pid} {start_ticks}")?;
        writeln!(file, "{}", BUILD.target)?;
        writeln!(file, "{}", BUILD.rustc.unwrap_or(""))?;
        writeln!(file, "{}", BUILD.toolchain.unwrap_or(""))?;
        writeln!(file, "{}", linked_allocator().as_deref().unwrap_or(""))?;
        if let Some(snapshot) = snapshot {
            writeln!(
                file,
                "{} {} {}",
                snapshot.bytes, snapshot.objects, snapshot.peak_bytes
            )?;
        }
        drop(file);
        std::fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Panel and Telegram already publish a heartbeat every second.
#[cfg(unix)]
pub fn from_heartbeat(path: &std::path::Path, start_ticks: u64, uptime_ms: u64, last: &mut u64) {
    if uptime_ms.saturating_sub(*last) < 10_000 || start_ticks == 0 {
        return;
    }
    *last = uptime_ms;
    if let Some(state) = std::env::var_os("R2O_META_STATE_DIR") {
        let diagnostics = std::path::PathBuf::from(state).join("diagnostics");
        if diagnostics.join("enabled").is_file() && !diagnostics.join("paused").is_file() {
            let _ = publish(&path.with_extension("memory"), start_ticks);
        }
    }
}

#[cfg(feature = "memory-diagnostics")]
mod allocator {
    use super::Heap;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

    #[derive(Default)]
    struct Counters {
        bytes: AtomicUsize,
        objects: AtomicUsize,
        peak: AtomicUsize,
    }

    impl Counters {
        const fn new() -> Self {
            Self {
                bytes: AtomicUsize::new(0),
                objects: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
            }
        }

        fn add_bytes(&self, bytes: usize) {
            let live = self.bytes.fetch_add(bytes, Relaxed) + bytes;
            self.peak.fetch_max(live, Relaxed);
        }

        fn add(&self, bytes: usize) {
            self.add_bytes(bytes);
            self.objects.fetch_add(1, Relaxed);
        }

        fn remove(&self, bytes: usize) {
            self.bytes.fetch_sub(bytes, Relaxed);
            self.objects.fetch_sub(1, Relaxed);
        }

        fn resize(&self, before: usize, after: usize) {
            if after >= before {
                self.add_bytes(after - before);
            } else {
                self.bytes.fetch_sub(before - after, Relaxed);
            }
        }

        fn snapshot(&self) -> Heap {
            let bytes = self.bytes.load(Relaxed);
            Heap {
                bytes,
                objects: self.objects.load(Relaxed),
                peak_bytes: self.peak.load(Relaxed).max(bytes),
            }
        }
    }

    static COUNTERS: Counters = Counters::new();
    struct CountingSystem;

    #[global_allocator]
    static ALLOCATOR: CountingSystem = CountingSystem;

    // Counting only accounts for layouts accepted by the underlying System allocator.
    unsafe impl GlobalAlloc for CountingSystem {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let ptr = unsafe { System.alloc(layout) };
            if !ptr.is_null() {
                COUNTERS.add(layout.size());
            }
            ptr
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            let ptr = unsafe { System.alloc_zeroed(layout) };
            if !ptr.is_null() {
                COUNTERS.add(layout.size());
            }
            ptr
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            COUNTERS.remove(layout.size());
            unsafe { System.dealloc(ptr, layout) };
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            let new = unsafe { System.realloc(ptr, layout, size) };
            if !new.is_null() {
                COUNTERS.resize(layout.size(), size);
            }
            new
        }
    }

    pub(super) fn snapshot() -> Heap {
        COUNTERS.snapshot()
    }

    #[test]
    fn growth_and_shrink_preserve_object_count_and_peak() {
        let counts = Counters::new();
        counts.add(64);
        counts.add(16);
        counts.resize(64, 128);
        counts.resize(128, 32);
        counts.remove(16);
        let snapshot = counts.snapshot();
        assert_eq!(snapshot.bytes, 32);
        assert_eq!(snapshot.objects, 1);
        assert_eq!(snapshot.peak_bytes, 144);
    }
}

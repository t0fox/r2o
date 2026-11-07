//! Сопоставимое измерение удержания памяти для worker-аргументов R2O.
//!
//! D2O `test_sched_worker_lifecycle.c` выполняет 1500 циклов «задача →
//! worker-поток → освобождение аргумента» с двумя буферами ClientHello и
//! проверяет, что VmRSS/VmData после прогрева не растут больше чем на 5 МиБ.
//! R2O использует не поток на задачу, а пул постоянных worker-потоков, поэтому
//! здесь те же 1500 задач с двумя 4-КиБ буферами передаются через каналы и
//! освобождаются уже в worker-потоке.

#[cfg(target_os = "linux")]
mod linux {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    const CYCLES: usize = 1500;
    const WARM: usize = 128;
    const MEMORY_GROWTH_LIMIT_KIB: i64 = 5 * 1024;
    const CLIENT_HELLO_BYTES: usize = 4096;
    const WORKERS: usize = 4;

    struct WorkerArg {
        trigger: Box<[u8; CLIENT_HELLO_BYTES]>,
        control: Box<[u8; CLIENT_HELLO_BYTES]>,
    }

    fn proc_kib(key: &str) -> Option<i64> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name == key {
                return value.trim().trim_end_matches("kB").trim().parse().ok();
            }
        }
        None
    }

    #[test]
    fn cross_thread_worker_args_do_not_grow_process_memory() {
        let mut senders = Vec::with_capacity(WORKERS);
        let mut workers = Vec::with_capacity(WORKERS);
        for _ in 0..WORKERS {
            let (sender, receiver) = mpsc::sync_channel::<WorkerArg>(1);
            senders.push(sender);
            workers.push(thread::spawn(move || {
                while let Ok(arg) = receiver.recv() {
                    // Прикоснуться к обоим буферам, как worker в D2O при
                    // копировании приветствия и контроля.
                    let mut trigger_sum = 0_u64;
                    for byte in arg.trigger.iter() {
                        trigger_sum = trigger_sum.wrapping_add(u64::from(*byte));
                    }
                    let mut control_sum = 0_u64;
                    for byte in arg.control.iter() {
                        control_sum = control_sum.wrapping_add(u64::from(*byte));
                    }
                    std::hint::black_box(trigger_sum ^ control_sum);
                }
            }));
        }

        let rss_before = proc_kib("VmRSS");
        let data_before = proc_kib("VmData");
        let mut rss_warm = None;
        let mut data_warm = None;
        for index in 0..CYCLES {
            senders[index % WORKERS]
                .send(WorkerArg {
                    trigger: Box::new([0x42; CLIENT_HELLO_BYTES]),
                    control: Box::new([0x24; CLIENT_HELLO_BYTES]),
                })
                .unwrap();
            if index + 1 == WARM {
                // Дать очереди опустеть: после прогрева замеряем устойчивое
                // состояние, а не ещё не обработанный хвост.
                thread::sleep(Duration::from_millis(20));
                rss_warm = proc_kib("VmRSS");
                data_warm = proc_kib("VmData");
            }
        }
        drop(senders);
        for worker in workers {
            worker.join().unwrap();
        }
        let rss_after = proc_kib("VmRSS");
        let data_after = proc_kib("VmData");

        println!(
            "{CYCLES} mock TCP measurements: VmRSS {rss_before:?} -> {rss_warm:?} -> {rss_after:?} KiB, \
             VmData {data_before:?} -> {data_warm:?} -> {data_after:?} KiB (start/warm/end)"
        );
        if let (Some(warm), Some(after)) = (rss_warm, rss_after) {
            assert!(
                after <= warm + MEMORY_GROWTH_LIMIT_KIB,
                "VmRSS вырос после прогрева: {warm} -> {after} KiB"
            );
        }
        if let (Some(warm), Some(after)) = (data_warm, data_after) {
            assert!(
                after <= warm + MEMORY_GROWTH_LIMIT_KIB,
                "VmData вырос после прогрева: {warm} -> {after} KiB"
            );
        }
    }
}

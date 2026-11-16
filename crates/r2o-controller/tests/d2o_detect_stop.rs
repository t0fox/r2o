//! C/Rust differential липкой остановки службы (`d2k_detect_stop_all` /
//! `stop_asked`) и проверки, что после неё новые пробы не стартуют.

use std::sync::atomic::AtomicBool;

use r2o_controller::classify::{
    ClassifyOptions, ProbeBackend, ProbeError, ProbeRequest, Trigger, r2o_detect_stop_all,
    r2o_detect_stop_all_requested, run_with_backend,
};

fn stop_asked(task: Option<&AtomicBool>) -> bool {
    r2o_detect_stop_all_requested()
        || task.is_some_and(|task| task.load(std::sync::atomic::Ordering::Relaxed))
}

fn case_line(name: &str, task: Option<&AtomicBool>) -> String {
    format!(
        "case={name} global={} task={} stop={}\n",
        i32::from(r2o_detect_stop_all_requested()),
        task.map_or(-1, |task| i32::from(
            task.load(std::sync::atomic::Ordering::Relaxed)
        )),
        i32::from(stop_asked(task)),
    )
}

struct PanicBackend;

impl ProbeBackend for PanicBackend {
    fn probe(&mut self, _request: ProbeRequest<'_>) -> Result<bool, ProbeError> {
        panic!("после остановки службы новая проба не должна стартовать");
    }
}

#[test]
fn stop_all_is_sticky_and_blocks_new_probes() {
    let idle = AtomicBool::new(false);
    let stopped = AtomicBool::new(true);
    let mut output = String::new();
    output.push_str(&case_line("no_flags", Some(&idle)));
    output.push_str(&case_line("task_flag", Some(&stopped)));
    output.push_str(&case_line("null_task", None));

    r2o_detect_stop_all();
    output.push_str(&case_line("global_only", Some(&idle)));
    output.push_str(&case_line("both_flags", Some(&stopped)));
    output.push_str(&case_line("new_probe_after_global", None));

    // C `d2k_classify_run`: липкий флаг проверяется до базы, поэтому после
    // остановки службы ни один зонд не задаётся.
    let trigger = Trigger::tls13("example.com").unwrap();
    let result = run_with_backend(
        "192.0.2.1:443",
        &trigger,
        ClassifyOptions::default(),
        &mut PanicBackend,
    );
    assert!(result.stopped);
    assert_eq!(result.probes, 0);

    if let Ok(path) = std::env::var("R2O_BRIDGE_STOP_DIFF_OUTPUT") {
        std::fs::write(path, &output).expect("write Rust stop differential output");
    }
    assert_eq!(
        output,
        "case=no_flags global=0 task=0 stop=0\n\
         case=task_flag global=0 task=1 stop=1\n\
         case=null_task global=0 task=-1 stop=0\n\
         case=global_only global=1 task=0 stop=1\n\
         case=both_flags global=1 task=1 stop=1\n\
         case=new_probe_after_global global=1 task=-1 stop=1\n"
    );
}

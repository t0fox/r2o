pub mod response {
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use crate::classify::{ProbeError, ProbeOutcome, ProbeTarget, Trigger};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum ResponseVerdict {
        NotApplicable,
        Clear,
        Blocked,
        Flaky,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct ResponseResult {
        pub verdict: ResponseVerdict,
        pub reason: String,
        pub target: i32,
        pub control: i32,
        pub probes: usize,
    }

    #[derive(Clone, Copy, Debug)]
    pub struct ResponseOptions {
        pub repeats: usize,
        pub timeout: Duration,
        pub mark: Option<u32>,
    }

    pub fn probe_response(_: &str, _: u16, _: &str, _: ResponseOptions) -> ResponseResult {
        ResponseResult {
            verdict: ResponseVerdict::NotApplicable,
            reason: "isolated differential fixture".into(),
            target: 0,
            control: 0,
            probes: 0,
        }
    }

    pub fn probe_trigger(
        _: &ProbeTarget,
        _: &Trigger,
        _: &[usize],
        _: Duration,
        _: Duration,
        _: Option<u32>,
        _: bool,
        _: Option<bool>,
        _: Option<&AtomicBool>,
    ) -> Result<ProbeOutcome, ProbeError> {
        Err(ProbeError::Unsupported(
            "isolated classifier differential fixture".into(),
        ))
    }

    pub fn probe_neutral_ack(
        _: &ProbeTarget,
        _: Duration,
        _: Option<u32>,
        _: Option<&AtomicBool>,
    ) -> Result<bool, ProbeError> {
        Err(ProbeError::Unsupported(
            "isolated classifier differential fixture".into(),
        ))
    }

    pub fn probe_tcp_control_peer(
        _: SocketAddr,
        _: Duration,
        _: Option<u32>,
    ) -> Result<(), ProbeError> {
        Err(ProbeError::Unsupported(
            "isolated classifier differential fixture".into(),
        ))
    }
}

pub mod raw_probe {
    use crate::classify::{
        ClassifyOptions, ClassifyResult, PoisonHit, ProbeError, ProbeTarget, Trigger,
    };

    pub fn raw_supported() -> bool {
        false
    }
    pub fn rst_rule_failure_count() -> u64 {
        0
    }
    pub fn raw_dial_count() -> u64 {
        0
    }
    pub fn flush_pending_rst_releases() {}
    pub fn sweep_poisons(
        _: &ProbeTarget,
        _: &Trigger,
        _: &ClassifyOptions,
        _: &mut ClassifyResult,
        _: &mut dyn FnMut(&str, usize, usize, usize),
    ) -> Result<Option<PoisonHit>, ProbeError> {
        Ok(None)
    }
}

use r2k_core::quic::{R2kQuicDataVerdict, r2k_quic_data_judge};

#[test]
fn повторяет_порядок_решений_этапа_данных_донора() {
    let cases = [
        (
            (false, 200, 40_000, true, false, false, false, false),
            R2kQuicDataVerdict::NoHandshake,
        ),
        (
            (true, 451, 40_000, true, false, false, false, true),
            R2kQuicDataVerdict::Cut,
        ),
        (
            (true, 200, 1, true, false, true, false, false),
            R2kQuicDataVerdict::Pass,
        ),
        (
            (true, 200, 60_000, false, false, true, false, true),
            R2kQuicDataVerdict::Pass,
        ),
        (
            (true, 200, 60_000, false, true, true, false, true),
            R2kQuicDataVerdict::Cut,
        ),
        (
            (true, 0, 0, false, false, true, true, false),
            R2kQuicDataVerdict::NotRun,
        ),
        (
            (true, 200, 32_768, false, false, false, false, false),
            R2kQuicDataVerdict::Pass,
        ),
        (
            (true, 200, 32_767, false, false, false, false, false),
            R2kQuicDataVerdict::NotRun,
        ),
    ];

    for (
        (handshake, status, bytes, complete, stalled, need_complete, headers_too_long, budget_ok),
        expected,
    ) in cases
    {
        assert_eq!(
            r2k_quic_data_judge(
                handshake,
                status,
                bytes,
                complete,
                stalled,
                need_complete,
                headers_too_long,
                budget_ok,
            ),
            expected,
        );
    }
}

use r2o_telegram::limits::{
    D2O_CONFIGURED_MAX_CONNECTIONS, MEMORY_BUDGET_MAX, RUNTIME_RESERVE_PER_CONNECTION,
    WS_RX_INITIAL, auto_max_connections, connection_reserve_bytes, proxy_memory_budget,
    runtime_memory_budget, soft_nofile_limit,
};

/// Векторы D2O `test_limits.c`.
#[test]
fn connection_budget_respects_file_descriptors() {
    assert_eq!(
        auto_max_connections(128, 16 * 1024 * 1024, 128 * 1024, 0, 512),
        47
    );
    assert_eq!(
        auto_max_connections(32, 16 * 1024 * 1024, 128 * 1024, 0, 512),
        0
    );
}

#[test]
fn connection_budget_respects_memory_and_configured_cap() {
    assert_eq!(
        auto_max_connections(4096, 1024 * 1024, 256 * 1024, 0, 512),
        4
    );
    assert_eq!(auto_max_connections(usize::MAX, usize::MAX, 1, 0, 12), 12);
    assert_eq!(auto_max_connections(usize::MAX, usize::MAX, 1, 0, 0), 0);
}

#[test]
fn reserved_resources_and_invalid_inputs_fail_closed() {
    assert_eq!(
        auto_max_connections(48, 1024 * 1024, 128 * 1024, 16, 512),
        0
    );
    assert_eq!(auto_max_connections(256, 1024 * 1024, 0, 0, 512), 0);
    assert_eq!(
        auto_max_connections(256, 1024 * 1024, 128 * 1024, usize::MAX, 512),
        0
    );
}

#[test]
fn runtime_memory_budget_tracks_router_ram() {
    const MIB: usize = 1024 * 1024;
    assert_eq!(runtime_memory_budget(512 * MIB, 348 * MIB), 192 * MIB);
    assert_eq!(runtime_memory_budget(64 * MIB, 40 * MIB), 24 * MIB);
    assert_eq!(runtime_memory_budget(2048 * MIB, 1024 * MIB), 192 * MIB);
    assert_eq!(runtime_memory_budget(512 * MIB, 0), 0);
    assert_eq!(MEMORY_BUDGET_MAX, 192 * MIB);
}

#[test]
fn default_router_budget_caps_connections_at_d2o_64() {
    let bytes_per_connection = connection_reserve_bytes() + WS_RX_INITIAL;
    assert!(bytes_per_connection > RUNTIME_RESERVE_PER_CONNECTION);
    let budget = runtime_memory_budget(128 * 1024 * 1024, 96 * 1024 * 1024);
    assert_eq!(
        auto_max_connections(1024, budget, bytes_per_connection, 0, 64),
        D2O_CONFIGURED_MAX_CONNECTIONS
    );
    // Урезанный бюджет памяти обязан уменьшить предел ниже 64.
    let tiny = bytes_per_connection * 7;
    assert_eq!(
        auto_max_connections(1024, tiny, bytes_per_connection, 0, 64),
        7
    );
}

#[test]
fn soft_nofile_limit_reports_a_usable_budget() {
    let limit = soft_nofile_limit();
    assert!(limit > 0);
    assert!(
        auto_max_connections(limit, 32 * 1024 * 1024, 282 * 1024, 0, 64)
            <= D2O_CONFIGURED_MAX_CONNECTIONS
    );
}

#[test]
fn proxy_memory_budget_is_bounded_and_nonzero() {
    let budget = proxy_memory_budget();
    assert!(budget > 0);
    assert!(budget <= MEMORY_BUDGET_MAX);
}

//! Ограничения соединений по дескрипторам и памяти (контракт D2O `limits.c`).
//!
//! D2O считает предел как минимум из бюджета файловых дескрипторов, бюджета
//! памяти и жёсткого `configured_max_connections=64`. R2O сохраняет ту же
//! арифметику и те же константы, чтобы на 128-МиБ роутере не открывать
//! сотни соединений вместо 64.

/// Осторожное запасное значение, если мягкий лимит платформы нельзя прочитать.
const DEFAULT_NOFILE_LIMIT: usize = 1024;
/// Предел, используемый, если у процесса вообще нет ограничения дескрипторов.
const UNLIMITED_MAX_CONNECTIONS: usize = 512;
/// Дескрипторы на listener, стандартные потоки и запас безопасности.
const RUNTIME_RESERVED_FDS: usize = 33;
/// Дескрипторы на одно соединение: один входящий и один исходящий.
const FDS_PER_CONNECTION: usize = 2;
/// Верхний предел бюджета динамических буферов Telegram.
pub const MEMORY_BUDGET_MAX: usize = 192 * 1024 * 1024;
/// Жёсткий предел D2O `configured_max_connections`.
pub const D2O_CONFIGURED_MAX_CONNECTIONS: usize = 64;
/// Резерв C `TG_EPOLL_RUNTIME_RESERVE_PER_CONNECTION`.
pub const RUNTIME_RESERVE_PER_CONNECTION: usize = 256 * 1024;
/// Начальный RX-буфер C `TG_WS_PUMP_RX_INITIAL`.
pub const WS_RX_INITIAL: usize = 16 * 1024;
/// Размер C `proxy_connection` по данным layout dump.
///
/// 64-битные цели — 20536; ARM/MIPS o32 выравнивают `uint64_t` по 8 и дают
/// 20256; i386 выравнивает по 4 и даёт 20228.
pub const fn d2o_connection_struct_bytes() -> usize {
    if cfg!(target_pointer_width = "64") {
        20_536
    } else if cfg!(target_arch = "x86") {
        20_228
    } else {
        20_256
    }
}

/// Полный резерв D2O на одно соединение без начального WS RX.
pub fn connection_reserve_bytes() -> usize {
    d2o_connection_struct_bytes() + RUNTIME_RESERVE_PER_CONNECTION
}

/// Прочитать мягкий лимит открытых файлов процесса из `/proc/self/limits`.
pub fn soft_nofile_limit() -> usize {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/self/limits") {
            for line in content.lines() {
                if line.starts_with("Max open files")
                    && let Some(soft) = line.split_whitespace().nth(3)
                {
                    if soft == "unlimited" {
                        return usize::MAX;
                    }
                    if let Ok(n) = soft.parse::<usize>() {
                        return n;
                    }
                }
            }
        }
    }

    DEFAULT_NOFILE_LIMIT
}

/// Бюджет памяти D2O: 2/5 total, 3/5 available, не выше 192 МиБ.
pub fn runtime_memory_budget(total_bytes: usize, available_bytes: usize) -> usize {
    if total_bytes == 0 || available_bytes == 0 {
        return 0;
    }
    let total_cap = (total_bytes / 5).saturating_mul(2);
    let available_cap = (available_bytes / 5).saturating_mul(3);
    total_cap.min(available_cap).min(MEMORY_BUDGET_MAX)
}

/// Прочитать бюджет памяти через `sysinfo(2)`, как C `proxy_memory_budget`.
/// При ошибке — 32 МиБ, ровно как fallback D2O.
pub fn proxy_memory_budget() -> usize {
    #[cfg(target_os = "linux")]
    {
        let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
        if unsafe { libc::sysinfo(&mut info) } == 0 && info.mem_unit != 0 {
            let unit = u64::from(info.mem_unit);
            let total = (info.totalram as u64)
                .saturating_mul(unit)
                .min(usize::MAX as u64) as usize;
            let available = (info.freeram as u64)
                .saturating_add(info.bufferram as u64)
                .saturating_mul(unit)
                .min(usize::MAX as u64) as usize;
            let budget = runtime_memory_budget(total, available);
            if budget != 0 {
                return budget;
            }
        }
    }
    32 * 1024 * 1024
}

/// Вычислить предел соединений ровно как C `tg_limits_auto_max_connections`.
///
/// Возвращает 0 при некорректных входных данных — вызывающий обязан
/// отказаться от запуска, как C `tg_epoll_proxy_create`.
pub fn auto_max_connections(
    fd_limit: usize,
    memory_budget: usize,
    bytes_per_connection: usize,
    hedge_limit: usize,
    configured_max: usize,
) -> usize {
    if memory_budget == 0 || bytes_per_connection == 0 || configured_max == 0 {
        return 0;
    }

    let fd_cap = if fd_limit == usize::MAX {
        UNLIMITED_MAX_CONNECTIONS
    } else {
        let Some(reserved) = RUNTIME_RESERVED_FDS.checked_add(hedge_limit) else {
            return 0;
        };
        if fd_limit <= reserved {
            return 0;
        }
        (fd_limit - reserved) / FDS_PER_CONNECTION
    };
    let memory_cap = memory_budget / bytes_per_connection;
    let mut cap = fd_cap.min(memory_cap).min(configured_max);
    if cap > UNLIMITED_MAX_CONNECTIONS {
        cap = UNLIMITED_MAX_CONNECTIONS;
    }
    cap
}

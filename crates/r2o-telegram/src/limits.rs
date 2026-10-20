//! Ограничения соединений, рассчитанные по бюджету файловых дескрипторов процесса.
//!
//! Каждое активное соединение занимает два дескриптора: принятый сокет клиента
//! и исходящее соединение к Telegram. При превышении бюджета accept-loop
//! получает `EMFILE`, поэтому предел заранее рассчитывается по мягкому лимиту
//! `ulimit -n` процесса.

/// Осторожное запасное значение, если мягкий лимит платформы нельзя прочитать.
const DEFAULT_NOFILE_LIMIT: usize = 1024;
/// Предел, используемый, если у процесса вообще нет ограничения дескрипторов.
const UNLIMITED_MAX_CONNECTIONS: usize = 512;
/// Дескрипторы, зарезервированные для Tokio, стандартных потоков и запаса безопасности.
const RUNTIME_RESERVED_FDS: usize = 32;
/// Дескрипторы на одно соединение: один входящий и один исходящий.
const FDS_PER_CONNECTION: usize = 2;
/// Минимальный полезный предел даже при самом тесном бюджете.
const MIN_MAX_CONNECTIONS: usize = 4;

/// Прочитать мягкий лимит открытых файлов процесса из `/proc/self/limits` (Linux).
/// На других платформах и при ошибке разбора использовать значение 1 024.
pub fn soft_nofile_limit() -> usize {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/self/limits") {
            for line in content.lines() {
                // Поля строки: имя лимита, мягкое и жёсткое значения, затем единица измерения.
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

/// Вычислить лимит клиентских соединений с резервом на одновременные WSS hedge.
///
/// На каждую hedge-попытку резервируется дополнительный исходящий сокет.
pub fn auto_max_connections(fd_limit: usize, hedge_limit: usize) -> usize {
    if fd_limit == usize::MAX {
        // При неограниченном числе дескрипторов использовать большой, но разумный предел.
        return UNLIMITED_MAX_CONNECTIONS;
    }

    let reserved = 1usize
        .saturating_add(RUNTIME_RESERVED_FDS)
        .saturating_add(hedge_limit);

    (fd_limit.saturating_sub(reserved) / FDS_PER_CONNECTION).max(MIN_MAX_CONNECTIONS)
}

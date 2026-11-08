/* Размеры C-структур, от которых зависит бюджет соединений.
 * Собирается в объектный файл; значения лежат в .rodata. */
#include "epoll_proxy.c"

const unsigned long d2o_proxy_connection_size = sizeof(proxy_connection);
const unsigned long d2o_runtime_reserve = TG_EPOLL_RUNTIME_RESERVE_PER_CONNECTION;
const unsigned long d2o_ws_rx_initial = TG_WS_PUMP_RX_INITIAL;
const unsigned long d2o_fds_per_connection = TG_LIMITS_FDS_PER_CONNECTION;
const unsigned long d2o_reserved_fds = TG_LIMITS_RESERVED_FDS;
const unsigned long d2o_unlimited_max = TG_LIMITS_UNLIMITED_MAX;
const unsigned long d2o_memory_budget_max = TG_LIMITS_MEMORY_BUDGET_MAX;

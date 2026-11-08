/* Размеры C-структур для 32-битного target.
 * Только compile-time константы: объект/ассемблер не требует link. */
#include "epoll_proxy.c"

const unsigned long d2o_proxy_connection_size = sizeof(proxy_connection);
const unsigned long d2o_ws_pump_size = sizeof(tg_ws_pump);
const unsigned long d2o_runtime_reserve = TG_EPOLL_RUNTIME_RESERVE_PER_CONNECTION;
const unsigned long d2o_ws_rx_initial = TG_WS_PUMP_RX_INITIAL;

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "d2k_ctl.h"
#include "d2k_ctlsrv.h"
#include "d2k_plans.h"

int main(void) {
    /* Точная раскладка C `ack()` для SET_NAME_BOUND: key(38) + 4 +
       trial_id(16) + raw binding(28), без R2BC. */
    uint8_t body[D2K_KEY_WIRE_LEN + 4 + D2K_TRIAL_ID_LEN + D2K_CTL_BINDING_LEN];
    memset(body, 0, sizeof body);
    body[0] = 4;
    body[D2K_KEY_WIRE_LEN] = (uint8_t)(D2K_CMD_SET_NAME_BOUND >> 8);
    body[D2K_KEY_WIRE_LEN + 1] = (uint8_t)D2K_CMD_SET_NAME_BOUND;
    body[D2K_KEY_WIRE_LEN + 2] = 1;
    body[D2K_KEY_WIRE_LEN + 3] = D2K_ACK_OK;
    memset(body + D2K_KEY_WIRE_LEN + 4, 0x22, D2K_TRIAL_ID_LEN);

    d2k_binding_context binding;
    memset(&binding, 0, sizeof binding);
    binding.generation = 0x0102030405060708ull;
    binding.kind = D2K_BIND_NAME;
    binding.family = 4;
    binding.shape = D2K_PLAN_SHAPE_HTTP;
    binding.temporary = 0;
    memset(binding.epoch, 0x11, sizeof binding.epoch);
    d2k_ctl_binding_write(body + D2K_KEY_WIRE_LEN + 4 + D2K_TRIAL_ID_LEN, &binding);

    for (size_t i = 0; i < sizeof body; i++) {
        printf("%02x", body[i]);
    }
    printf("\n");
    return 0;
}

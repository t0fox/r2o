/* M6: C-оракул udpplan — голосовой план Discord. */
#include "d2k_quicprobe.h"

#include <stdio.h>

int main(void) {
    static const unsigned copies[] = {1, 6, 10};
    static const unsigned char decoy[20] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    };
    char buffer[4096];
    for (size_t index = 0; index < sizeof copies / sizeof copies[0]; index++) {
        printf("case voice-%u\n", copies[index]);
        int result = d2k_voice_arm_plan(decoy, sizeof decoy, copies[index],
                                        buffer, sizeof buffer);
        if (result != 0) {
            printf("rc=%d\n", result);
        } else {
            printf("%s", buffer);
        }
    }
    return 0;
}

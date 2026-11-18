#define _POSIX_C_SOURCE 200809L
#include "d2k_quic_arms.h"
#include "d2k_udpruntime.h"
#include <stdio.h>
#include <string.h>

static void show(const char *label, d2k_quic_arm_question q)
{
    char buf[8192];
    memset(buf, 0, sizeof buf);
    int rc = d2k_quic_question_plan(&q, buf, sizeof buf);
    printf("--%s rc=%d--\n", label, rc);
    if (rc != 0) { return; }
    static const char proto[] = "proto udp quic\n";
    char *body = strstr(buf, proto);
    if (body) { fputs(body + sizeof proto - 1, stdout); }
}

int main(void)
{
    d2k_quic_arm_question q;
    memset(&q, 0, sizeof q); q.udplen = 100; show("udplen", q);
    memset(&q, 0, sizeof q); q.split = 1; show("split", q);
    for (int shape = 1; shape <= 4; shape++) {
        char label[16];
        snprintf(label, sizeof label, "frag%d", shape);
        memset(&q, 0, sizeof q); q.frag = shape; show(label, q);
    }
    memset(&q, 0, sizeof q);
    q.ttl = 3; q.copies = 2;
    q.blob = d2k_quic_original_blob(0, &q.blob_len, NULL);
    show("ttl3", q);
    return 0;
}

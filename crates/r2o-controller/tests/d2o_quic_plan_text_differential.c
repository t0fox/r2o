/* C oracle quic_plan_text (core/udpplan.c:69-171). */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "udpplan.c"

static uint8_t blob[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

static void run(const char *name, const d2k_quic_arm *arm, const uint8_t *data,
                size_t length, int junk, unsigned udplen)
{
    char text[4096];
    int rc = quic_plan_text(arm, data, length, junk, udplen, text, sizeof text);
    printf("plan|%s|%d\n", name, rc);
    if (rc == 0) fputs(text, stdout);
}

int main(void)
{
    memset(blob, 0, sizeof blob);
    blob[0] = 0xaa; blob[1] = 0xbb; blob[2] = 0xcc; blob[3] = 0xdd;

    {
        d2k_quic_arm a;
        memset(&a, 0, sizeof a);
        a.kind = D2K_QA_SPLIT;
        a.original = 1;
        run("split", &a, NULL, 0, 0, 0);
    }
    {
        d2k_quic_arm a;
        memset(&a, 0, sizeof a);
        a.kind = D2K_QA_SPLIT;
        a.original = 1;
        a.copies = 2;
        a.len = 4;
        memcpy(a.bytes, blob, 4);
        run("split-blob", &a, blob, 4, 0, 0);
    }
    {
        d2k_quic_arm a;
        memset(&a, 0, sizeof a);
        a.kind = D2K_QA_SPLIT;
        a.original = 1;
        a.copies = 2;
        a.len = 4;
        memcpy(a.bytes, blob, 4);
        run("split-blob-udplen", &a, blob, 4, 0, 100);
    }
    {
        d2k_quic_arm a;
        memset(&a, 0, sizeof a);
        a.kind = D2K_QA_COPIES;
        a.original = 1;
        a.copies = 2;
        a.len = 4;
        memcpy(a.bytes, blob, 4);
        run("copies2", &a, blob, 4, 0, 0);
    }
    {
        d2k_quic_arm a;
        memset(&a, 0, sizeof a);
        a.kind = D2K_QA_COPIES;
        a.original = 1;
        a.copies = 3;
        a.len = 4;
        memcpy(a.bytes, blob, 4);
        run("copies3", &a, blob, 4, 0, 0);
    }
    {
        d2k_quic_arm a;
        memset(&a, 0, sizeof a);
        a.kind = D2K_QA_TTL;
        a.original = 1;
        a.copies = 2;
        a.ttl = 3;
        a.len = 4;
        memcpy(a.bytes, blob, 4);
        run("ttl3", &a, blob, 4, 0, 0);
    }
    {
        d2k_quic_arm a;
        memset(&a, 0, sizeof a);
        a.kind = D2K_QA_FRAG;
        a.original = 1;
        a.frag_kind = 2;
        a.frag_survives = D2K_PROP_YES;
        run("frag2", &a, NULL, 0, 0, 0);
    }
    {
        d2k_quic_arm a;
        memset(&a, 0, sizeof a);
        a.kind = D2K_QA_FRAG;
        a.original = 1;
        a.frag_kind = 2;
        a.frag_survives = D2K_PROP_YES;
        run("frag2-udplen", &a, NULL, 0, 0, 100);
    }
    run("junk", NULL, NULL, 0, 1, 0);
    run("udplen", NULL, NULL, 0, 0, 100);
    {
        d2k_quic_arm a;
        memset(&a, 0, sizeof a);
        a.kind = D2K_QA_COPIES;
        a.copies = 1;
        a.len = 4;
        memcpy(a.bytes, blob, 4);
        run("non-original", &a, blob, 4, 0, 0);
    }
    {
        d2k_quic_arm a;
        memset(&a, 0, sizeof a);
        a.kind = D2K_QA_FRAG;
        a.original = 1;
        a.frag_kind = 2;
        a.frag_survives = D2K_PROP_NO;
        run("frag-no-survive", &a, NULL, 0, 0, 0);
    }
    {
        d2k_quic_arm a;
        memset(&a, 0, sizeof a);
        a.kind = D2K_QA_SPLIT;
        a.original = 0;
        run("split-non-original", &a, NULL, 0, 0, 0);
    }
    return 0;
}

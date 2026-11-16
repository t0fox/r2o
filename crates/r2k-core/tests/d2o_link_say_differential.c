/* link.c сам содержит static say; включаем его целиком, чтобы оракул был
 * именно production-функцией, а не копией форматирования. */
#include "link.c"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void show_link_error(const char *label, const char *path)
{
    char err[256];
    memset(err, 0, sizeof err);
    int rc = d2k_link_open(path, err, sizeof err);
    printf("%s rc=%d err=%s\n", label, rc, err);
}

int main(void)
{
    char buffer[64];
    memset(buffer, 'Z', sizeof buffer);
    say(buffer, 0, "abc");
    printf("say_cap0=%d\n", buffer[0] == 'Z' ? 1 : 0);

    memset(buffer, 'Z', sizeof buffer);
    say(buffer, 1, "abc");
    printf("say_cap1=%zu\n", strlen(buffer));

    memset(buffer, 'Z', sizeof buffer);
    say(buffer, 8, "abcdefghij");
    printf("say_cap8=%s\n", buffer);

    memset(buffer, 'Z', sizeof buffer);
    say(buffer, 64, "путь");
    printf("say_ru=%s\n", buffer);

    show_link_error("empty", "");
    char long_path[256];
    memset(long_path, 'x', sizeof long_path);
    long_path[108] = '\0';
    show_link_error("long", long_path);

    const char *missing = "/tmp/r2o-link-say-differential.sock";
    (void)unlink(missing);
    show_link_error("missing", missing);
    return 0;
}

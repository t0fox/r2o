/* C-оракул: `is_telegram_tunnel_domain` и проверка SCHED_DECOY из core/sched.c.
 *
 * sched.c включается целиком: нужна статическая функция. Неиспользуемые
 * секции выбрасываются --gc-sections. */
#include "sched.c"

#include <stdio.h>

int main(void) {
    static const char *const names[] = {
        "telegram.org",
        "TELEGRAM.ORG",
        "web.telegram.org",
        "a.b.Telegram.Org",
        ".telegram.org",
        "",
        "telegram.or",
        "nottelegram.org",
        "xtelegram.org",
        "telegram.org.evil",
        "telegram.org.",
        "telegramxorg",
        "disk.rzd.ru",
        "DISK.RZD.RU",
        "disk.rzd.ru.",
        "ddos-guard.net",
    };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        const char *name = names[i];
        printf("%s tunnel=%d decoy=%d\n", name,
               is_telegram_tunnel_domain(name) ? 1 : 0,
               strcasecmp(name, SCHED_DECOY) == 0 ? 1 : 0);
    }
    return 0;
}

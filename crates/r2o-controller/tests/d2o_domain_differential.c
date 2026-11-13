/* C/Rust differential для d2k_domain_normalize/base/member. */
#include <stdio.h>
#include "include/d2k_domain.h"

static const char *names[] = {
    "WWW.Example.COM.",
    "localhost",
    "LOCALHOST.",
    "127.0.0.1",
    "123",
    "a..example.com",
    "-a.example.com",
    "a-.example.com",
    "a_1.example.com",
    "a.example.com",
    "a.b.example.co.uk",
    "co.uk",
    "x.foo.blogspot.com",
    "www.city.kawasaki.jp",
    "city.kawasaki.jp",
    "a.b.googlevideo.com",
    "a.b.replit.dev",
    "replit.dev",
    "x.teams.replit.dev",
    "a.us-east-1.cs.amazonlightsail.com",
    "us-east-1.cs.amazonlightsail.com",
    "x.ap-southeast-5.cs.amazonlightsail.com",
    "x.example.not-a-real-tld",
    "a.123",
    "example.com..",
    "a-b.example.com",
    "-",
    "a.-b.com",
    "a.b-.com",
    "a.b.c.d.e.f.g.h",
    "a.elasticbeanstalk.com",
    "x.ap-southeast-4.elasticbeanstalk.com",
    "x.retool.app",
    "x.auth.ap-east-2.amazoncognito.com",
    NULL};

static const char *pairs[][2] = {
    {"www.example.co.uk", "example.co.uk"},
    {"example.co.uk", "example.co.uk"},
    {"badexample.co.uk", "example.co.uk"},
    {"example.co.uk", "co.uk"},
    {"bad..example.co.uk", "example.co.uk"},
    {"localhost", "localhost"},
    {"a.b.replit.dev", "replit.dev"},
    {"a.b.replit.dev", "b.replit.dev"},
    {"x.teams.replit.dev", "teams.replit.dev"},
    {"a.us-east-1.cs.amazonlightsail.com", "us-east-1.cs.amazonlightsail.com"},
    {NULL, NULL}};

int main(void) {
    char out[256];
    for (size_t i = 0; names[i]; i++) {
        printf("case norm %s\n", names[i]);
        if (d2k_domain_normalize(names[i], out) == 0) {
            printf("result ok %s\n", out);
        } else {
            printf("result err\n");
        }
        printf("case base %s\n", names[i]);
        if (d2k_domain_base(names[i], out) == 0) {
            printf("result ok %s\n", out);
        } else {
            printf("result err\n");
        }
    }
    for (size_t i = 0; pairs[i][0]; i++) {
        printf("case member %s %s\n", pairs[i][0], pairs[i][1]);
        printf("result %d\n", d2k_domain_member(pairs[i][0], pairs[i][1]));
    }
    return 0;
}

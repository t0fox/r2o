"""Снимок DC-карты для TG17: primaries, tcpo/secret, CDN, IPv6, 17 секретов."""
import json
import sys

NOW = 1_800_000_000


def endpoint(dc, address, port=443, tcpo=False, cdn=False, ipv6=False,
             this_port_only=False, secret=None, media=False):
    return {
        "id": dc,
        "address": address,
        "port": port,
        "ipv6": ipv6,
        "media_only": media,
        "tcpo_only": tcpo,
        "cdn": cdn,
        "is_static": True,
        "this_port_only": this_port_only,
        "secret": secret,
        "last_seen": NOW,
    }


endpoints = [
    endpoint(1, "149.154.175.50"),
    endpoint(2, "149.154.167.51"),
    endpoint(3, "149.154.175.100"),
    endpoint(4, "149.154.167.91"),
    endpoint(5, "149.154.171.5"),
    endpoint(2, "149.154.167.151", port=5222, tcpo=True, secret="aabbccdd"),
    endpoint(2, "149.154.167.155", cdn=True),
    endpoint(4, "2001:67c:4e8:f004::a", ipv6=True),
    endpoint(2, "149.154.167.152", port=5222, secret="deadbeef"),
    endpoint(5, "2001:67c:4e8:f005::a", port=5222, ipv6=True, tcpo=True,
             secret="0102030405"),
    endpoint(2, "149.154.167.153", port=5222, tcpo=True, secret=None),
    endpoint(2, "149.154.167.156", port=5222, tcpo=True,
             this_port_only=True, secret="11223344"),
]
for index in range(17):
    endpoints.append(
        endpoint(2, "149.154.167.160", port=5222, tcpo=True,
                 secret=f"{index + 1:04x}")
    )

snapshot = {
    "schema_version": 1,
    "fetched_at": NOW,
    "config_date": NOW - 100,
    "config_expires": NOW + 86_400,
    "this_dc": 2,
    "endpoints": endpoints,
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(snapshot, handle, separators=(",", ":"))

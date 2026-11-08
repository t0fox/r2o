import json
import sys
import time

now = int(time.time())
document = {
    "schema_version": 1,
    "fetched_at": now,
    "config_date": now - 100,
    "config_expires": now + 86400,
    "this_dc": 2,
    "endpoints": [
        {
            "id": dc,
            "address": address,
            "port": 443,
            "ipv6": False,
            "media_only": False,
            "tcpo_only": False,
            "cdn": False,
            "is_static": True,
            "this_port_only": False,
            "secret": "aabbccdd" if dc == 1 else None,
            "last_seen": now,
        }
        for dc, address in [
            (1, "149.154.175.50"),
            (2, "149.154.167.51"),
            (3, "149.154.175.100"),
            (4, "149.154.167.91"),
            (5, "149.154.171.5"),
        ]
    ],
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(document, handle, separators=(",", ":"))
print(now)

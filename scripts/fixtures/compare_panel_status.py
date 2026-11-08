import json
import sys

c = json.load(open(sys.argv[1], encoding="utf-8"))
r = json.load(open(sys.argv[2], encoding="utf-8"))
assert set(c) == {"snapshot", "knowledge"}, c.keys()
assert set(r) == {"snapshot", "knowledge"}, r.keys()
cs = c["snapshot"]
rs = r["snapshot"]
assert "telegram_diagnostics" in rs
assert "telegram_diagnostics" not in cs
rs_common = {key: value for key, value in rs.items() if key != "telegram_diagnostics"}
assert set(cs) == set(rs_common), (set(cs) - set(rs_common), set(rs_common) - set(cs))
for key in [
    "version",
    "commit",
    "built",
    "mode",
    "panel_listen",
    "config_path",
    "state_dir",
    "queue_num",
    "controls_enabled",
    "config_exists",
    "dirty",
    "started_at",
    "uptime_seconds",
]:
    assert cs[key] == rs_common[key], (key, cs[key], rs_common[key])
assert cs["unknown_keys"] == ["Z-KEY", "A-KEY"], cs["unknown_keys"]
assert rs_common["unknown_keys"] == ["Z-KEY", "A-KEY"], rs_common["unknown_keys"]
for field in ("stages", "absent"):
    c_values = [(s["key"], s["title"], s["built"], s["detail"]) for s in cs[field]]
    r_values = [(s["key"], s["title"], s["built"], s["detail"]) for s in rs_common[field]]
    assert c_values == r_values, (field, c_values, r_values)
assert cs["telegram_stats"] == rs_common["telegram_stats"]
print("panel status structure ok")

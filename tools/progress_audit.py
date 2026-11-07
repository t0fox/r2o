#!/usr/bin/env python3
# Генерация дашборда прогресса из уточнённой матрицы аудита 2026-11-07.
# Основной счёт — строгий: только строки «доказано» на принятой ревизии.
# Использование: python3 tools/progress_audit.py [--check]
import html
import json
import math
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "docs/functional-parity-matrix.md"
PROGRESS = ROOT / "docs/progress"
BASE_CSS = PROGRESS / "base.css"

GROUP_ORDER = [
    "Datapath",
    "Classifier / TLS",
    "Discovery",
    "QUIC / HTTP3",
    "Discord RTC",
    "Discord Gateway",
    "Telegram",
    "WebPanel",
    "Router / Service",
    "Core / CLI",
]

GROUP_BY_PREFIX = {
    "TG": "Telegram",
    "CL": "Classifier / TLS",
    "D": "Datapath",
    "S": "Discovery",
    "Q": "QUIC / HTTP3",
    "R": "Discord RTC",
    "G": "Discord Gateway",
    "A": "WebPanel",
    "B": "Router / Service",
    "M": "Core / CLI",
}

COMPARE_CSS = """
.compare{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:18px 0}
.compare .stat b{font-size:28px}
.compare .strict b{color:#36c989}
.compare .carry b{color:#e6b45d}
.compare .legacy b{color:#819bf8}
.note{color:#9eb0c4;font-size:13px;line-height:1.5}
@media(max-width:720px){.compare{grid-template-columns:1fr}}
"""


def group_for(key: str, name: str) -> str:
    for prefix in ("TG", "CL"):
        if key.startswith(prefix):
            return GROUP_BY_PREFIX[prefix]
    if key.startswith("R") and ("Gateway" in name or "WebSocket" in name):
        return "Discord Gateway"
    return GROUP_BY_PREFIX.get(key[:1], "Core / CLI")


def parse_items():
    text = MATRIX.read_text(encoding="utf-8")
    start = text.index("## Нормализованная матрица покрытия")
    items = []
    for line in text[start:].splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.split("|")]
        if len(cells) < 8:
            continue
        key = cells[1]
        weight_match = re.search(r"\((\d+)\)\s*$", cells[2])
        if not re.fullmatch(r"[A-Z]{1,2}\d+[a-z]?", key) or not weight_match:
            continue
        name = re.sub(r"\s*\(\d+\)\s*$", "", cells[2]).strip()
        weight = int(weight_match.group(1))
        raw_status = cells[3].lower()
        coverage = cells[5]
        gap = cells[6]
        strict = int(cells[4]) if cells[4].isdigit() else 0
        if "carry" in raw_status:
            status, status_label, points, carry = (
                "carry",
                "carry (304) — historical",
                0,
                weight,
            )
        elif "verified" in raw_status or "доказано" in raw_status:
            status, status_label, points, carry = "verified", "доказано", strict, weight
        elif "missing" in raw_status:
            status, status_label, points, carry = "missing", "пробел", 0, 0
        elif "extension" in raw_status:
            status, status_label, points, carry = "extension", "R2O-only", 0, 0
        elif "out-of-scope" in raw_status:
            status, status_label, points, carry = "out-of-scope", "вне scope", 0, 0
        elif "partial" in raw_status or "частично" in raw_status:
            status, status_label, points, carry = "partial", "частично", strict, weight if strict else 0
        else:
            status, status_label, points, carry = (
                "missing",
                "0 — нет принятого доказательства",
                0,
                0,
            )
        items.append(
            {
                "id": len(items) + 1,
                "key": key,
                "name": name,
                "weight": weight,
                "points": points,
                "carry_points": carry,
                "status": status,
                "statusLabel": status_label,
                "group": group_for(key, name),
                "coverage": coverage,
                "gap": gap,
                "mapping": coverage,
                "evidence": coverage + ((" · пробел: " + gap) if gap else ""),
            }
        )
    if not items:
        raise SystemExit("No contracts found in the normalized matrix")
    return items


def build_data(items):
    groups = []
    for name in GROUP_ORDER:
        members = [item for item in items if item["group"] == name]
        if not members:
            continue
        groups.append(
            {
                "name": name,
                "weight": sum(item["weight"] for item in members),
                "points": sum(item["points"] for item in members),
                "items": members,
            }
        )
    weight = sum(item["weight"] for item in items)
    points = sum(item["points"] for item in items)
    carry_points = sum(item["carry_points"] for item in items)
    counts = {
        "verified": sum(1 for item in items if item["status"] == "verified"),
        "carry": sum(1 for item in items if item["status"] == "carry"),
        "partial": sum(1 for item in items if item["status"] == "partial"),
        "missing": sum(1 for item in items if item["status"] == "missing"),
        "implemented": 0,
        "unknown": 0,
    }
    return {
        "source": "docs/functional-parity-matrix.md",
        "date": "2026-11-08",
        "mode": "strict-current-revision",
        "weight": weight,
        "points": points,
        "percent": round(100 * points / weight, 2),
        "total": len(items),
        "counts": counts,
        "groups": groups,
        "items": items,
        "comparison": {
            "strict": {
                "points": points,
                "weight": weight,
                "percent": round(100 * points / weight, 2),
            },
            "carry_forward": {
                "points": carry_points,
                "weight": weight,
                "percent": round(100 * carry_points / weight, 2),
                "note": "только строки, явно помеченные carry (304); historical evidence",
            },
            "legacy": {
                "points": 80,
                "weight": 89,
                "percent": 89.89,
                "total": 57,
                "note": "legacy-агрегат, не оценка текущей ревизии",
            },
        },
    }


def tile_html(item):
    title = f'{item["key"]} {item["name"]} — {item["statusLabel"]} ({item["points"]}/{item["weight"]})'
    return (
        f'<button class="tile {item["status"]}" data-id="{item["id"]}" '
        f'title="{html.escape(title, quote=True)}"></button>'
    )


def grid_html(groups):
    sections = []
    for group in groups:
        tiles = "".join(tile_html(item) for item in group["items"])
        sections.append(
            f'<section class="group"><header><strong>{html.escape(group["name"])}</strong>'
            f'<small>{group["points"]}/{group["weight"]} баллов</small></header>'
            f'<div class="tiles">{tiles}</div>'
            f'<small>{len(group["items"])} контрактов</small></section>'
        )
    return "".join(sections)


def search_text(item):
    return " ".join(
        [item["key"], item["name"], item["group"], item["coverage"], item["gap"]]
    ).lower()


def row_html(item):
    return (
        f'<div class="row" data-id="{item["id"]}" data-status="{item["status"]}" '
        f'data-search="{html.escape(search_text(item), quote=True)}">'
        f'<span class="dot {item["status"]}"></span>'
        f'<div class="row-content"><strong>{html.escape(item["key"])} · {html.escape(item["name"])}</strong>'
        f'<small>{html.escape(item["group"])} · {html.escape(item["statusLabel"])}</small></div>'
        f'<span class="end">{item["points"]}/{item["weight"]}</span></div>'
    )


def render_index(data, css, grid, rows):
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    comparison = data["comparison"]

    def card(label, item, cls):
        return (
            f'<div class="stat {cls}"><b>{item["percent"]:.2f}%</b>'
            f'<small>{label}<br>{item["points"]}/{item["weight"]}</small></div>'
        )

    compare_cards = (
        card("строгий текущий", comparison["strict"], "strict")
        + card("carry-forward 304", comparison["carry_forward"], "carry")
        + card("legacy-агрегат", comparison["legacy"], "legacy")
    )
    counts = data["counts"]
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>R2O · прогресс паритета</title>
<style>{css}{COMPARE_CSS}</style></head><body><main>
<div class="top"><span class="logo">r2o <span style="color:#40d592">/ progress</span></span>
<div class="nav"><a href="https://github.com/t0fox/r2o">GitHub</a><a href="history.html">история</a>
<a href="https://github.com/t0fox/r2o/blob/main/docs/functional-parity-matrix.md">матрица</a>
<a href="https://github.com/t0fox/r2o/blob/main/docs/audit/README.md">аудит</a></div></div>
<h1>Функциональный паритет</h1>
<p>Строгий срез текущей ревизии: балл получают только контракты с прямым C/Rust differential на
<code>a63d964</code>/<code>a378e23</code>/<code>8e2c981</code>. Helper, mock, source mapping и
дифференциалы на <code>304ba893</code> показаны отдельно и не входят в основной счёт.</p>
<div class="lead"><div><div class="score">{data["percent"]:.2f}%</div>
<small>{data["points"]} из {data["weight"]} доказанных баллов</small></div>
<small>срез: {data["date"]} · {data["total"]} контрактов</small></div>
<div class="bar"><b style="width:{data["percent"]}%"></b></div>
<div class="stats">
<div class="stat"><b>{counts["verified"]}</b><small>доказано</small></div>
<div class="stat"><b>{counts["carry"]}</b><small>carry (304)</small></div>
<div class="stat"><b>{counts["partial"]}</b><small>частично</small></div>
<div class="stat"><b>{counts["missing"]}</b><small>пробел</small></div>
</div>
<div class="panel"><h2>Три оценки</h2><div class="compare">{compare_cards}</div>
<p class="note">Строгий счёт — единственный, который подтверждает текущую ревизию. Carry-forward
принимает <code>304ba893</code> как допустимую; здесь учитываются только строки, явно помеченные
<code>carry (304)</code>. Legacy-агрегат имеет другой знаменатель (57 строк / 89 баллов)
и не сопоставим напрямую с 173 контрактами / 261 баллом.</p></div>
<div class="legend"><span style="--c:#36c989">доказано</span><span style="--c:#819bf8">carry (304)</span>
<span style="--c:#e6b45d">частично</span><span style="--c:#e06c75">пробел</span></div>
<div class="grid">{grid}</div>
<div id="detail" class="panel" aria-live="polite"><h2>Выберите контракт</h2>
<div>Нажмите на плитку, чтобы увидеть покрытие, пробел и статус.</div></div>
<div class="controls"><input id="search" placeholder="поиск контракта:" aria-label="поиск">
<select id="filter" aria-label="фильтр"><option value="all">все статусы</option>
<option value="verified">доказано</option><option value="carry">carry (304)</option>
<option value="partial">частично</option><option value="missing">пробел</option></select></div>
<div id="rows">{rows}</div>
<p class="footer">Источник — <a href="https://github.com/t0fox/r2o/blob/main/docs/functional-parity-matrix.md">матрица</a>,
аудит — <a href="https://github.com/t0fox/r2o/blob/main/docs/audit/README.md">docs/audit/README.md</a>.
Балл не начисляется за наличие похожей функции, компиляцию, mock или source mapping.
Физический роутер и полный C/Rust differential здесь не запускались.</p>
</main><script>const d={payload};const byId=new Map(d.items.map(x=>[x.id,x]));
function show(c){{const box=document.getElementById("detail");box.replaceChildren();
const h=document.createElement("h2");h.textContent=c.key+" · "+c.name;
const p=document.createElement("p");p.textContent=c.statusLabel+" · "+c.points+"/"+c.weight+" баллов";
const cov=document.createElement("div");cov.textContent="Покрытие: "+(c.coverage||"—");
const gap=document.createElement("div");gap.textContent="Пробел: "+(c.gap||"—");
box.append(h,p,cov,gap);box.scrollIntoView({{behavior:"smooth",block:"nearest"}})}}
document.querySelectorAll(".tile").forEach(el=>el.onclick=()=>show(byId.get(+el.dataset.id)));
function update(){{const q=document.getElementById("search").value.toLowerCase();
const f=document.getElementById("filter").value;document.querySelectorAll("#rows .row").forEach(row=>{{
const okStatus=f==="all"||row.dataset.status===f;
const okQuery=row.dataset.search.includes(q);row.style.display=okStatus&&okQuery?"":"none"}})}}
document.getElementById("search").oninput=update;document.getElementById("filter").onchange=update;update();
</script></body></html>"""


def render_svg(data):
    groups = data["groups"]
    width = 1100
    height = 175 + math.ceil(len(groups) / 2) * 112 + 55
    colors = {
        "verified": "#36c989",
        "carry": "#819bf8",
        "partial": "#e6b45d",
        "missing": "#e06c75",
        "implemented": "#819bf8",
        "unknown": "#65758c",
    }
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" role="img" aria-label="R2O strict parity {data["percent"]:.2f}%">',
        f'<rect width="{width}" height="{height}" rx="20" fill="#0c121e"/>',
        '<text x="36" y="48" fill="#edf7ff" font-family="Arial,sans-serif" font-size="29" font-weight="700">R2O / D2O · Strict parity</text>',
        f'<text x="37" y="98" fill="#36c989" font-family="Arial,sans-serif" font-size="42" font-weight="700">{data["percent"]:.2f}%</text>',
        f'<text x="230" y="93" fill="#9bafc3" font-family="Arial,sans-serif" font-size="18">{data["points"]} / {data["weight"]} verified points</text>',
        '<rect x="37" y="113" width="1024" height="11" rx="5" fill="#273245"/>',
        f'<rect x="37" y="113" width="{1024 * data["points"] / data["weight"]:.1f}" height="11" rx="5" fill="#36c989"/>',
        f'<text x="38" y="147" fill="#90a5b8" font-family="Arial,sans-serif" font-size="13">{data["total"]} contracts · {data["counts"]["verified"]} verified · {data["counts"]["missing"]} missing · 2026-11-08</text>',
        f'<text x="38" y="166" fill="#65758c" font-family="Arial,sans-serif" font-size="12">legacy 80/89 = 89.89% · carry 304 {data["comparison"]["carry_forward"]["points"]}/{data["comparison"]["carry_forward"]["weight"]} = {data["comparison"]["carry_forward"]["percent"]:.2f}% · strict {data["points"]}/{data["weight"]} = {data["percent"]:.2f}%</text>',
    ]
    for index, group in enumerate(groups):
        x = 37 + (index % 2) * 520
        y = 190 + (index // 2) * 112
        parts.append(
            f'<rect x="{x}" y="{y}" width="510" height="100" rx="12" fill="#162233" stroke="#2b394c"/>'
        )
        parts.append(
            f'<text x="{x + 14}" y="{y + 23}" fill="#e8f1fa" font-family="Arial,sans-serif" font-size="15" font-weight="700">{html.escape(group["name"])}</text>'
        )
        parts.append(
            f'<text x="{x + 496}" y="{y + 23}" text-anchor="end" fill="#9bb0c5" font-family="Arial,sans-serif" font-size="12">{group["points"]}/{group["weight"]}</text>'
        )
        for tile_index, item in enumerate(group["items"]):
            tx = x + 14 + (tile_index % 12) * 38
            ty = y + 33 + (tile_index // 12) * 27
            title = html.escape(
                f'{item["key"]} {item["name"]}: {item["statusLabel"]} ({item["points"]}/{item["weight"]})',
                quote=True,
            )
            parts.append(
                f'<rect x="{tx}" y="{ty}" width="30" height="22" rx="5" fill="{colors[item["status"]]}"><title>{title}</title></rect>'
            )
    parts.append("</svg>")
    return "\n".join(parts)


def render_badge(label, value, width, split):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} 28" width="{width}" height="28" role="img" aria-label="{html.escape(label + " " + value, quote=True)}">'
        f'<rect width="{width}" height="28" rx="5" fill="#243146"/>'
        f'<path d="M{split} 0 H{width - 5} Q{width} 0 {width} 5 V23 Q{width} 28 {width - 5} 28 H{split}Z" fill="#217851"/>'
        f'<g fill="#ffffff" font-size="13" font-family="Arial,sans-serif">'
        f'<text x="{split / 2}" y="18.5" text-anchor="middle">{html.escape(label)}</text>'
        f'<text x="{split + (width - split) / 2}" y="18.5" text-anchor="middle">{html.escape(value)}</text></g></svg>'
    )


def render_history():
    entries = [
        {
            "sha": "legacy-80-89",
            "date": "2026-11-06",
            "points": 80,
            "weight": 89,
            "percent": 89.89,
            "label": "legacy-агрегат",
        },
        {
            "sha": "carry-304-normalized",
            "date": "2026-11-08",
            "points": 151,
            "weight": 261,
            "percent": 57.85,
            "label": "carry (только явно помеченные 304)",
        },
        {
            "sha": "strict-normalized",
            "date": "2026-11-08",
            "points": 88,
            "weight": 261,
            "percent": 33.72,
            "label": "строгий текущий (нормализованный)",
        },
    ]
    history_json = json.dumps(entries, ensure_ascii=False, indent=2)
    rows = "".join(
        f'<tr><td>{html.escape(e["date"])}</td><td>{e["points"]}/{e["weight"]}</td>'
        f'<td>{e["percent"]:.2f}%</td><td>{html.escape(e["label"])}</td></tr>'
        for e in entries
    )
    history_html = f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>R2O · история</title>
<style>body{{background:#0c121e;color:#e8f1fa;font:15px Inter,system-ui,sans-serif;max-width:1110px;padding:25px;margin:auto}}a{{color:#59dfa4}}p{{color:#a7bad0;line-height:1.6}}table{{border-collapse:collapse;width:100%}}td,th{{padding:12px;text-align:left;border-bottom:1px solid #2c394c}}</style>
</head><body><a href="index.html">← назад</a><h1>История оценок R2O</h1>
<p>Три оценки используют разные знаменатели и правила доказательства. Строгий текущий счёт не сопоставим напрямую с legacy-агрегатом.</p>
<table><thead><tr><th>Дата</th><th>Баллы</th><th>Процент</th><th>Режим</th></tr></thead><tbody>{rows}</tbody></table>
</body></html>"""
    return history_json, history_html


def outputs():
    items = parse_items()
    data = build_data(items)
    css = BASE_CSS.read_text(encoding="utf-8").strip()
    grid = grid_html(data["groups"])
    rows = "".join(row_html(item) for item in data["items"])
    history_json, history_html = render_history()
    return {
        "progress.json": json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        "index.html": render_index(data, css, grid, rows),
        "progress.svg": render_svg(data),
        "badge-parity.svg": render_badge(
            "parity", f'{data["percent"]:.2f}%  {data["points"]}/{data["weight"]}', 260, 78
        ),
        "badge-contracts.svg": render_badge(
            "contracts", f'{data["counts"]["verified"]}/{data["total"]} verified', 230, 85
        ),
        "history.json": history_json + "\n",
        "history.html": history_html,
    }


def main():
    check = "--check" in sys.argv
    generated = outputs()
    if check:
        stale = []
        for name, content in generated.items():
            path = PROGRESS / name
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                stale.append(name)
        if stale:
            print("Stale or missing generated progress files: " + ", ".join(stale), file=sys.stderr)
            raise SystemExit(1)
        print("Progress dashboard is current.")
        return
    PROGRESS.mkdir(parents=True, exist_ok=True)
    for name, content in generated.items():
        (PROGRESS / name).write_text(content, encoding="utf-8")
    data = json.loads(generated["progress.json"])
    print(
        f'contracts={data["total"]} weight={data["weight"]} '
        f'points={data["points"]} percent={data["percent"]}'
    )


if __name__ == "__main__":
    main()

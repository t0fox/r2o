# R2O parity dashboard

Inspired by [AnyPS5](https://github.com/boykopovar/AnyPS5), but this visualization measures **verified functional parity**, not number of implemented functions.

The only source of truth is [the functional parity matrix](../functional-parity-matrix.md). Green cells have a C/Rust equivalence claim backed by the matrix's evidence; partial and implementation-only rows earn zero weighted points.

**Audit note (2026-11-07).** The dashboard still reads the legacy 57-row aggregate (`80/89 = 89,89 %`). The audit found that this aggregate is not a current-revision proof: 49 of 80 points rest on differentials pinned to `304ba893`, and several broad rows combine independent contracts. The refined matrix in the same document has 96 contracts / 132 points: `37/132 = 28,03 %` in strict current-revision mode and `89/132 = 67,42 %` if `304ba893` is accepted. Do not present the dashboard percentage as current parity until the 304-pinned differentials are re-pinned and re-run. See `docs/audit/README.md`.

Run `node tools/progress.mjs` to regenerate the tracked SVG, badges, JSON and HTML. Run `node tools/progress.mjs --check` to validate freshness (PR gate). The Pages workflow calls `node tools/progress.mjs --pages` to additionally generate historical charts from first-parent git history. GitHub Pages must be configured with **GitHub Actions** as source.

Before the pull request is merged, preview the [SVG map](progress.svg), [HTML source](index.html), and [JSON report](progress.json) directly in the branch. The public website URL will not resolve until the Pages workflow has successfully deployed the site. The history HTML is generated at deployment time and is not committed to this PR.

The dashboard deliberately ignores old percentage claims in prose. Historical snapshots can have different denominators because the set of requirements changes over time. A green tile is not proof of physical-router acceptance.

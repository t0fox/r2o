# R2O parity dashboard

Inspired by [AnyPS5](https://github.com/boykopovar/AnyPS5), but this visualization measures **verified functional parity**, not number of implemented functions.

The only source of truth is [the functional parity matrix](../functional-parity-matrix.md). Green cells have a C/Rust equivalence claim backed by the matrix's evidence; partial and implementation-only rows earn zero weighted points.

Run `node tools/progress.mjs` to regenerate the tracked SVG, badges, JSON and HTML. Run `node tools/progress.mjs --check` to validate freshness (PR gate). The Pages workflow calls `node tools/progress.mjs --pages` to additionally generate historical charts from first-parent git history. GitHub Pages must be configured with **GitHub Actions** as source.

The dashboard deliberately ignores old percentage claims in prose. Historical snapshots can have different denominators because the set of requirements changes over time. A green tile is not proof of physical-router acceptance.

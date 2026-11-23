#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
ABI=mipsel exec sh "$ROOT/scripts/r2o-build-static-musl.sh"

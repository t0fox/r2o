#!/bin/sh
set -eu

usage() {
    echo "usage: ci-apt-cache.sh prepare CACHE_DIR PARTIAL_DIR | finalize CACHE_DIR" >&2
    exit 2
}

[ "$#" -ge 2 ] || usage
mode=$1
cache_dir=$2
runner_owner=$(id -u):$(id -g)
runner_gid=$(id -g)

case "$mode" in
    prepare)
        [ "$#" -eq 3 ] || usage
        partial_dir=$3
        mkdir -p "$cache_dir" "$partial_dir"
        sudo chown -R "$runner_owner" "$cache_dir"
        sudo chmod 0755 "$cache_dir"
        # runner.temp may be private to the runner, so apt's sandbox uses /tmp.
        sudo chown "_apt:$runner_gid" "$partial_dir"
        sudo chmod 0775 "$partial_dir"
        ;;
    finalize)
        [ "$#" -eq 2 ] || usage
        sudo chown -R "$runner_owner" "$cache_dir"
        ;;
    *) usage ;;
esac

#!/bin/sh
set -eu

usage() {
    echo "usage: ci-apt-cache.sh prepare|finalize CACHE_DIR" >&2
    exit 2
}

[ "$#" -eq 2 ] || usage
mode=$1
cache_dir=$2
runner_owner=$(id -u):$(id -g)
runner_gid=$(id -g)

case "$mode" in
    prepare)
        mkdir -p "$cache_dir/partial"
        sudo chown -R "$runner_owner" "$cache_dir"
        sudo chmod 0755 "$cache_dir"
        sudo chown "_apt:$runner_gid" "$cache_dir/partial"
        sudo chmod 0775 "$cache_dir/partial"
        ;;
    finalize)
        sudo chown -R "$runner_owner" "$cache_dir"
        ;;
    *) usage ;;
esac

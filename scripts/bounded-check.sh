#!/bin/sh
# Keep a defective test from exhausting the workstation. GOMEMLIMIT is only
# a GC target; the cgroup is the hard limit for the entire compiler/test tree.
set -eu
ulimit -c 0
export GOMEMLIMIT="${GOMEMLIMIT:-512MiB}"
export GOMAXPROCS="${GOMAXPROCS:-2}"
if [ "$(uname -s)" = Linux ]; then
    if command -v systemd-run >/dev/null 2>&1 &&
       systemctl --user show --property=Version >/dev/null 2>&1; then
        exec systemd-run --user --quiet --wait --pipe --collect \
            --working-directory="$PWD" \
            --property=MemoryMax=2G --property=MemorySwapMax=0 \
            --property=TasksMax=256 --property=RuntimeMaxSec=180s \
            env "PATH=$PATH" "CGO_ENABLED=${CGO_ENABLED:-0}" \
            "GOMEMLIMIT=$GOMEMLIMIT" "GOMAXPROCS=$GOMAXPROCS" "$@"
    fi
    # Fallback for Linux without a user service manager. This bounds each
    # process's address space; -p 1 in Makefile also limits compiler concurrency.
    ulimit -v 2097152
fi
exec "$@"

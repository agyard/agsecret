#!/bin/sh
# Keep a defective test from exhausting the workstation. GOMEMLIMIT is a GC
# target; the Linux address-space limit is an additional per-process guard.
set -eu
ulimit -c 0
export GOMEMLIMIT="${GOMEMLIMIT:-512MiB}"
export GOMAXPROCS="${GOMAXPROCS:-2}"
if [ "$(uname -s)" = Linux ]; then
    # -p 1 in Makefile limits compiler/test concurrency. Keep this wrapper
    # independent of a service manager so it works in minimal CI environments.
    ulimit -v 2097152
fi
exec "$@"

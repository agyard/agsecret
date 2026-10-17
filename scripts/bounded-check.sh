#!/bin/sh
# Stop a runaway test from using up the machine. GOMEMLIMIT only guides the
# garbage collector; on Linux, ulimit -v also caps each process's address space.
set -eu
ulimit -c 0
export GOMEMLIMIT="${GOMEMLIMIT:-512MiB}"
export GOMAXPROCS="${GOMAXPROCS:-2}"
if [ "$(uname -s)" = Linux ]; then
    ulimit -v "${VMEM_KB:-2097152}"
fi
exec "$@"

#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

if ! command -v cargo-mutants >/dev/null 2>&1; then
  echo "cargo-mutants is required (cargo install cargo-mutants --locked)" >&2
  exit 1
fi

cores=$(nproc 2>/dev/null || echo 4)
default_jobs=4
[ "$cores" -lt "$default_jobs" ] && default_jobs=$cores

packages=${KAHEA_MUTANT_PACKAGES:-"kahea-core kahea-plan kahea-conformance kahea-ingest"}
jobs=${KAHEA_MUTANT_JOBS:-$default_jobs}
tasks=${KAHEA_MUTANT_TASKS:-$((jobs * 2))}
timeout=${KAHEA_MUTANT_TIMEOUT:-90}
copy_target=${KAHEA_MUTANT_COPY_TARGET:-true}
memory_high=${KAHEA_MUTANT_MEMORY_HIGH:-16G}
memory_max=${KAHEA_MUTANT_MEMORY_MAX:-32G}
tasks_max=${KAHEA_MUTANT_TASKS_MAX:-512}
cpu_quota=${KAHEA_MUTANT_CPU_QUOTA:-$((jobs * 200))%}

# Every job copies the workspace and its build tree. Keeping that on a disk
# path matters: a tmpfs TMPDIR spends real memory on build directories and can
# starve the rest of the machine long before the run finishes.
scratch=${KAHEA_MUTANT_SCRATCH:-${XDG_CACHE_HOME:-$HOME/.cache}/kahea-mutants}
case "$scratch" in
  "$PWD"/*) echo "scratch must live outside the workspace: $scratch" >&2; exit 2 ;;
esac
mkdir -p "$scratch"
trap 'rm -rf "$scratch"' EXIT INT TERM
TMPDIR=$scratch
export TMPDIR

# --jobserver-tasks caps rustc processes across every job at once. Without it
# the cap is the CPU count, so a handful of jobs can fan out to hundreds of
# compilers and drive the load average into the hundreds.
#
# `--cargo-arg=--workspace` is what actually widens the test scope. cargo-mutants
# 27 accepts `--test-workspace` and `--test-package` but ignores both: it always
# runs `cargo test --package=<mutated package>`, so a mutant is judged only by
# its own crate's tests. Injecting `--workspace` into every cargo invocation
# puts all 113 workspace tests behind each mutant instead of 7 or 19.
set -- cargo mutants
for package in $packages; do
  set -- "$@" -p "$package"
done
set -- "$@" \
  -j "$jobs" \
  --jobserver-tasks "$tasks" \
  --copy-target "$copy_target" \
  --timeout "$timeout" \
  --cargo-arg=--workspace

# Scope escape hatch for callers that need a narrower run than a package list,
# such as `--in-diff` on a pull request.
if [ -n "${KAHEA_MUTANT_EXTRA:-}" ]; then
  # shellcheck disable=SC2086
  set -- "$@" $KAHEA_MUTANT_EXTRA
fi

# Probe rather than trust: `systemd-run` is present on many CI images but has
# no user session bus to run a transient scope in.
if [ "${KAHEA_MUTANT_UNCONFINED:-0}" = "1" ]; then
  echo "running without cgroup limits (KAHEA_MUTANT_UNCONFINED=1)" >&2
elif systemd-run --user --scope --quiet --collect -- true >/dev/null 2>&1; then
  set -- systemd-run --user --scope --quiet --collect \
    -p "MemoryHigh=$memory_high" \
    -p "MemoryMax=$memory_max" \
    -p "CPUQuota=$cpu_quota" \
    -p "TasksMax=$tasks_max" \
    -- "$@"
else
  echo "no usable systemd user scope; running without cgroup limits" >&2
fi

command -v ionice >/dev/null 2>&1 && set -- ionice -c 3 "$@"
command -v nice >/dev/null 2>&1 && set -- nice -n 19 "$@"

echo "mutation gate: packages=[$packages] jobs=$jobs tasks=$tasks cpu=$cpu_quota memory=$memory_high/$memory_max scratch=$scratch" >&2

# Run as a child rather than exec'ing, so an interrupted gate still reaches the
# cleanup trap instead of stranding tens of gigabytes of build copies.
"$@" &
child=$!
trap 'kill -TERM "$child" 2>/dev/null; rm -rf "$scratch"; exit 143' INT TERM
status=0
wait "$child" || status=$?
exit "$status"

#!/usr/bin/env bash
# Regenerate the crash fixtures from real executions (Linux x86_64, gcc).
#   bash tests/fixtures/crash/gen.sh
set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
gcc -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer -o /tmp/zoo-asan zoo.c
gcc -O0 -g -fstack-protector-strong -o /tmp/zoo-release zoo.c
export ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:symbolize=1
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
for mode in stack heap global uaf double null div; do
  /tmp/zoo-asan "$mode" >/dev/null 2>"asan-$mode.txt"
  echo "asan $mode: exit $?"
done
for mode in stack double; do
  /tmp/zoo-release "$mode" >/dev/null 2>"release-$mode.txt"
  echo "release $mode: exit $?"
done

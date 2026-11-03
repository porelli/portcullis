#!/bin/sh
# The settings hook (manifest hooks[log]): stores its stdin (the Hub's
# HookInput JSON) as /log/hook-<n>.json, n counting up. The Hub runs hooks
# of one instance one at a time, so the counter needs no lock.
set -eu
n=$(( $(cat /log/hook-count 2>/dev/null || echo 0) + 1 ))
cat > "/log/hook-$(printf %04d "$n").json"
echo "$n" > /log/hook-count
echo "hook: stored input $n"

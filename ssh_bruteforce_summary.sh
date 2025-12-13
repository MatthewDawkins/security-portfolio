#!/bin/bash

LOG="/var/log/auth.log"

echo "=== SSH Brute Force Summary ==="
echo

#Total failed logins
echo -n "Total failed SSH logins: "
grep "Failed password" "$LOG" | wc -l
echo

# Failed logins by IP
echo "Failed logins by IP:"
grep "Failed password" "$LOG" | awk '{for (i=1;i<=NF;i++) if ($i=="from") {print $(i+1); break}}' | sort | uniq -c
echo

# Failed logins by username
echo "Failed logins by username:"
grep "Failed password" "$LOG" \
	| awk '{for (i=1;i<=NF;i++) if ($i=="for") print $(i+1)}' \
	| sort | uniq -c
echo

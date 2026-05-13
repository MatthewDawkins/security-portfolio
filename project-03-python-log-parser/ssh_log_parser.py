#!/usr/bin/env python3

from collections import defaultdict

LOG_FILE = "/var/log/auth.log"

failed_by_ip = defaultdict(int)
failed_by_user = defaultdict(int)

try:
    with open(LOG_FILE, "r") as log:
        for line in log:
            if "Failed password" in line:
                parts = line.split()

                if "from" in parts:
                    ip_index = parts.index("from") + 1
                    ip = parts[ip_index]
                    failed_by_ip[ip] += 1

                if "for" in parts:
                    user_index = parts.index("for") + 1
                    user = parts[user_index]
                    failed_by_user[user] += 1

except FileNotFoundError:
    print(f"Log file not found: {LOG_FILE}")
    exit(1)

print("=== SSH Failed Login Summary ===\n")

print("Failed attempts by IP (most frequent first):")
for ip, count in sorted(failed_by_ip.items(), key=lambda x: x[1], reverse=True):
    print(f"  {count:>4}  {ip}")

print("\nFailed attempts by username (most frequent first):")
for user, count in sorted(failed_by_user.items(), key=lambda x: x[1], reverse=True):
    print(f"  {count:>4}  {user}")

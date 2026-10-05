import argparse
import re
import csv
from collections import Counter
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

parser = argparse.ArgumentParser(
    description="Analyze authentication logs for suspicious login activity."
)

parser.add_argument(
    "logfile",
    nargs="?",
    default="logs/sample_auth.log",
    help="Path to the authentication log file"
)

args = parser.parse_args()

LOG_FILE = Path(args.logfile)

if not LOG_FILE.is_absolute():
    LOG_FILE = BASE_DIR / LOG_FILE

if not LOG_FILE.exists():
    print(f"[ERROR] Log file not found: {LOG_FILE}")
    raise SystemExit(1)

failed_logins = []
successful_logins = []

with open(LOG_FILE, "r") as file:
    for line in file:

        failed_match = re.search(
            r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)",
            line
        )

        success_match = re.search(
            r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)",
            line
        )

        if failed_match:
            username = failed_match.group(1)
            ip_address = failed_match.group(2)

            failed_logins.append({
                "username": username,
                "ip": ip_address
            })

        elif success_match:
            username = success_match.group(1)
            ip_address = success_match.group(2)

            successful_logins.append({
                "username": username,
                "ip": ip_address
            })


print("\n=== SECURITY LOG ANALYSIS ===")

print(f"\nTotal failed logins: {len(failed_logins)}")
print(f"Total successful logins: {len(successful_logins)}")

failed_ips = Counter(event["ip"] for event in failed_logins)

print("\nTop IP addresses with failed logins:")

for ip, count in failed_ips.most_common():
    print(f"{ip}: {count} failed attempts")

THRESHOLD = 5

# Find IP addresses that had successful logins
successful_ips = {
    event["ip"] for event in successful_logins
}


# Assign severity levels
print("\n=== SECURITY ALERTS ===")

for ip, count in failed_ips.items():

    if count >= THRESHOLD and ip in successful_ips:
        severity = "CRITICAL"

    elif count >= THRESHOLD:
        severity = "HIGH"

    elif count >= 3:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    print(f"[{severity}] {ip}: {count} failed login attempts")


# Detect failed attempts followed by a successful login
print("\n=== CORRELATED SECURITY EVENTS ===")

for ip, count in failed_ips.items():

    if count >= THRESHOLD and ip in successful_ips:
        print(
            f"[CRITICAL] {ip}: {count} failed login attempts "
            f"followed by a successful login"
        )


# Count the most targeted usernames
targeted_users = Counter(
    event["username"] for event in failed_logins
)

print("\n=== MOST TARGETED USERS ===")

for username, count in targeted_users.most_common():
    print(f"{username}: {count} failed attempts")

# Count successful logins by IP
successful_ip_counts = Counter(
    event["ip"] for event in successful_logins
)

# Create output directory
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

# Create CSV security report
OUTPUT_FILE = OUTPUT_DIR / "security_report.csv"

with open(OUTPUT_FILE, "w", newline="") as file:
    writer = csv.writer(file)

    writer.writerow([
        "IP Address",
        "Failed Attempts",
        "Successful Logins",
        "Severity",
        "Correlated Event"
    ])

    for ip, failed_count in failed_ips.items():

        successful_count = successful_ip_counts.get(ip, 0)

        correlated = (
            failed_count >= THRESHOLD
            and successful_count > 0
        )

        if correlated:
            severity = "CRITICAL"

        elif failed_count >= THRESHOLD:
            severity = "HIGH"

        elif failed_count >= 3:
            severity = "MEDIUM"

        else:
            severity = "LOW"

        writer.writerow([
            ip,
            failed_count,
            successful_count,
            severity,
            "YES" if correlated else "NO"
        ])

print(f"\nSecurity report exported to: {OUTPUT_FILE}")
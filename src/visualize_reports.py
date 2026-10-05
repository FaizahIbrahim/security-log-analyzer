from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


BASE_DIR = Path(__file__).resolve().parent

REPORT_FILE = BASE_DIR / "output" / "security_report.csv"
CHART_FILE = BASE_DIR / "output" / "security_activity_by_ip.png"


# Load the generated security report
df = pd.read_csv(REPORT_FILE)


print("\n=== SECURITY REPORT DATA ===")
print(df)


print("\n=== ANALYTICS SUMMARY ===")

print(f"Total IP addresses analyzed: {len(df)}")
print(f"Total failed attempts: {df['Failed Attempts'].sum()}")
print(f"Total successful logins: {df['Successful Logins'].sum()}")

critical_count = (df["Severity"] == "CRITICAL").sum()

print(f"Critical security events: {critical_count}")


# Create a grouped bar chart
ax = df.plot(
    x="IP Address",
    y=["Failed Attempts", "Successful Logins"],
    kind="bar",
    figsize=(9, 5)
)

plt.title("Authentication Activity by Source IP")
plt.xlabel("Source IP Address")
plt.ylabel("Number of Login Attempts")

plt.xticks(rotation=0)
plt.legend(title="Event Type")

plt.tight_layout()

plt.savefig(CHART_FILE, dpi=200)

print(f"\nChart exported to: {CHART_FILE}")

plt.show()
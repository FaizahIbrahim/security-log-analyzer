# Detection Logic

The Security Log Analyzer uses rule-based thresholds to classify authentication activity.

## Severity Levels

| Severity | Criteria |
|---|---|
| LOW | Fewer than 3 failed login attempts |
| MEDIUM | 3–4 failed login attempts |
| HIGH | 5 or more failed login attempts |
| CRITICAL | 5 or more failed attempts followed by a successful login |

## Correlation Logic

An IP address is classified as CRITICAL when it generates at least five failed login attempts and later records a successful login.

This rule is designed for this educational project and is not intended to represent a universal SOC detection standard.

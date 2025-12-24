# Snort Fast Alert Triage (Python) — Portfolio Lab

This repository provides small Python utilities to turn **Snort fast alert logs** into structured data and quick SOC-style summaries.

It supports my lab work with **Snort 3 custom rules** (SQLi, scans, brute-force spikes, flooding) by enabling:
- faster triage of alerts
- basic aggregation (top signatures, top source IPs, top destination ports, priorities)

> Note: This is intended for **controlled lab environments** only.

---

## Input Format (Fast Alerts)
The parser expects lines similar to:
## Expected Output (Example)

After parsing and summarizing, you should see SOC-style stats similar to:

```text
Total alerts: 12

Top 5 signatures:
    1  WEB-ATTACK SQLi - UNION SELECT in URI
    1  WEB-ATTACK SQLi - ' OR 1=1 in URI
    1  WEB-ATTACK SQLi - information_schema in URI
    1  WEB-ATTACK SQLi - sleep() time-based attempt in URI
    1  RECON Possible TCP SYN scan (by_src threshold)

Top 5 source IPs:
    4  10.0.0.20
    2  10.0.0.5
    1  10.0.0.40
    1  10.0.0.50
    1  10.0.0.51

Top 5 destination ports:
    6  80
    2  22
    1  443

Priority distribution:
  Priority 1: 6
  Priority 2: 6

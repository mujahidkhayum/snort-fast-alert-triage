# Snort Fast Alert Triage (Python) — Portfolio Lab

This repository provides small Python utilities to turn **Snort fast alert logs** into structured data and quick SOC-style summaries.

It supports my lab work with **Snort 3 custom rules** (SQLi, scans, brute-force spikes, flooding) by enabling:
- faster triage of alerts
- basic aggregation (top signatures, top source IPs, top destination ports, priorities)

> Note: This is intended for **controlled lab environments** only.

---

## Input Format (Fast Alerts)
The parser expects lines similar to:

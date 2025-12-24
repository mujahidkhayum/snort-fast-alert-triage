# Snort Fast Alert Triage (Python) — Portfolio Lab

This repository provides small Python utilities to turn **Snort fast alert logs** into structured data and quick SOC-style summaries.

It supports my lab work with **Snort 3 custom rules** (SQLi, scans, brute-force spikes, flooding) by enabling:
- Faster triage of alerts
- Basic aggregation (top signatures, top source IPs, top destination ports, priorities)

> **Note:** Intended for **controlled lab environments** only.

---

## Repository Structure
- `src/parse_fast_alert.py` — parse fast alerts → structured JSON
- `src/summarize_alerts.py` — SOC-style summaries (top-N); optional CSV export
- `samples/alert_fast_sample.txt` — **synthetic demo data** for portfolio/testing
- `output/` — output directory (contains `.gitkeep`)

---

## Input Format (Fast Alerts)
The parser expects lines similar to:
MM/DD-HH:MM:SS.micro [] [gid:sid:rev] message [] [Priority: X] {PROTO} src_ip:src_port -> dst_ip:dst_port

text

Snort fast alert formats can vary slightly. If your real Snort output differs, update the regex in `src/parse_fast_alert.py`.

---

## How to Run

### 1) Parse alerts into JSON
```bash
python3 src/parse_fast_alert.py \
  --input samples/alert_fast_sample.txt \
  --output output/parsed_alerts.json
(Optional: keep unparsed lines)

bash
python3 src/parse_fast_alert.py \
  --input samples/alert_fast_sample.txt \
  --output output/parsed_alerts.json \
  --keep-unparsed
2) Generate SOC-style summaries
bash
python3 src/summarize_alerts.py --input output/parsed_alerts.json
Top 10 instead of top 5:

bash
python3 src/summarize_alerts.py --input output/parsed_alerts.json --top 10
Write a CSV summary:

bash
python3 src/summarize_alerts.py \
  --input output/parsed_alerts.json \
  --csv output/summary.csv
Expected Output (Example)
After parsing and summarizing, you should see SOC-style stats similar to:

text
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
The exact counts depend on the input file. This example corresponds to samples/alert_fast_sample.txt.

Safety / Ethics
Use only on networks and systems you own or have explicit permission to test. Do not use this tooling for unauthorized activity.

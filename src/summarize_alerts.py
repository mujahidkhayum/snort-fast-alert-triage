#!/usr/bin/env python3
"""
Summarize parsed Snort alerts JSON produced by parse_fast_alert.py.
Prints SOC-style quick stats and (optionally) writes a CSV summary.
"""

import json
import csv
import argparse
from collections import Counter
from typing import Dict, Any, List

def main():
    ap = argparse.ArgumentParser(description="Summarize parsed Snort alerts.")
    ap.add_argument("--input", required=True, help="Path to parsed_alerts.json")
    ap.add_argument("--csv", default="", help="Optional path to write CSV summary")
    ap.add_argument("--top", type=int, default=5, help="Top-N results to print")
    args = ap.parse_args()

    data: Dict[str, Any] = json.load(open(args.input, "r", encoding="utf-8"))
    events: List[Dict[str, Any]] = data.get("events", [])

    by_sig = Counter(e["message"] for e in events)
    by_src = Counter(e["src_ip"] for e in events)
    by_dst = Counter(e["dst_ip"] for e in events)
    by_dport = Counter(e["dst_port"] for e in events)
    by_prio = Counter(e["priority"] for e in events)

    print(f"Total alerts: {len(events)}\n")

    print(f"Top {args.top} signatures:")
    for msg, cnt in by_sig.most_common(args.top):
        print(f"  {cnt:>3}  {msg}")
    print()

    print(f"Top {args.top} source IPs:")
    for ip, cnt in by_src.most_common(args.top):
        print(f"  {cnt:>3}  {ip}")
    print()

    print(f"Top {args.top} destination IPs:")
    for ip, cnt in by_dst.most_common(args.top):
        print(f"  {cnt:>3}  {ip}")
    print()

    print(f"Top {args.top} destination ports:")
    for p, cnt in by_dport.most_common(args.top):
        print(f"  {cnt:>3}  {p}")
    print()

    print("Priority distribution:")
    for prio in sorted(by_prio.keys()):
        print(f"  Priority {prio}: {by_prio[prio]}")
    print()

    if args.csv:
        rows = [
            ("total_alerts", str(len(events)), ""),
            ("top_signature", by_sig.most_common(1)[0][0] if by_sig else "", by_sig.most_common(1)[0][1] if by_sig else 0),
            ("top_src_ip", by_src.most_common(1)[0][0] if by_src else "", by_src.most_common(1)[0][1] if by_src else 0),
            ("top_dst_ip", by_dst.most_common(1)[0][0] if by_dst else "", by_dst.most_common(1)[0][1] if by_dst else 0),
            ("top_dst_port", str(by_dport.most_common(1)[0][0]) if by_dport else "", by_dport.most_common(1)[0][1] if by_dport else 0),
            ("priority_counts", json.dumps(dict(by_prio)), ""),
        ]
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["metric", "value", "count"])
            for r in rows:
                w.writerow(r)
        print(f"Wrote CSV summary: {args.csv}")

if __name__ == "__main__":
    main()

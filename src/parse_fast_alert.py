#!/usr/bin/env python3
"""
Parse Snort fast alert lines into structured JSON.

Expected (common) fast alert format:
MM/DD-HH:MM:SS.micro [**] [gid:sid:rev] message [**] [Priority: X] {PROTO} src_ip:src_port -> dst_ip:dst_port
"""

import re
import json
import argparse
from typing import Optional, Dict, Any

FAST_ALERT_RE = re.compile(
    r"^(?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"
$$
\*\*
$$\s+
$$
(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)
$$\s+"
    r"(?P<msg>.*?)\s+
$$
\*\*
$$\s+"
    r"
$$
Priority:\s*(?P<prio>\d+)
$$\s+"
    r"\{(?P<proto>\w+)\}\s+"
    r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<src_port>\d+)\s+->\s+"
    r"(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<dst_port>\d+)\s*$"
)

def parse_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None

    m = FAST_ALERT_RE.match(line)
    if not m:
        return None

    d = m.groupdict()
    return {
        "timestamp": d["ts"],
        "gid": int(d["gid"]),
        "sid": int(d["sid"]),
        "rev": int(d["rev"]),
        "message": d["msg"].strip(),
        "priority": int(d["prio"]),
        "protocol": d["proto"],
        "src_ip": d["src_ip"],
        "src_port": int(d["src_port"]),
        "dst_ip": d["dst_ip"],
        "dst_port": int(d["dst_port"]),
        "raw": line,
    }

def main():
    ap = argparse.ArgumentParser(description="Parse Snort fast alerts into JSON.")
    ap.add_argument("--input", required=True, help="Path to fast alert file")
    ap.add_argument("--output", default="output/parsed_alerts.json", help="Output JSON path")
    ap.add_argument("--keep-unparsed", action="store_true", help="Store unparsed lines in output JSON")
    args = ap.parse_args()

    events = []
    unparsed = []

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)
            else:
                if line.strip():
                    unparsed.append(line.strip())

    out_obj = {"events": events}
    if args.keep_unparsed:
        out_obj["unparsed_lines"] = unparsed

    with open(args.output, "w", encoding="utf-8") as out:
        json.dump(out_obj, out, indent=2)

    print(f"Parsed alerts: {len(events)}")
    if args.keep_unparsed:
        print(f"Unparsed lines: {len(unparsed)}")
    print(f"Wrote: {args.output}")

if __name__ == "__main__":
    main()

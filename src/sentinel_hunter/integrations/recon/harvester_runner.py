#!/usr/bin/env python3
import argparse, json, subprocess, sys
from pathlib import Path

def run_harvester(target, output_file):
    print(f"[*] Running theHarvester for passive recon on {target}...")
    # Using safe, public engines. -l limits results to avoid long hangs.
    cmd = ["theHarvester", "-d", target, "-b", "hackertarget, crtsh, duckduckgo", "-l", "100", "-f", "tmp_harvester", "-format", "json"]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        json_file = Path("tmp_harvester.json")
        if json_file.exists():
            data = json.loads(json_file.read_text())
            emails = data.get("emails", [])
            subdomains = data.get("hosts", [])
            print(f"[+] Found {len(emails)} emails and {len(subdomains)} subdomains passively.")
            return {"emails": emails, "subdomains": subdomains}
    except Exception as e:
        print(f"[!] theHarvester failed or not installed: {e}")
    return {"emails": [], "subdomains": []}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--output", default="reports/harvester_results.json")
    args = parser.parse_args()
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    results = run_harvester(args.target, args.output)
    Path(args.output).write_text(json.dumps(results, indent=2))
    print(f"[+] Harvester results saved to {args.output}")

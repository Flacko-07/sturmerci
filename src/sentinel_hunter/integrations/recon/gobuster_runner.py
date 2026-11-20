#!/usr/bin/env python3
import argparse, json, subprocess, sys
from pathlib import Path

def run_gobuster(url, output_file):
    print(f"[*] Running Gobuster on {url}...")
    # Using dir mode, common extensions, ignoring 404s
    cmd = ["gobuster", "dir", "-u", url, "-w", "/usr/share/wordlists/dirb/common.txt", 
           "-x", "php,js,html,json,txt,bak,zip", "-q", "-o", output_file]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if Path(output_file).exists():
            results = Path(output_file).read_text().splitlines()
            # Filter for interesting status codes
            interesting = [r for r in results if any(code in r for code in ["200", "301", "302", "403", "500"])]
            print(f"[+] Gobuster found {len(interesting)} interesting paths.")
            return {"paths": interesting}
    except Exception as e:
        print(f"[!] Gobuster failed: {e}")
    return {"paths": []}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--output", default="reports/gobuster_results.json")
    args = parser.parse_args()
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    # Convert json output expectation to text parsing for simplicity
    txt_out = args.output.replace(".json", ".txt")
    results = run_gobuster(args.url, txt_out)
    Path(args.output).write_text(json.dumps(results, indent=2))
    print(f"[+] Gobuster results saved to {args.output}")

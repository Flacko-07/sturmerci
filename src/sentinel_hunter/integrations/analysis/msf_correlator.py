#!/usr/bin/env python3
import argparse, json, subprocess, sys, re
from pathlib import Path

def check_msf_cves(service_name, version, output_file):
    print(f"[*] Querying Metasploit for {service_name} {version}...")
    # Clean version string for search
    clean_version = re.sub(r'[^0-9.]', '', version)
    query = f"search name:{service_name} version:{clean_version}"
    
    cmd = ["msfconsole", "-q", "-x", f"{query}; exit"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        # Look for "exploit/" or "auxiliary/" in the output
        matches = re.findall(r'(exploit/[^\s]+|auxiliary/[^\s]+).*?(\d{4}-\d{4})', result.stdout, re.IGNORECASE)
        cves = list(set([m1 for m0, m1 in matches]))
        print(f"[+] Metasploit found {len(cves)} potential CVEs/exploits.")
        Path(output_file).write_text(json.dumps({"service": service_name, "version": version, "cves": cves}, indent=2))
        return cves
    except Exception as e:
        print(f"[!] Metasploit query failed: {e}")
    return []

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", default="reports/msf_results.json")
    args = parser.parse_args()
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    check_msf_cves(args.service, args.version, args.output)

#!/usr/bin/env python3
import argparse, json, subprocess, sys, urllib.request
from pathlib import Path

def scan_js_files(urls, output_file):
    print(f"[*] Running Semgrep on discovered JS files...")
    findings = []
    for url in urls:
        if not url.endswith(".js"): continue
        filename = url.split("/")[-1]
        local_path = f"/tmp/{filename}"
        try:
            print(f"    Downloading {url}...")
            urllib.request.urlretrieve(url, local_path)
            
            # Run semgrep with a focus on security and correctness
            cmd = ["semgrep", "--config", "p/security-audit", "--config", "p/secrets", 
                   "--json", "--quiet", local_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for res in data.get("results", []):
                        findings.append({
                            "file": url,
                            "rule": res.get("check_id"),
                            "message": res.get("extra", {}).get("message"),
                            "line": res.get("start", {}).get("line")
                        })
                except: pass
        except Exception as e:
            print(f"[!] Failed to process {url}: {e}")
    
    print(f"[+] Semgrep found {len(findings)} potential issues in JS files.")
    Path(output_file).write_text(json.dumps({"findings": findings}, indent=2))
    return findings

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--urls", nargs="+", required=True)
    parser.add_argument("--output", default="reports/semgrep_results.json")
    args = parser.parse_args()
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    scan_js_files(args.urls, args.output)

#!/usr/bin/env python3
import argparse, json, subprocess, sys, urllib.request
from pathlib import Path

def scan_py_files(urls, output_file):
    print(f"[*] Running Bandit on discovered Python files...")
    findings = []
    for url in urls:
        if not url.endswith(".py"): continue
        filename = url.split("/")[-1]
        local_path = f"/tmp/{filename}"
        try:
            print(f"    Downloading {url}...")
            urllib.request.urlretrieve(url, local_path)
            cmd = ["bandit", "-r", local_path, "-f", "json", "-q"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for res in data.get("results", []):
                        findings.append({
                            "file": url,
                            "severity": res.get("issue_severity"),
                            "confidence": res.get("issue_confidence"),
                            "test_name": res.get("test_name"),
                            "line": res.get("line_number")
                        })
                except: pass
        except Exception as e:
            pass # Ignore download failures
    print(f"[+] Bandit found {len(findings)} potential Python security issues.")
    Path(output_file).write_text(json.dumps({"findings": findings}, indent=2))
    return findings

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--urls", nargs="+", default=[])
    parser.add_argument("--output", default="reports/bandit_results.json")
    args = parser.parse_args()
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    scan_py_files(args.urls, args.output)

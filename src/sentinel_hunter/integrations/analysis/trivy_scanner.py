#!/usr/bin/env python3
import argparse, json, subprocess, sys
from pathlib import Path

def scan_with_trivy(target, output_file):
    print(f"[*] Running Trivy on {target}...")
    # Trivy can scan filesystems, repos, or even configs. We'll use it on the reports dir.
    cmd = ["trivy", "fs", "--scanners", "secret,vuln", "--format", "json", "--output", output_file, target]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if Path(output_file).exists():
            data = json.loads(Path(output_file).read_text())
            results = data.get("Results", [])
            vulns = sum(len(r.get("Vulnerabilities", [])) for r in results)
            secrets = sum(len(r.get("Secrets", [])) for r in results)
            print(f"[+] Trivy found {vulns} vulns and {secrets} secrets in scanned artifacts.")
            return {"vulnerabilities": vulns, "secrets": secrets}
    except Exception as e:
        print(f"[!] Trivy failed: {e}")
    return {"vulnerabilities": 0, "secrets": 0}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Directory or file to scan (e.g., ./reports)")
    parser.add_argument("--output", default="reports/trivy_results.json")
    args = parser.parse_args()
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    results = scan_with_trivy(args.target, args.output)
    Path(args.output).write_text(json.dumps(results, indent=2))

#!/usr/bin/env python3
"""Dynamic recon chainer — SCOPE-ENFORCED.
Only chains domains within the target scope. Never recons dummy-payload
domains (test.com etc.) or third-party CDNs. Fail-safe: no scope -> no active recon.
"""
import argparse, re, subprocess, sys
from pathlib import Path

THIRD_PARTY = ("cloudflare.com","google.com","gstatic.com","googleapis.com",
               "w.org","wp.org","wordpress.org","schema.org","example.com",
               "example.org","test.com","email.com","localhost","jquery.com",
               "bootstrapcdn.com","facebook.com","twitter.com","youtube.com")

def in_scope(d, scope):
    d, scope = d.lower().strip("."), scope.lower().strip(".")
    return d == scope or d.endswith("." + scope)

def extract(text, scope):
    cands = set(re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text))
    kept = set()
    for d in cands:
        d = d.lower()
        if any(d == tp or d.endswith("." + tp) for tp in THIRD_PARTY):
            continue
        if in_scope(d, scope):
            kept.add(d)
    return sorted(kept)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input_file")
    ap.add_argument("--scope", default=None, help="target domain, e.g. kaluafarms.com")
    ap.add_argument("--output-dir", default="/tmp/dynamic_recon")
    a = ap.parse_args()
    Path(a.output_dir).mkdir(parents=True, exist_ok=True)
    if not Path(a.input_file).exists():
        print(f"[!] input not found: {a.input_file}"); sys.exit(1)

    if not a.scope:
        print("[!] No --scope provided; skipping active chain recon (fail-safe).")
        return

    domains = extract(Path(a.input_file).read_text(), a.scope)
    print(f"[+] In-scope domains to chain: {len(domains)} (scope={a.scope})")
    for d in domains:
        out = f"{a.output_dir}/subfinder_{d.replace('.', '_')}.txt"
        print(f"[*] subfinder -> {d}")
        try:
            subprocess.run(["subfinder", "-d", d, "-silent", "-o", out],
                           capture_output=True, text=True, timeout=120)
        except Exception as e:
            print(f"[!] subfinder failed for {d}: {e}")
    print("[+] done (out-of-scope domains dropped)")

if __name__ == "__main__":
    main()

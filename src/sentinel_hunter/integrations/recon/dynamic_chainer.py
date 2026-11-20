#!/usr/bin/env python3
"""
Dynamic Reconnaissance Chainer
Extracts new domains/emails from tool output and triggers further recon.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

def extract_targets(text: str):
    """Extract potential subdomains and emails from text."""
    # Basic subdomain regex (e.g., api.dev.example.com)
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    # Basic email regex
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    domains = set(re.findall(domain_pattern, text))
    emails = set(re.findall(email_pattern, text))
    
    # Filter out common false positives
    domains = {d for d in domains if not d.startswith('www.') and len(d) > 5}
    
    return list(domains), list(emails)

def run_subfinder(domain: str, output_file: str):
    """Run subfinder against a newly discovered domain."""
    print(f"[*] Triggering subfinder for newly discovered domain: {domain}")
    cmd = ["subfinder", "-d", domain, "-silent", "-o", output_file]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        print(f"[+] Subfinder results saved to {output_file}")
    except Exception as e:
        print(f"[!] Subfinder failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Chain recon tools based on tool output")
    parser.add_argument("input_file", help="File containing tool output (e.g., nuclei/ffuf results)")
    parser.add_argument("--output-dir", default="/tmp/dynamic_recon", help="Directory for new findings")
    args = parser.parse_args()
    
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)
    
    if not Path(args.input_file).exists():
        print(f"[!] Input file not found: {args.input_file}")
        sys.exit(1)
        
    text = Path(args.input_file).read_text()
    domains, emails = extract_targets(text)
    
    print(f"\n[+] Extracted {len(domains)} potential domains and {len(emails)} emails.")
    
    for domain in domains:
        # Skip the original target if you want, or let it run
        out_file = f"{args.output_dir}/subfinder_{domain.replace('.', '_')}.txt"
        run_subfinder(domain, out_file)
        
    if emails:
        email_file = f"{args.output_dir}/extracted_emails.txt"
        Path(email_file).write_text("\n".join(emails))
        print(f"[+] Extracted emails saved to {email_file}")

if __name__ == "__main__":
    main()

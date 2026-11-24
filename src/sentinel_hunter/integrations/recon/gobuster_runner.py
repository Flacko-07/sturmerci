#!/usr/bin/env python3
import argparse, json, subprocess, shutil, requests, uuid, urllib3
from pathlib import Path
urllib3.disable_warnings()

WORDLISTS = [
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]

def pick_wordlist():
    return next((w for w in WORDLISTS if Path(w).exists()), None)

def detect_soft_404_length(url):
    """Probe a random non-existent path to get the catch-all response length."""
    probe = f"{url.rstrip('/')}/{uuid.uuid4()}"
    try:
        r = requests.get(probe, timeout=10, verify=False)
        if r.status_code == 200:
            return len(r.content)
    except Exception:
        pass
    return None

def run(url):
    wl = pick_wordlist()
    if not wl:
        return {"url": url, "error": "no wordlist found", "paths": []}
    if not shutil.which("gobuster"):
        return {"url": url, "error": "gobuster not installed", "paths": []}

    cmd_base = ["gobuster", "dir", "-u", url, "-w", wl, "-k", "-q", "--no-progress",
                "-t", "10", "-s", "200,204,301,302,307,401,403", "-b", ""]

    soft_len = detect_soft_404_length(url)
    
    # Pass 1: Try with soft-404 exclusion
    cmd_pass1 = cmd_base + (["--exclude-length", str(soft_len)] if soft_len else [])
    
    try:
        p1 = subprocess.run(cmd_pass1, capture_output=True, text=True, timeout=180)
        paths = [l.strip() for l in p1.stdout.splitlines() if l.strip().startswith("/")]
        
        # If we found paths, great!
        if len(paths) > 0:
            return {"url": url, "wordlist": wl, "paths": paths, "count": len(paths),
                    "soft_404_length": soft_len, "error": ""}
        
        # Pass 2: If 0 paths found with exclusion, check if it's a uniform response (WAF/Misconfig)
        if soft_len and len(paths) == 0:
            # Run without exclusion to see the raw volume
            cmd_pass2 = cmd_base
            p2 = subprocess.run(cmd_pass2, capture_output=True, text=True, timeout=180)
            raw_paths = [l.strip() for l in p2.stdout.splitlines() if l.strip().startswith("/")]
            
            if len(raw_paths) > 0:
                return {
                    "url": url, 
                    "wordlist": wl, 
                    "paths": [], 
                    "count": 0,
                    "status": "UNIFORM_RESPONSE_DETECTED",
                    "message": f"Target returns uniform {soft_len}-byte response for all paths. Likely WAF, CDN block, or misconfiguration.",
                    "raw_paths_count": len(raw_paths),
                    "error": ""
                }
                
        return {"url": url, "wordlist": wl, "paths": paths, "count": 0,
                "soft_404_length": soft_len, "error": ""}
                
    except Exception as e:
        return {"url": url, "error": str(e), "paths": []}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--output", default="reports/gobuster.json")
    a = ap.parse_args()
    res = run(a.url)
    Path(a.output).parent.mkdir(parents=True, exist_ok=True)
    Path(a.output).write_text(json.dumps(res, indent=2))
    
    msg = f"[+] gobuster {a.url}: {res.get('count', 0)} paths"
    if res.get("status") == "UNIFORM_RESPONSE_DETECTED":
        msg += f" (WAF/Misconfig detected: {res.get('raw_paths_count')} uniform responses)"
    print(msg + (f"  ERROR: {res['error']}" if res.get("error") else ""))

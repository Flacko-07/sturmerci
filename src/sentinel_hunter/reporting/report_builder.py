#!/usr/bin/env python3
"""Faithful per-tool report builder.
Reports exactly what each tool collected. No invented findings.
Empty/missing artifacts are reported honestly.
"""
import json, sys
from pathlib import Path
from datetime import datetime, timezone

def jload(p):
    try: return json.loads(p.read_text())
    except Exception: return None

def lines(p):
    try: return [l.strip() for l in p.read_text().splitlines() if l.strip()]
    except Exception: return []

def status(n):
    return "collected" if n else "empty_or_not_run"

def main():
    r = Path(sys.argv[1]).expanduser() if len(sys.argv) > 1 else Path.home()/"creative-logic-agent"/"reports"
    target = sys.argv[2] if len(sys.argv) > 2 else None
    out = {"generated": datetime.now(timezone.utc).isoformat(),
           "reports_dir": str(r), "target_filter": target, "tools": {}}

    subs = set()
    sf = jload(r/"subfinder.json")
    if isinstance(sf, dict):
        for k in ("subdomains","hosts","results"):
            if isinstance(sf.get(k), list): subs.update(sf[k])
    for f in (r/"dynamic_recon").glob("subfinder_*.txt"): subs.update(lines(f))
    out["tools"]["subfinder"] = {"status": status(len(subs)), "count": len(subs), "subdomains": sorted(subs)}

    hv = jload(r/"harvester.json")
    out["tools"]["theHarvester"] = {"status": "collected" if hv else "empty_or_not_run", "raw": hv}

    hx = lines(r/"httpx_live.txt")
    out["tools"]["httpx"] = {"status": status(len(hx)), "count": len(hx), "live_hosts": hx}

    nm = jload(r/"nmap.json")
    out["tools"]["nmap"] = {"status": "collected" if nm else "empty_or_not_run", "raw": nm}

    gob = {}
    for f in sorted(r.glob("gobuster_*.json")):
        d = jload(f); paths = d.get("paths", []) if isinstance(d, dict) else []
        gob[f.stem[len("gobuster_"):]] = paths
    found = {k: v for k, v in gob.items() if v}
    out["tools"]["gobuster"] = {"status": status(len(found)), "hosts_scanned": len(gob),
                                "hosts_with_paths": len(found), "paths": found}

    nuc = lines(r/"nuclei_results.txt")
    out["tools"]["nuclei"] = {"status": status(len(nuc)), "count": len(nuc), "matches": nuc}

    ffuf = {f.stem: jload(f) for f in sorted(r.glob("ffuf_*_results.json"))}
    out["tools"]["ffuf"] = {"status": "collected" if ffuf else "empty_or_not_run", "files": ffuf}

    sq = {f.stem: jload(f) for f in sorted(r.glob("sqlmap_*_results.json"))}
    out["tools"]["sqlmap"] = {"status": "collected" if sq else "empty_or_not_run", "files": sq}

    lm = jload(r/"llm_mutator_results.json")
    out["tools"]["llm_mutator"] = {"status": "collected" if lm else "empty_or_not_run", "raw": lm}

    tv = jload(r/"trivy_audit.json")
    out["tools"]["trivy"] = {"status": "collected" if tv else "empty_or_not_run", "raw": tv}

    logic = {}
    for f in sorted(r.glob("logic_*.json")):
        d = jload(f)
        if not isinstance(d, dict): continue
        url = d.get("target_url", "")
        if target and target not in url: continue
        params = sorted({a.get("parameter") for a in d.get("anomalies", []) if a.get("parameter")})
        logic[url] = {"tools_run": d.get("tools_run", []), "dom_params": params,
                      "nuclei_findings": d.get("findings", []),
                      "mutation_groups": len(d.get("anomalies", []))}
    out["tools"]["logic_testing"] = {"status": status(len(logic)), "targets": logic}

    dest = r/"faithful_report.json"
    dest.write_text(json.dumps(out, indent=2))
    print(f"FAITHFUL PER-TOOL REPORT  ({r})")
    print("="*60)
    for name, info in out["tools"].items():
        print(f"\n[{name}] status={info['status']}")
        for k, v in info.items():
            if k == "status": continue
            s = v if isinstance(v, (int, str)) else json.dumps(v)
            print(f"   {k}: {str(s)[:200]}")
    print("\nSaved:", dest)

if __name__ == "__main__":
    main()

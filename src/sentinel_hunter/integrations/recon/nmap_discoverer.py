#!/usr/bin/env python3
import argparse, json, subprocess, sys, xml.etree.ElementTree as ET
from pathlib import Path

def run_nmap(target, output_file):
    print(f"[*] Running intelligent Nmap discovery on {target}...")
    # Safe, connect scan (-sT), no ping (-Pn), no DNS (-n), fast rate, top web ports + top 1000
    ports = "80,443,8080,8443,8000,3000,5000,8081,9000,10000"
    cmd = ["nmap", "-sT", "-Pn", "-n", "--max-rate", "100", "-p", ports, "-oX", "/tmp/nmap_smart.xml", target]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        tree = ET.parse("/tmp/nmap_smart.xml")
        root = tree.getroot()
        live_endpoints = []
        for host in root.findall("host"):
            ip = host.find("address").get("addr")
            for port in host.findall("ports/port"):
                if port.find("state").get("state") == "open":
                    port_num = port.get("portid")
                    proto = port.get("protocol")
                    service = port.find("service")
                    name = service.get("name") if service is not None else "unknown"
                    # Heuristic: if it looks like HTTP or we don't know, probe it
                    if any(x in name for x in ["http", "ssl", "unknown", "tcpwrapped"]) or port_num in ["80", "443", "8080", "8443"]:
                        scheme = "https" if "ssl" in name or port_num in ["443", "8443"] else "http"
                        live_endpoints.append(f"{scheme}://{ip}:{port_num}")
        print(f"[+] Nmap found {len(live_endpoints)} potential web endpoints.")
        return {"endpoints": live_endpoints}
    except Exception as e:
        print(f"[!] Nmap failed or not installed: {e}")
    return {"endpoints": []}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--output", default="reports/nmap_results.json")
    args = parser.parse_args()
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    results = run_nmap(args.target, args.output)
    Path(args.output).write_text(json.dumps(results, indent=2))
    print(f"[+] Nmap results saved to {args.output}")

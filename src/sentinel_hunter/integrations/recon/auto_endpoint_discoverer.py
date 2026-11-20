#!/usr/bin/env python3
import argparse, json, re, subprocess, sys
from pathlib import Path
import ollama

class EndpointDiscoverer:
    def __init__(self, model="qwen3:1.7b"):
        self.model = model
        self.client = ollama.Client(host="http://127.0.0.1:11434")
        self.discovered = {"domains": [], "endpoints": [], "parameters": {}}

    def run_cmd(self, cmd, description):
        print(f"[*] {description}...")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return result.stdout.strip()
        except Exception as e:
            print(f"[!] {description} failed: {e}")
            return ""

    def discover_subdomains(self, target):
        print(f"[*] Discovering subdomains for {target}...")
        out = self.run_cmd(["/home/nflacko/go/bin/subfinder", "-d", target, "-silent"], "Subfinder")
        self.discovered["domains"] = list(set(out.splitlines())) if out else [target]
        print(f"[+] Found {len(self.discovered['domains'])} potential domains.")

    def probe_live_hosts(self):
        print("[*] Probing for live HTTP/HTTPS hosts...")
        domains_file = "/tmp/discovered_domains.txt"
        Path(domains_file).write_text("\n".join(self.discovered["domains"]))
        out = self.run_cmd(["/home/nflacko/go/bin/httpx", "-l", domains_file, "-silent", "-status-code", "-title"], "HTTPX Probing")
        live_hosts = []
        for line in out.splitlines():
            if any(code in line for code in ["200", "403", "401", "405", "30"]):
                live_hosts.append(line.split(" ")[0])
        self.discovered["live_hosts"] = list(set(live_hosts))
        print(f"[+] Found {len(self.discovered['live_hosts'])} live HTTP endpoints.")

    def discover_api_paths(self, live_hosts):
        print("[*] Running lightweight Nuclei API/Tech detection...")
        targets_file = "/tmp/live_hosts.txt"
        Path(targets_file).write_text("\n".join(live_hosts))
        nuclei_out = "/tmp/nuclei_api_discovery.txt"
        self.run_cmd(["/home/nflacko/go/bin/nuclei", "-l", targets_file, "-t", "http/technologies/", "http/exposures/", "-silent", "-o", nuclei_out, "-timeout", "5"], "Nuclei API Discovery")
        
        endpoints = set()
        if Path(nuclei_out).exists():
            for line in Path(nuclei_out).read_text().splitlines():
                match = re.search(r'(https?://[^\s]+)', line)
                if match:
                    endpoints.add(match.group(1).split("?")[0])
        
        if not endpoints:
            print("[*] Nuclei found no specific API paths. Falling back to discovered live hosts.")
            endpoints = set(live_hosts)
        self.discovered["endpoints"] = list(set(endpoints))[:20]
        print(f"[+] Discovered {len(self.discovered['endpoints'])} unique endpoints.")

    def infer_parameters_with_llm(self):
        print("[*] Using LLM to infer likely parameters for discovered endpoints...")
        for endpoint in self.discovered["endpoints"]:
            prompt = f"Given this API endpoint URL: {endpoint}\nInfer 3 to 5 most likely JSON body or query parameters this endpoint accepts (e.g., user_id, email, role). Output ONLY a valid JSON array of strings."
            try:
                resp = self.client.chat(model=self.model, messages=[{"role":"user","content":prompt}], options={"temperature":0.3,"num_ctx":2048,"think":False})
                match = re.search(r'\[.*\]', resp["message"]["content"], re.DOTALL)
                if match:
                    params = json.loads(match.group())
                    if isinstance(params, list):
                        self.discovered["parameters"][endpoint] = params
            except Exception:
                self.discovered["parameters"][endpoint] = ["id", "user_id"]
        print(f"[+] Inferred parameters for {len(self.discovered['parameters'])} endpoints.")

    def run_full_discovery(self, target):
        self.discover_subdomains(target)
        self.probe_live_hosts()
        self.discover_api_paths(self.discovered.get("live_hosts", self.discovered["domains"]))
        self.infer_parameters_with_llm()
        return self.discovered

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--output", default="reports/discovered_targets.json")
    args = parser.parse_args()
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    discoverer = EndpointDiscoverer()
    results = discoverer.run_full_discovery(args.target)
    Path(args.output).write_text(json.dumps(results, indent=2))
    print(f"[+] Discovery complete. Saved to {args.output}")

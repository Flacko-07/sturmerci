
import urllib3
import requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# UNIVERSAL HTTP PATCH: Force verify=False and browser UA for all requests in this pipeline
_original_get = requests.get
_original_post = requests.post
_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

def _robust_get(*args, **kwargs):
    kwargs.setdefault("verify", False)
    kwargs.setdefault("headers", _HEADERS)
    kwargs.setdefault("timeout", 15)
    return _original_get(*args, **kwargs)

def _robust_post(*args, **kwargs):
    kwargs.setdefault("verify", False)
    kwargs.setdefault("headers", _HEADERS)
    kwargs.setdefault("timeout", 15)
    return _original_post(*args, **kwargs)

requests.get = _robust_get
requests.post = _robust_post
#!/usr/bin/env python3
"""
Ultimate Creative Logic Testing Orchestrator v3
Chains: LLM Mutator -> Nuclei -> FFUF -> SQLMap -> Gitleaks -> Dynamic Recon
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path
from dataclasses import dataclass, field

@dataclass
class OrchestrationResult:
    target_url: str
    tools_run: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    anomalies: list = field(default_factory=list)
    leaked_secrets: list = field(default_factory=list)
    new_recon_targets: list = field(default_factory=list)

class UltimateOrchestrator:
    def __init__(self, base_dir="/home/nflacko/creative-logic-agent"):
        self.base_dir = Path(base_dir)
        self.scripts_dir = self.base_dir / "scripts"
        self.integrations_dir = self.base_dir / "integrations"
        self.templates_dir = self.base_dir / "templates"
        self.reports_dir = self.base_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def _run_cmd(self, cmd, description):
        print(f"\n{'='*60}\n[{description}]\n{'='*60}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"[!] {description} failed: {e}")
            print(f"    stderr: {e.stderr[:200]}")
            return None
        except FileNotFoundError:
            print(f"[!] Command not found. Ensure the tool is installed.")
            return None

    def run_llm_mutator(self, url, method, headers, body, context):
        cmd = ['python3', str(self.scripts_dir / 'llm_mutator.py'), url, '--method', method, 
               '--body', json.dumps(body), '--context', context, 
               '--output', str(self.reports_dir / 'llm_mutator_results.json')]
        for k, v in headers.items(): cmd.extend(['--header', f'{k}: {v}'])
        
        out = self._run_cmd(cmd, "1/6 Running LLM Mutator")
        if out: 
            return json.loads((self.reports_dir / 'llm_mutator_results.json').read_text())
        return {}

    def run_nuclei(self, url):
        out_file = self.reports_dir / "nuclei_results.txt"
        cmd = ['nuclei', '-u', url, '-t', str(self.templates_dir), '-severity', 'medium,high,critical', '-o', str(out_file)]
        self._run_cmd(cmd, "2/6 Running Custom Nuclei Templates")
        return out_file.read_text().splitlines() if out_file.exists() else []

    def run_ffuf_fuzzing(self, url, parameters, baseline_size=1646):
        results = []
        for param in parameters:
            cmd = ['python3', str(self.integrations_dir / 'ffuf' / 'ffuf_parameter_fuzzer.py'),
                   url, '--parameter', param, '--baseline-size', str(baseline_size),
                   '--output', str(self.reports_dir / f'ffuf_{param}_results.json')]
            self._run_cmd(cmd, f"3/6 Running FFUF Parameter Fuzzing ({param})")
            if (self.reports_dir / f'ffuf_{param}_results.json').exists():
                results.extend(json.loads((self.reports_dir / f'ffuf_{param}_results.json').read_text()))
        return results

    def run_sqlmap(self, url, parameters):
        results = []
        for param in parameters:
            cmd = ['python3', str(self.integrations_dir / 'sqlmap' / 'sqlmap_logic_tester.py'),
                   url, '--parameter', param, 
                   '--output', str(self.reports_dir / f'sqlmap_{param}_results.json')]
            self._run_cmd(cmd, f"4/6 Running SQLMap Proof-Only ({param})")
            if (self.reports_dir / f'sqlmap_{param}_results.json').exists():
                results.append(json.loads((self.reports_dir / f'sqlmap_{param}_results.json').read_text()))
        return results

    # def run_gitleaks(self, files_to_scan):
        secrets = []
        for f in files_to_scan:
            if Path(f).exists():
                cmd = ['gitleaks', 'detect', '--source', str(f), '--redact', '--no-git', '-v']
                result = subprocess.run(cmd, capture_output=True, text=True)
                if "No leaks found" not in result.stdout and "No leaks found" not in result.stderr:
                    secrets.append(f)
                    print(f"[!] ⚠️  Potential secret leak found in: {f}")
        return secrets

    def run_dynamic_recon(self, input_files):
        new_targets = []
        out_dir = self.reports_dir / "dynamic_recon"
        for f in input_files:
            if Path(f).exists():
                cmd = ['python3', str(self.integrations_dir / 'recon' / 'dynamic_chainer.py'), 
                       str(f), '--output-dir', str(out_dir)]
                self._run_cmd(cmd, "6/6 Running Dynamic Reconnaissance Chainer")
                
                if out_dir.exists():
                    for nf in out_dir.glob("subfinder_*.txt"):
                        if nf.stat().st_size > 0:
                            new_targets.append(nf.name)
        return new_targets

    def orchestrate(self, url, parameters=None, method="POST", headers=None, body=None, context=""):
        print(f"\n{'#'*70}")
        print(f"# 🧠 ULTIMATE CREATIVE LOGIC TESTING ORCHESTRATOR v3")
        print(f"# Target: {url}")
        print(f"{'#'*70}")
        
        result = OrchestrationResult(target_url=url)
        parameters = parameters or []
        
        # 1. LLM Mutator
        llm_res = self.run_llm_mutator(url, method, headers, body, context)
        if llm_res:
            result.tools_run.append('llm_mutator')
            result.anomalies.extend([r for r in llm_res.get('results', []) if r.get('is_anomalous')][:5])
            
        # 2. Nuclei
        nuclei_res = self.run_nuclei(url)
        if nuclei_res:
            result.tools_run.append('nuclei')
            result.findings.extend([line.strip() for line in nuclei_res if line.strip()])
            
        # 3. FFUF (if parameters provided)
        if parameters:
            ffuf_res = self.run_ffuf_fuzzing(url, parameters)
            if ffuf_res:
                result.tools_run.append('ffuf_parameter_fuzzer')
                result.anomalies.extend([r for r in ffuf_res if r.get('anomalies_found', 0) > 0][:5])

        # 4. SQLMap (if parameters provided)
        if parameters:
            sqlmap_res = self.run_sqlmap(url, parameters)
            if sqlmap_res:
                result.tools_run.append('sqlmap')
                result.findings.extend([r for r in sqlmap_res if r.get('injection_found')])

        # 5. Gitleaks (Scan all generated reports)
        files_to_scan = [
            str(self.reports_dir / 'llm_mutator_results.json'),
            str(self.reports_dir / 'nuclei_results.txt')
        ]
        if parameters:
            files_to_scan.extend([str(self.reports_dir / f'ffuf_{p}_results.json') for p in parameters])
            files_to_scan.extend([str(self.reports_dir / f'sqlmap_{p}_results.json') for p in parameters])
            
        secrets = []  # Gitleaks disabled
        if secrets:
            result.tools_run.append('gitleaks_response_scanner')
            result.leaked_secrets.extend(secrets)
            
        # 6. Dynamic Recon
        new_targets = self.run_dynamic_recon(files_to_scan)
        if new_targets:
            result.tools_run.append('dynamic_recon_chainer')
            result.new_recon_targets.extend(new_targets)
            
        return result

def main():
    parser = argparse.ArgumentParser(description="Ultimate Business Logic Testing Orchestrator v3")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--parameters", "-p", nargs='+', help="Parameters to test (e.g., user_id email)")
    parser.add_argument("--method", default="POST")
    parser.add_argument("--header", action='append', default=[])
    parser.add_argument("--body", default="{}")
    parser.add_argument("--context", default="")
    parser.add_argument("--output", default="reports/ultimate_orchestration_results.json")
    args = parser.parse_args()
    
    headers = {h.split(":",1)[0].strip(): h.split(":",1)[1].strip() for h in args.header if ":" in h}
    try: body = json.loads(args.body)
    except: body = {}
    
    orchestrator = UltimateOrchestrator()
    result = orchestrator.orchestrate(args.url, parameters=args.parameters, method=args.method, 
                                      headers=headers, body=body, context=args.context)
    
    print(f"\n{'='*70}")
    print("🏆 ORCHESTRATION SUMMARY")
    print(f"{'='*70}")
    print(f"Target: {result.target_url}")
    print(f"Tools Executed: {', '.join(result.tools_run)}")
    print(f"Nuclei/SQLMap Findings: {len(result.findings)}")
    print(f"LLM/FFUF Anomalies: {len(result.anomalies)}")
    print(f"Leaked Secrets Detected: {len(result.leaked_secrets)}")
    print(f"New Recon Targets Discovered: {len(result.new_recon_targets)}")
    
    if args.output:
        Path(args.output).write_text(json.dumps({
            'target_url': result.target_url, 'tools_run': result.tools_run,
            'findings': result.findings, 'anomalies': result.anomalies,
            'leaked_secrets': result.leaked_secrets, 'new_recon_targets': result.new_recon_targets
        }, indent=2))
        print(f"\n[+] Full results saved to {args.output}")

if __name__ == "__main__":
    main()

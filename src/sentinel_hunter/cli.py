import argparse
import sys
import subprocess
from pathlib import Path
from sentinel_hunter.safety.policy import load_profile

def main():
    parser = argparse.ArgumentParser(description="Sentinel Hunter: AI-Native Autonomous Security Logic Hunter")
    parser.add_argument("command", choices=["hunt", "profile"], help="Command to run")
    parser.add_argument("target", nargs="?", help="Target domain or URL")
    parser.add_argument("--profile", default="bug_bounty", help="Safety profile to use")
    parser.add_argument("--output", default="reports/hunt_results.json", help="Output report path")
    
    args = parser.parse_args()
    
    if args.command == "hunt":
        if not args.target:
            print("Error: 'hunt' command requires a target.")
            sys.exit(1)
            
        # 1. Load Safety Profile
        policy = load_profile(args.profile)
        print(f"[*] Initializing Sentinel Hunter v2.0.0")
        print(f"[*] Target: {args.target}")
        print(f"[*] Safety Profile: {policy.profile_name.upper()}")
        print(f"    - Max Concurrent Requests: {policy.max_concurrent_requests}")
        print(f"    - NetNS Isolation: {'ENABLED (Strict)' if policy.enable_netns_isolation else 'DISABLED (Bug Bounty Mode)'}")
        print(f"    - Human Approval Required: {policy.require_approval}")
        
        # 2. Enforce Approval Gating
        if policy.require_approval:
            confirm = input("\n[!] Enterprise profile requires human approval. Proceed with hunt? (y/n): ")
            if confirm.lower() != 'y':
                print("[*] Hunt aborted by operator.")
                sys.exit(0)

        print("\n[+] Launching 6-Phase Autonomous Pipeline...\n")
        
        
        # 3. Execute the v7 Orchestrator with Policy Headers
        orch_path = Path(__file__).parent / "orchestrator" / "adaptive_hunter.py"
        
        # Build header arguments if they exist in the policy
        header_args = []
        if hasattr(policy, 'custom_headers') and policy.custom_headers:
            for key, value in policy.custom_headers.items():
                header_args.extend(["--header", f"{key}: {value}"])

        cmd = ["python3", str(orch_path), args.target, "--output", args.output] + header_args
           
        try:
            subprocess.run(cmd, check=True)
            print(f"\n[+] Hunt complete. Report saved to {args.output}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Orchestrator failed with exit code {e.returncode}")
            sys.exit(1)
if __name__ == "__main__":
    main()

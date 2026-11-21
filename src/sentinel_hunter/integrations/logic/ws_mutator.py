#!/usr/bin/env python3
import asyncio
import json
import argparse
import re
import ollama
import websockets
from pathlib import Path

async def generate_ws_mutations(context, model="qwen3:1.7b"):
    prompt = f"""You are a penetration tester targeting a financial trading WebSocket API (like Deriv).
Context: {context}
Generate 5 malicious JSON payloads to test for business logic flaws. 
Examples: negative stake amounts, extreme leverage, unauthorized contract types, IDOR in transaction IDs, or currency manipulation.
Output ONLY a valid JSON array of objects. No explanation."""
    try:
        client = ollama.Client(host="http://127.0.0.1:11434")
        resp = client.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.7, "num_ctx": 2048, "think": False}
        )
        content = resp["message"]["content"]
        match = re.search(r'\[.*\]', content, re.DOTALL)
        return json.loads(match.group()) if match else []
    except Exception as e:
        print(f"[!] LLM error: {e}")
        return []

async def test_ws_payload(url, payload, token=None):
    try:
        extra_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Origin": "https://app.deriv.com",
            "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits"
        }
        async with websockets.connect(url, ping_interval=None, additional_headers=extra_headers) as ws:
            # If token provided, authorize first
            if token:
                await ws.send(json.dumps({"authorize": token}))
                auth_resp = await asyncio.wait_for(ws.recv(), timeout=3.0)
                if "error" in json.loads(auth_resp):
                    return {"payload": payload, "response": "Auth failed", "is_anomalous": False, "reason": "Invalid token"}
            
            # Send the malicious payload
            await ws.send(json.dumps(payload))
            response = await asyncio.wait_for(ws.recv(), timeout=5.0)
            data = json.loads(response)
            
            # Anomaly detection logic
            is_anomalous = False
            reason = ""
            
            if "error" not in data:
                # If we sent a clearly malicious payload (e.g., negative amount) and got NO error, that's a huge red flag
                if "buy" in payload or "amount" in str(payload).lower() or "price" in str(payload).lower():
                    is_anomalous = True
                    reason = "Malicious payload accepted without error (Potential Logic Flaw)"
            else:
                reason = f"Safely rejected: {data['error'].get('message', 'Unknown error')}"
                
            return {
                "payload": payload,
                "response": data,
                "is_anomalous": is_anomalous,
                "reason": reason
            }
    except asyncio.TimeoutError:
        return {"payload": payload, "response": "Timeout", "is_anomalous": True, "reason": "Server hung (Potential DoS/Logic Flaw)"}
    except Exception as e:
        return {"payload": payload, "response": str(e), "is_anomalous": True, "reason": f"Connection error: {e}"}

async def main():
    parser = argparse.ArgumentParser(description="WebSocket API Logic Mutator")
    parser.add_argument("url", help="WebSocket URL (e.g., wss://ws.derivws.com/websockets/v3?app_id=1089)")
    parser.add_argument("--context", default="Trade buy endpoint", help="Context for LLM payload generation")
    parser.add_argument("--token", help="Optional authentication token (for authorized testing)")
    parser.add_argument("--output", default="reports/ws_mutator_results.json")
    args = parser.parse_args()
    
    print(f"[*] Generating malicious WebSocket payloads for: {args.context}")
    mutations = await generate_ws_mutations(args.context)
    print(f"[+] Generated {len(mutations)} payloads. Testing against {args.url}...\n")
    
    results = []
    for i, payload in enumerate(mutations, 1):
        print(f"[{i}/{len(mutations)}] Testing: {json.dumps(payload)[:60]}...")
        res = await test_ws_payload(args.url, payload, token=args.token)
        results.append(res)
        
        if res["is_anomalous"]:
            print(f"    ⚠️ ANOMALY: {res['reason']}")
        else:
            print(f"    ✓ Safely rejected")
        await asyncio.sleep(0.5) # Rate limiting
            
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps({"target": args.url, "context": args.context, "results": results}, indent=2))
    print(f"\n[+] Results saved to {args.output}")

if __name__ == "__main__":
    asyncio.run(main())

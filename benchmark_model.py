# SPDX-License-Identifier: Apache-2.0
"""Milestone 0 benchmark — qwen3:4b at 4096 context, strict schema."""
import json
import subprocess
import threading
import time
from pathlib import Path
import psutil
from pydantic import BaseModel, ConfigDict, ValidationError
from ollama import chat

MODEL = "qwen3:4b"
N = 20
CTX = 4096
OUT = Path("data/benchmark_qwen3_4b.jsonl")

class SentinelOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    task_type: str
    summary: str
    confidence_hint: str

PROMPT = (
    "Return a JSON object with exactly three fields: "
    "task_type='test', summary='System ready', confidence_hint='high'. "
    "No other fields, no prose."
)

def vram_mib() -> int:
    out = subprocess.check_output([
        "nvidia-smi", "--query-gpu=memory.used",
        "--format=csv,noheader,nounits"
    ]).decode().strip().splitlines()[0]
    return int(out)

peak = {"vram": 0}
stop = threading.Event()

def poll():
    while not stop.is_set():
        try:
            peak["vram"] = max(peak["vram"], vram_mib())
        except Exception:
            pass
        time.sleep(0.2)

threading.Thread(target=poll, daemon=True).start()

ok = 0
rows = []
for i in range(N):
    t0 = time.time()
    try:
        r = chat(
            model=MODEL,
            messages=[{"role": "user", "content": PROMPT}],
            format=SentinelOutput.model_json_schema(),
            options={"temperature": 0, "num_ctx": CTX},
        )
        elapsed = time.time() - t0
        try:
            SentinelOutput.model_validate_json(r.message.content)
            valid, err = True, None
            ok += 1
        except ValidationError as e:
            valid, err = False, str(e).splitlines()[0][:200]
        rows.append({"i": i, "sec": round(elapsed, 2), "valid": valid, "err": err})
        print(f"{i+1:02d}/{N}  {elapsed:5.2f}s  valid={valid}")
    except Exception as e:
        rows.append({"i": i, "sec": None, "valid": False, "err": repr(e)[:200]})
        print(f"{i+1:02d}/{N}  ERROR {e!r}"[:160])

stop.set()

placement = subprocess.check_output(["ollama", "ps"]).decode()
ram = psutil.virtual_memory()

print("\n--- RESULT ---")
print(f"schema-valid: {ok}/{N} ({100*ok/N:.0f}%)")
print(f"peak VRAM:    {peak['vram']} MiB / 4096 MiB")
print(f"RAM used:     {ram.used/1024**3:.2f} GB / {ram.total/1024**3:.2f} GB")
print("\nollama ps:\n" + placement)
OUT.write_text("\n".join(json.dumps(r) for r in rows))
print(f"raw results -> {OUT}")

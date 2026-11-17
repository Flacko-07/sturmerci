# Local LLM and Triage

The current primary integration is Ollama through `src/sentinel/llm/`, with
Qwen configured by the operator. Triage and query construction are implemented
under `src/sentinel/triage/`; model runs are recorded by the audit subsystem.
Model availability, model identity, endpoint configuration, and local resource
requirements depend on the operator's Ollama installation.

Treat model output as untrusted analysis. It can be inaccurate, incomplete, or
prompt-influenced by evidence. Do not allow it to authorize scans, modify
scope, or automatically transition findings. Human review is required.
Live Ollama triage is environment-dependent and has not been included in this
documentation task's validation.

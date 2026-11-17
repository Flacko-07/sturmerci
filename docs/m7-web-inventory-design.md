# M7.1 — Web inventory adapter design (httpx)

**Status:** Implementing
**Date:** 2026-11-14
**Milestone:** M7.1
**Scope:** Passive HTTP inventory of an approved hostname at an approved
port with an approved method.

## 1. The L7 gap this milestone accepts

The nft ruleset operates at IP / port / protocol. It cannot inspect
HTTPS request method, path, Host header, or body. Any of those controls
would require a proxy terminating TLS with a trusted CA installed in the
sandbox.

Until that proxy exists, we do not pretend to enforce L7 scope. The
`approvals.allowed_path_profile` field was added at M2A but has never
been enforced. **M7.1 makes it enforced by refusing anything other than
`"default"`.** Attempting to use a path-restricted approval results in
`SandboxDenied` before any subprocess spawns.

## 2. What httpx in M7.1 does

- One target hostname, one port, one HTTP method (GET or HEAD).
- Path is `/` (inventory only). No `-path`, no `-paths`.
- No redirects. No headers beyond User-Agent (and that's fixed by the
  adapter, not user-supplied). No body. No proxy. No auth.
- Output: httpx `-json` JSONL; one line per probed target.
- Writes `candidate_assets` with `asset_type='web_endpoint'` and
  `discovery_source='httpx:inventory'`.

What inventory provides the operator:
- HTTP status code of `GET /`
- Server / tech header
- TLS certificate CN, SAN entries, issuer, expiry
- Title and content-length

These are the observations that drive M7.2 target selection, not
vulnerability findings themselves.

## 3. Explicitly refused

The adapter builds argv from scratch and refuses any flag matching
`FORBIDDEN_FLAGS` (defense in depth: even if a future edit adds a
user-input path through the argv, the runner fails closed):

| Refused | Why |
|---|---|
| `-path`, `-paths` | Path scope requires L7 enforcement |
| `-follow-redirects`, `-fr` | Redirect target escapes approval |
| `-H`, `-header` | Arbitrary headers (auth, Host override) |
| `-body` | Non-GET body |
| `-X`, `-method` | Method override |
| `-x`, `-http-proxy`, `-proxy` | Egress bypass |
| `-auth` | Auth injection |
| `-websocket`, `-ws` | Protocol upgrade |
| `-dc`, `-dashboard` | External dashboard = provider contact |
| `-sr`, `-store-response` | Filesystem writes outside artifact dir |
| `-screenshot` | Chromedriver side channel |

Update checks disabled via `-duc` (no vendor telemetry).

## 4. Approval requirements

- `approvals.canonical_hostnames` includes the target hostname
- `approvals.allowed_ports` includes the port
- `approvals.allowed_protocols` includes `https` (or `http`)
- `approvals.allowed_http_methods` includes `GET` or `HEAD`
- `approvals.allowed_path_profile == "default"` (M7.1 only)
- `approvals.port_scanning_authorized` is NOT checked (httpx does not
  target the IP's other tenants; the Host header identifies the
  approved hostname — see §6)

## 5. What M7.1 does NOT deliver

- Path-restricted scopes (M7.2, requires proxy)
- Method != GET/HEAD (M7.2, requires proxy)
- Following redirects with per-hop reauth (M7.2)
- Header injection / auth (M7.2)
- Body scanning (POST endpoints, M7.2)
- Nuclei template checks (M7.3, requires template intake process)
- ZAP active scan (M7.4, requires proxy + active-scan profiles)
- Vulnerability correlation (M8)

## 6. Why httpx doesn't need port_scanning_authorized

The reviewer distinguished httpx from Nmap: port scanning enumerates
every port on the IP and may reach unrelated services on shared
infrastructure. HTTP inventory sends a request with `Host: <approved
hostname>` on an approved port. If the target is behind a shared reverse
proxy, the Host header routes the request to the approved backend. The
practical concern is whether the program permits the operator to make
requests to that hostname — which the approval already authorizes via
`canonical_hostnames` + `allowed_ports` + `allowed_http_methods`.

If evidence later shows httpx traffic that bypassed hostname routing
(e.g. SNI-less requests to `Host: <cdn-ip>`), this decision changes.

## 7. Tests planned

- M7.1-a: `allowed_path_profile != "default"` → `SandboxDenied` (in
  SandboxRunner; applies to all adapters, not just httpx)
- M7.1-b: httpx FORBIDDEN_FLAGS rejection (parametrized per flag)
- M7.1-c: argv construction (exact flags, no `-path`, no `-H`)
- M7.1-d: JSONL parsing (multiple lines, malformed lines, empty)
- M7.1-e: integration — fake httpx emits JSONL, adapter writes
  candidate_assets with `asset_type='web_endpoint'`
- M7.1-f: integration — approval with `allowed_path_profile="restricted"`
  → refusal (cross-check between a + e)

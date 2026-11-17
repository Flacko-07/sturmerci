# SPDX-License-Identifier: Apache-2.0
"""Per-run TLS-terminating proxy for L7 inspection (M7.2).

Accepts HTTP CONNECT from the sandboxed tool, terminates TLS with a leaf
signed by the run's ephemeral CA, opens upstream TLS to the real target
(verifying against the real CA bundle), then parses the HTTP request and
consults a filter callback before forwarding.

Scope (M7.2a):
- CONNECT tunnels only (HTTPS). Plain HTTP proxy is not supported in v1.
- One request per connection. No keep-alive, no pipelining.
- Content-Length and Connection: close both handled; chunked responses
  are forwarded transparently (we don't rewrite the body).
- Filter defaults to pass-through in this chunk. M7.2b supplies a real
  filter that calls the gatekeeper.

Not in scope:
- WebSocket upgrades (proxy refuses CONNECT port not in approved set).
- HTTP/2 (upstream may negotiate h2; we forward ALPN-negotiated bytes as
  produced by ssl module — no h2 parsing, so filter sees only HTTP/1.1).
- gRPC / streaming bodies beyond what Content-Length declares.

Threat model note: the CA key lives in the same 0700 directory as the
proxy process. Anyone with read access to that directory can sign certs
trusted by the sandbox. This is no worse than the sandbox itself being
compromised. For the scanner not to trust a rogue CA, the CA is rotated
per run and the tool's SSL_CERT_FILE is set to that run's CA only.
"""
from __future__ import annotations

import select
import socket
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from sentinel.l7.ca import CAError, L7CA


# Upper bound on how much of the HTTP request we buffer before deciding.
# Real requests are small (headers + small body); anything larger than
# this is refused rather than forwarded. 64 KiB is generous — typical
# inventory GET is under 2 KiB.
MAX_REQUEST_BYTES = 64 * 1024

# CONNECT line + head read timeout in seconds.
CONNECT_TIMEOUT = 5.0
# After CONNECT, per-read timeout on the terminated TLS channel.
REQUEST_READ_TIMEOUT = 30.0
# M7-08: connection-level limits.
MAX_CONCURRENT_CONNECTIONS = 16
# Total bytes relayed per connection, across both directions. Response
# bodies larger than this are truncated and the connection closed.
MAX_RELAY_BYTES = 10 * 1024 * 1024
# Wall-clock deadline per connection (CONNECT through close).
MAX_CONNECTION_DURATION = 120.0


class ProxyError(Exception):
    """Proxy startup, protocol, or forwarding failure."""


class RequestBodyRefused(ProxyError):
    """Client sent a request with a body; proxy refuses to forward
    uninspected bodies (M7-05)."""


@dataclass(frozen=True, slots=True)
class ProxyRequest:
    method: str
    path: str
    http_version: str
    host: str
    port: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


@dataclass(frozen=True, slots=True)
class ProxyDecision:
    allow: bool
    reason: str


class RequestFilter(Protocol):
    """Decides whether to forward a parsed request."""
    def __call__(self, req: ProxyRequest) -> ProxyDecision: ...


def pass_through_filter(req: ProxyRequest) -> ProxyDecision:
    """Default filter: allow everything. Used in M7.2a before gatekeeper
    integration lands in M7.2b."""
    return ProxyDecision(allow=True, reason="pass_through")


class TLSProxy:
    """CONNECT tunnel proxy that terminates and re-encrypts TLS."""

    def __init__(
        self,
        *,
        ca: L7CA,
        request_filter: RequestFilter = pass_through_filter,
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
        upstream_ca_bundle: Path | str | None = None,
        allowed_connect_hosts: set[str] | None = None,
        pinned_upstreams: dict[str, list[str]] | None = None,
        max_concurrent_connections: int = MAX_CONCURRENT_CONNECTIONS,
        max_relay_bytes: int = MAX_RELAY_BYTES,
        max_connection_duration: float = MAX_CONNECTION_DURATION,
    ):
        self._ca = ca
        self._filter = request_filter
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._upstream_ca_bundle = (
            Path(upstream_ca_bundle) if upstream_ca_bundle else None
        )
        # If set (not None), only hostnames in this set may be CONNECTed
        # to. Lowercased, trailing-dot-stripped. Empty set = refuse all.
        # None = no hostname restriction (unit tests, direct use).
        self._allowed_connect_hosts = (
            {h.lower().rstrip(".") for h in allowed_connect_hosts}
            if allowed_connect_hosts is not None else None
        )
        # Pinned upstream IPs per hostname. When set (dict not None),
        # the proxy resolves nothing itself -- it uses only the IPs
        # provided here. Closes the DNS-rebinding vector: the gatekeeper
        # saw these IPs during resolution; the proxy connects to the same
        # IPs. If a hostname has no entry, CONNECT is refused.
        self._pinned_upstreams = (
            {h.lower().rstrip("."): list(ips) for h, ips in pinned_upstreams.items()}
            if pinned_upstreams is not None else None
        )
        self._listen_sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopped = threading.Event()
        self._active_connections = 0
        self._active_lock = threading.Lock()
        self._max_concurrent = max_concurrent_connections
        self._max_relay_bytes = max_relay_bytes
        self._max_duration = max_connection_duration

    @property
    def listen_port(self) -> int:
        return self._listen_port

    def start(self) -> None:
        if self._listen_sock is not None:
            raise ProxyError("proxy already started")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self._listen_host, self._listen_port))
        sock.listen(16)
        self._listen_port = sock.getsockname()[1]
        sock.settimeout(0.5)  # allow clean shutdown
        self._listen_sock = sock
        self._stopped.clear()
        self._thread = threading.Thread(
            target=self._accept_loop, daemon=True, name="tlsproxy-accept",
        )
        self._thread.start()

    def stop(self) -> None:
        self._stopped.set()
        if self._listen_sock is not None:
            try:
                self._listen_sock.close()
            except OSError:
                pass
            self._listen_sock = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def _accept_loop(self) -> None:
        while not self._stopped.is_set():
            try:
                client, addr = self._listen_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(
                target=self._handle_client, args=(client, addr),
                daemon=True, name="tlsproxy-client",
            )
            t.start()


    def _handle_client(self, client: socket.socket, addr) -> None:
        with self._active_lock:
            if self._active_connections >= self._max_concurrent:
                _send_simple(
                    client,
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Length: 0\r\n"
                    b"Connection: close\r\n\r\n",
                )
                try:
                    client.close()
                except OSError:
                    pass
                return
            self._active_connections += 1
        try:
            self._handle_client_inner(client, addr)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass
        except Exception as e:
            import sys
            print(f"[tlsproxy] handler error from {addr}: {e}",
                  file=sys.stderr, flush=True)
        finally:
            try:
                client.close()
            except OSError:
                pass
            with self._active_lock:
                self._active_connections -= 1

    def _handle_client_inner(self, client: socket.socket, addr) -> None:
        client.settimeout(CONNECT_TIMEOUT)
        # Read the WHOLE CONNECT request (headers + blank line) in one
        # call. Clients routinely send it in a single TCP segment; reading
        # only up to the first CRLF would leave the trailing blank line
        # buffered and any subsequent read would block until timeout.
        try:
            raw_connect = _read_until(client, b"\r\n\r\n", MAX_REQUEST_BYTES)
        except (socket.timeout, OSError, ProxyError):
            return

        first_line = raw_connect.split(b"\r\n", 1)[0]
        if not first_line.upper().startswith(b"CONNECT "):
            _send_simple(client, b"HTTP/1.1 405 Method Not Allowed\r\n"
                                 b"Content-Length: 0\r\n"
                                 b"Connection: close\r\n\r\n")
            return

        rest = first_line[len(b"CONNECT "):].split(b" ", 1)[0]
        try:
            host_b, port_b = rest.rsplit(b":", 1)
            hostname = host_b.decode("ascii").lower().strip("[]")
            port = int(port_b.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            _send_simple(client, b"HTTP/1.1 400 Bad Request\r\n"
                                 b"Content-Length: 0\r\n"
                                 b"Connection: close\r\n\r\n")
            return

        if not hostname or not (1 <= port <= 65535):
            _send_simple(client, b"HTTP/1.1 400 Bad Request\r\n"
                                 b"Content-Length: 0\r\n"
                                 b"Connection: close\r\n\r\n")
            return

        # Host allowlist (M7.2b). Refuses CONNECT to unapproved SNI/host
        # before any cert signing or upstream connect. Tools behind a
        # nft rule could still attempt a direct connection bypassing the
        # proxy, but the kernel denies it because the target IP is only
        # approved when use_tls_proxy=False.
        if self._allowed_connect_hosts is not None:
            normalized = hostname.lower().rstrip(".")
            if normalized not in self._allowed_connect_hosts:
                _send_simple(client, b"HTTP/1.1 403 Forbidden\r\n"
                                     b"Content-Length: 0\r\n"
                                     b"Connection: close\r\n\r\n")
                return

        # Sign a leaf for the requested hostname.
        try:
            leaf = self._ca.sign_leaf(hostname)
        except CAError as e:
            _send_simple(client, b"HTTP/1.1 400 Bad Request\r\n"
                                 b"Content-Length: 0\r\n"
                                 b"Connection: close\r\n\r\n")
            return

        # 200 Connection Established, then switch to TLS.
        try:
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except OSError:
            return

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(str(leaf.cert_path), str(leaf.key_path))
        server_ctx.set_alpn_protocols(["http/1.1"])
        client.settimeout(REQUEST_READ_TIMEOUT)
        try:
            tls_client = server_ctx.wrap_socket(client, server_side=True)
        except (ssl.SSLError, OSError):
            return

        # Read the inner HTTP request (headers only; body follows inline
        # for Content-Length bodies but we read the headers separately so
        # the filter sees method+path before any body is forwarded).
        try:
            head = _read_until(tls_client, b"\r\n\r\n", MAX_REQUEST_BYTES)
        except (socket.timeout, OSError, ssl.SSLError):
            try:
                tls_client.close()
            except OSError:
                pass
            return

        # M7-05: refuse bodies before parsing (cheaper + clearer error).
        try:
            _assert_no_request_body(head)
        except RequestBodyRefused:
            try:
                tls_client.sendall(
                    b"HTTP/1.1 413 Payload Too Large\r\n"
                    b"Content-Length: 0\r\n"
                    b"Connection: close\r\n\r\n"
                )
            except OSError:
                pass
            try:
                tls_client.close()
            except OSError:
                pass
            return

        try:
            req = _parse_request_head(head, hostname, port)
        except ProxyError:
            try:
                tls_client.close()
            except OSError:
                pass
            return

        # M7-P0-C: inner Host header must match the CONNECT authority.
        # A mismatch lets the filter authorize hostname A while upstream
        # receives Host: B on shared infrastructure.
        inner_host = ""
        for hname, hvalue in req.headers:
            if hname.lower() == "host":
                if inner_host:
                    # Duplicate Host headers -> reject
                    try:
                        tls_client.sendall(
                            b"HTTP/1.1 400 Bad Request\r\n"
                            b"Content-Length: 0\r\n"
                            b"Connection: close\r\n\r\n"
                        )
                    except OSError:
                        pass
                    try:
                        tls_client.close()
                    except OSError:
                        pass
                    return
                inner_host = hvalue.strip().lower()
        if inner_host:
            # (batch C.2) Parse hostname AND port. Prior code stripped
            # :port before comparison, which let CONNECT example.com:443
            # with Host: example.com:8443 through — upstream parses a
            # different authority than the tunneled connection.
            try:
                inner_hostname, inner_port = _parse_host_header(inner_host)
            except ValueError:
                # Malformed Host authority — 400 Bad Request
                try:
                    tls_client.sendall(
                        b"HTTP/1.1 400 Bad Request\r\n"
                        b"Content-Length: 0\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                except OSError:
                    pass
                try:
                    tls_client.close()
                except OSError:
                    pass
                return

            if inner_hostname != hostname.lower():
                try:
                    tls_client.sendall(
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Content-Length: 0\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                except OSError:
                    pass
                try:
                    tls_client.close()
                except OSError:
                    pass
                return

            # (batch C.2 corrected) Port comparison — only when Host
            # explicitly declares a port. If Host omits the port, the
            # client did not claim one: standard HTTPS semantics treat
            # `Host: example.com` inside a CONNECT tunnel as "same
            # authority as the tunnel." Real curl to :443 sends
            # `Host: example.com` (no port); refusing that would break
            # every legitimate client.
            #
            # The actual M7-P0-C bypass is a MISMATCHED explicit port:
            # CONNECT example.com:443 + Host: example.com:8443 lets the
            # filter authorize :443 while upstream receives a request
            # claiming :8443. Explicit mismatch → refuse. No explicit
            # port → trust CONNECT authority.
            if inner_port is not None and inner_port != port:
                try:
                    tls_client.sendall(
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Content-Length: 0\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                except OSError:
                    pass
                try:
                    tls_client.close()
                except OSError:
                    pass
                return

        decision = self._filter(req)

        if not decision.allow:
            body = f"denied: {decision.reason}\n".encode()
            try:
                tls_client.sendall(
                    b"HTTP/1.1 403 Forbidden\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
            except OSError:
                pass
            try:
                tls_client.close()
            except OSError:
                pass
            return

        # Forward: connect upstream, wrap in TLS, replay the head we read,
        # then relay bytes bidirectionally until either side closes.
        # M7-P0-B: if pinned_upstreams is set, we connect to a pinned IP
        # from the gatekeeper's resolution, never re-resolving here.
        if self._pinned_upstreams is not None:
            normalized = hostname.lower().rstrip(".")
            pinned_ips = self._pinned_upstreams.get(normalized)
            if not pinned_ips:
                try:
                    tls_client.sendall(
                        b"HTTP/1.1 403 Forbidden\r\n"
                        b"Content-Length: 0\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                except OSError:
                    pass
                try:
                    tls_client.close()
                except OSError:
                    pass
                return
            connect_ip = pinned_ips[0]
        else:
            connect_ip = hostname

        try:
            upstream_raw = socket.create_connection(
                (connect_ip, port), timeout=REQUEST_READ_TIMEOUT,
            )
        except OSError:
            try:
                tls_client.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\n"
                    b"Content-Length: 0\r\n"
                    b"Connection: close\r\n\r\n"
                )
            except OSError:
                pass
            try:
                tls_client.close()
            except OSError:
                pass
            return

        try:
            if self._upstream_ca_bundle:
                upstream_ctx = ssl.create_default_context(
                    cafile=str(self._upstream_ca_bundle),
                )
            else:
                upstream_ctx = ssl.create_default_context()
            upstream_ctx.set_alpn_protocols(["http/1.1"])
            try:
                tls_upstream = upstream_ctx.wrap_socket(
                    upstream_raw, server_hostname=hostname,
                )
            except (ssl.SSLError, OSError):
                upstream_raw.close()
                try:
                    tls_client.sendall(
                        b"HTTP/1.1 502 Bad Gateway\r\n"
                        b"Content-Length: 0\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                except OSError:
                    pass
                try:
                    tls_client.close()
                except OSError:
                    pass
                return

            try:
                tls_upstream.sendall(head)
                _relay_bidir(
                    tls_client, tls_upstream,
                    max_bytes=self._max_relay_bytes,
                    max_duration=self._max_duration,
                )
            finally:
                for s in (tls_upstream, upstream_raw):
                    try:
                        s.close()
                    except OSError:
                        pass
                try:
                    tls_client.close()
                except OSError:
                    pass
        except OSError:
            try:
                upstream_raw.close()
            except OSError:
                pass
            try:
                tls_client.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Small helpers kept module-level for easy unit testing
# ---------------------------------------------------------------------------

def _read_until(sock: socket.socket, delim: bytes, max_bytes: int) -> bytes:
    """Read from sock until delim is found. Raises ProxyError if over limit."""
    buf = b""
    while delim not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ProxyError("connection closed before delimiter")
        buf += chunk
        if len(buf) > max_bytes:
            raise ProxyError(f"read {len(buf)} > max_bytes {max_bytes}")
    return buf


def _send_simple(sock: socket.socket, data: bytes) -> None:
    try:
        sock.sendall(data)
    except OSError:
        pass


def _assert_no_request_body(head: bytes) -> None:
    """Refuse requests that declare a body (M7-05).

    A GET/HEAD with Content-Length > 0 or Transfer-Encoding: chunked
    is abnormal for inventory probing and cannot be safely forwarded
    without body inspection.
    """
    text = head.decode("iso-8859-1", errors="replace")
    for line in text.split("\r\n")[1:]:
        if not line:
            break
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        lname = name.strip().lower()
        lvalue = value.strip().lower()
        if lname == "content-length":
            try:
                n = int(value.strip())
            except ValueError as e:
                raise RequestBodyRefused(
                    f"invalid Content-Length: {value.strip()!r}"
                ) from e
            if n > 0:
                raise RequestBodyRefused(
                    f"request body of {n} bytes not permitted"
                )
        if lname == "transfer-encoding" and "chunked" in lvalue:
            raise RequestBodyRefused(
                "chunked request body not permitted"
            )


def _parse_host_header(host_value: str) -> tuple[str, int | None]:
    """Parse a Host header value into (hostname, port_or_None).

    Handles IPv4, IPv6 (``[::1]`` or ``[::1]:443``), and plain DNS forms.
    Returns (hostname_lowercase, explicit_port_or_None). Raises
    ValueError on malformed input — the caller converts that to a 400.

    (batch C.2) Extracted so the port-comparison logic in
    ``_handle_client_inner`` can be unit-tested without a live TLS
    handshake. Prior code stripped ``:port`` before comparison, which
    let ``CONNECT example.com:443`` / ``Host: example.com:8443`` through.
    """
    host = host_value.strip().lower()
    if not host:
        raise ValueError("empty Host header")

    if host.startswith("["):
        end = host.find("]")
        if end < 0:
            raise ValueError(f"unterminated IPv6 bracket: {host!r}")
        hostname = host[1:end]
        if not hostname:
            raise ValueError("empty IPv6 hostname")
        rest = host[end + 1:]
        if not rest:
            return hostname, None
        if not rest.startswith(":"):
            raise ValueError(f"garbage after IPv6 bracket: {host!r}")
        port_str = rest[1:]
        try:
            port = int(port_str)
        except ValueError as e:
            raise ValueError(f"non-numeric IPv6 port: {port_str!r}") from e
        if not (1 <= port <= 65535):
            raise ValueError(f"port out of range: {port}")
        return hostname, port

    if ":" in host:
        host_part, port_part = host.rsplit(":", 1)
        if not host_part:
            raise ValueError(f"empty hostname: {host!r}")
        try:
            port = int(port_part)
        except ValueError as e:
            raise ValueError(f"non-numeric port: {port_part!r}") from e
        if not (1 <= port <= 65535):
            raise ValueError(f"port out of range: {port}")
        return host_part, port

    return host, None


def _parse_request_head(
    head: bytes, hostname: str, port: int,
) -> ProxyRequest:
    """Parse an HTTP/1.1 request head (headers only, no body)."""
    try:
        text = head.decode("iso-8859-1")
    except UnicodeDecodeError as e:
        raise ProxyError(f"undecodable request head: {e}") from e
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        raise ProxyError("empty request line")
    parts = lines[0].split(" ")
    if len(parts) != 3:
        raise ProxyError(f"malformed request line: {lines[0]!r}")
    method, path, http_version = parts
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            break
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))
    return ProxyRequest(
        method=method,
        path=path,
        http_version=http_version,
        host=hostname,
        port=port,
        headers=tuple(headers),
        body=b"",  # body handled inline by relay; not inspected in M7.2a
    )


def _relay_bidir(
    a: socket.socket, b: socket.socket, *,
    max_bytes: int = MAX_RELAY_BYTES,
    max_duration: float = MAX_CONNECTION_DURATION,
) -> None:
    """Relay bytes in both directions until either side closes.

    M7-08 limits enforced:
      - Total bytes in both directions capped at max_bytes.
      - Wall-clock duration capped at max_duration.

    TLS gotcha: select() on an SSLSocket's underlying fd does NOT report
    data already decrypted into the SSL object's buffer. If we send a
    request and OpenSSL decrypts the response before we call select(),
    select() blocks forever while recv() would return instantly. We
    therefore drain ``pending()`` before every select() call.
    """
    try:
        a.setblocking(False)
        b.setblocking(False)
    except OSError:
        return
    sockets = [a, b]
    import time as _t
    started = _t.monotonic()
    total = 0
    try:
        while True:
            if _t.monotonic() - started > max_duration:
                return
            # Drain SSL-buffered plaintext first — select() cannot see it.
            progressed = False
            for sock in sockets:
                pending = getattr(sock, "pending", None)
                if pending is not None:
                    n = pending()
                    while n > 0:
                        try:
                            data = sock.recv(n)
                        except ssl.SSLWantReadError:
                            break
                        except (ConnectionResetError, OSError):
                            return
                        if not data:
                            return
                        total += len(data)
                        if total > max_bytes:
                            return
                        other = b if sock is a else a
                        try:
                            other.sendall(data)
                        except ssl.SSLWantWriteError:
                            break
                        except OSError:
                            return
                        progressed = True
                        n = pending()
            if progressed:
                continue

            try:
                r, _, x = select.select(sockets, [], sockets, 30.0)
            except (OSError, ValueError):
                return
            if x:
                return
            if not r:
                return
            for sock in r:
                other = b if sock is a else a
                try:
                    data = sock.recv(65536)
                except ssl.SSLWantReadError:
                    # Should not happen with select() ready, but be safe
                    continue
                except (ConnectionResetError, OSError):
                    return
                if not data:
                    return
                total += len(data)
                if total > max_bytes:
                    return
                try:
                    other.sendall(data)
                except ssl.SSLWantWriteError:
                    # Backpressure; retry via pending() path on next loop.
                    # Data is still in ``data`` — we lose it here, but this
                    # only fires under extreme backpressure we don't hit.
                    return
                except OSError:
                    return
    finally:
        for s in (a, b):
            try:
                s.setblocking(True)
            except OSError:
                pass

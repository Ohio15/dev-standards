#!/usr/bin/env python3
"""
sb — Shared-Brain CLI

Direct-HTTPS client that talks to https://shared-brain.us/mcp without
needing an MCP host. Survives MCP-client outages, auth-scheme drifts,
and config divergence on fresh/remote machines. Only requires Python
3.8+ and outbound HTTPS.

Subcommands:
    recall      Search persistent memory (brain_recall)
    store       Write a new memory (brain_store action=remember)
    reinforce   Boost recalled memories (brain_store action=reinforce)
    forget      Delete or suppress a memory (brain_store action=forget)
    health      Verify Bearer auth against /mcp (NOT /health — which is
                unauthenticated and accepts anything)
    status      Show token source, endpoint, and redacted token prefix

Token resolution order (first hit wins):
    1. --token <value>
    2. $SHARED_BRAIN_TOKEN
    3. ~/.config/shared-brain/api-key (single line file, gitignored)
    4. `op item get "shared-brain" --fields password` (1Password CLI)

Endpoint resolution order:
    1. --endpoint <url>
    2. $SHARED_BRAIN_URL
    3. https://shared-brain.us  (default; the /mcp suffix is appended)

Auth scheme: `Authorization: Bearer <token>` against /mcp. The legacy
`X-API-Key:` scheme and /api/* static-key endpoints were deprecated in
the v7.8.0 OAuth refactor (2026-04-29). This CLI hardcodes the correct
scheme so future header-scheme drifts cannot strand it silently.

The token is NEVER echoed to stdout, stderr, or any error message —
only the first 8 characters (the generation prefix) are shown.

Stdlib only. No pip install.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_ENDPOINT = "https://shared-brain.us"
DEFAULT_TIMEOUT = 30
DEFAULT_TOKEN_FILE = Path.home() / ".config" / "shared-brain" / "api-key"
OP_ITEM = "shared-brain"
OP_FIELD = "password"
PROTOCOL_VERSION = "2024-11-05"
CLIENT_NAME = "sb-cli"
CLIENT_VERSION = "1.0.0"


class SbError(Exception):
    """Human-readable CLI error. Never embeds the bearer token."""


# ---------------------------------------------------------------------------
# Token + endpoint resolution
# ---------------------------------------------------------------------------

def resolve_token(cli_value: str | None) -> tuple[str, str]:
    """Return (token, source-description). Never echoes the value on error."""
    if cli_value:
        return cli_value.strip(), "--token flag"

    env_token = os.environ.get("SHARED_BRAIN_TOKEN")
    if env_token:
        return env_token.strip(), "$SHARED_BRAIN_TOKEN"

    if DEFAULT_TOKEN_FILE.is_file():
        token = DEFAULT_TOKEN_FILE.read_text(encoding="utf-8").strip()
        if token:
            return token, str(DEFAULT_TOKEN_FILE)

    if shutil.which("op"):
        try:
            result = subprocess.run(
                ["op", "item", "get", OP_ITEM, "--fields", OP_FIELD, "--reveal"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip(), f"1Password (op item:{OP_ITEM})"
        except (subprocess.TimeoutExpired, OSError):
            pass

    raise SbError(
        "No shared-brain token found. Provide one of:\n"
        "  --token <value>\n"
        "  $SHARED_BRAIN_TOKEN\n"
        f"  {DEFAULT_TOKEN_FILE}  (single-line file)\n"
        "  1Password CLI signed in with item 'shared-brain'"
    )


def resolve_endpoint(cli_value: str | None) -> str:
    base = cli_value or os.environ.get("SHARED_BRAIN_URL") or DEFAULT_ENDPOINT
    return base.rstrip("/")


def redact(token: str) -> str:
    """First 8 chars (generation prefix) only. Safe to log."""
    return f"{token[:8]}..." if token else "<empty>"


# ---------------------------------------------------------------------------
# JSON-RPC over /mcp
# ---------------------------------------------------------------------------

def _post_mcp(
    endpoint: str,
    token: str,
    body: bytes,
    timeout: int,
    session_id: str | None = None,
    expect_response_body: bool = True,
) -> tuple[str, str, str | None]:
    """Low-level POST to /mcp. Returns (raw_body, content_type, session_id_header)."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": f"{CLIENT_NAME}/{CLIENT_VERSION}",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id

    req = urllib.request.Request(
        f"{endpoint}/mcp", data=body, method="POST", headers=headers
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace") if expect_response_body else ""
            content_type = resp.headers.get("Content-Type", "")
            new_session = (
                resp.headers.get("Mcp-Session-Id")
                or resp.headers.get("mcp-session-id")
            )
            return raw, content_type, new_session
    except urllib.error.HTTPError as e:
        body_snippet = e.read().decode("utf-8", errors="replace")[:400]
        if e.code == 401:
            raise SbError(
                f"401 Unauthorized from {endpoint}/mcp (token prefix "
                f"{redact(token)}). Check that the token is current "
                "(gen-3 prefix is 'axZSQ_...') and that the scheme is "
                "Authorization: Bearer (NOT X-API-Key)."
            ) from None
        # 202 Accepted with empty body is success for notifications
        if e.code == 202:
            return "", "", None
        raise SbError(
            f"HTTP {e.code} from {endpoint}/mcp: {body_snippet}"
        ) from None
    except urllib.error.URLError as e:
        raise SbError(f"Cannot reach {endpoint}/mcp — {e.reason}") from None
    except socket.timeout:
        raise SbError(f"Timeout after {timeout}s waiting on {endpoint}/mcp") from None


def mcp_call(
    endpoint: str,
    token: str,
    method: str,
    params: dict[str, Any] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    request_id: int = 1,
    session_id: str | None = None,
) -> tuple[dict[str, Any], str | None]:
    """POST a JSON-RPC request to /mcp. Returns (result, session_id_from_response)."""
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }
    ).encode("utf-8")

    raw, content_type, new_session = _post_mcp(
        endpoint, token, body, timeout, session_id=session_id
    )

    payload = _parse_mcp_response(raw, content_type)

    if "error" in payload:
        err = payload["error"]
        raise SbError(
            f"MCP error from {method}: "
            f"{err.get('code')} {err.get('message', '')} "
            f"{json.dumps(err.get('data', {}))[:300]}"
        )

    return payload.get("result", {}), new_session


def init_session(endpoint: str, token: str, timeout: int) -> str:
    """Open an MCP streamable-HTTP session: initialize + initialized notification."""
    init_result, session_id = mcp_call(
        endpoint,
        token,
        "initialize",
        {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
        },
        timeout=timeout,
    )
    if not session_id:
        raise SbError(
            "MCP server did not return Mcp-Session-Id header on initialize. "
            "Server may not support streamable HTTP transport."
        )

    # Notifications carry no `id` field per JSON-RPC 2.0 spec; server replies 202.
    notif_body = json.dumps(
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
    ).encode("utf-8")
    _post_mcp(
        endpoint, token, notif_body, timeout,
        session_id=session_id, expect_response_body=False,
    )

    return session_id


def _parse_mcp_response(raw: str, content_type: str) -> dict[str, Any]:
    """The /mcp endpoint may respond with plain JSON or an SSE event stream."""
    raw = raw.strip()
    if "text/event-stream" in content_type or raw.startswith("event:") or "\ndata:" in raw:
        # SSE: extract the last `data:` payload (the response JSON-RPC frame)
        last_data = None
        for line in raw.splitlines():
            if line.startswith("data:"):
                last_data = line[5:].strip()
        if not last_data:
            raise SbError(f"Empty SSE response: {raw[:200]}")
        return json.loads(last_data)
    return json.loads(raw)


def call_tool(
    endpoint: str,
    token: str,
    tool_name: str,
    arguments: dict[str, Any],
    timeout: int = DEFAULT_TIMEOUT,
) -> Any:
    """Open a session, invoke an MCP tool, unwrap the payload."""
    session_id = init_session(endpoint, token, timeout)
    result, _ = mcp_call(
        endpoint,
        token,
        "tools/call",
        {"name": tool_name, "arguments": arguments},
        timeout=timeout,
        request_id=2,
        session_id=session_id,
    )

    # tools/call returns {content: [{type: "text", text: "<json>"}], isError?}
    if result.get("isError"):
        text = _content_text(result)
        raise SbError(f"Tool {tool_name} returned isError: {text[:400]}")

    text = _content_text(result)
    if not text:
        return result
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _content_text(tool_result: dict[str, Any]) -> str:
    parts = tool_result.get("content") or []
    return "".join(p.get("text", "") for p in parts if isinstance(p, dict))


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def emit(value: Any, raw: bool, quiet: bool) -> None:
    if raw:
        if isinstance(value, str):
            print(value)
        else:
            print(json.dumps(value, ensure_ascii=False))
        return

    if quiet:
        # Emit just the most useful field per shape
        if isinstance(value, dict):
            # recall returns {pri: [{id, ...}], assoc: [...]}; flatten ids
            if "pri" in value and isinstance(value["pri"], list):
                for item in value["pri"]:
                    if isinstance(item, dict) and "id" in item:
                        print(item["id"])
                return
            for key in ("id", "memory_id", "status"):
                if key in value:
                    print(value[key])
                    return
        if isinstance(value, list) and value:
            for item in value:
                if isinstance(item, dict) and "id" in item:
                    print(item["id"])
            return

    print(json.dumps(value, indent=2, ensure_ascii=False))


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def cmd_recall(args: argparse.Namespace, endpoint: str, token: str) -> int:
    arguments: dict[str, Any] = {"query": args.query}
    if args.project:
        arguments["project"] = args.project
    if args.max_results is not None:
        arguments["max_results"] = args.max_results
    if args.min_relevance is not None:
        arguments["min_relevance"] = args.min_relevance
    if args.compact:
        arguments["compact"] = True
    if args.domains:
        arguments["domains"] = [d.strip() for d in args.domains.split(",") if d.strip()]
    if args.depth is not None:
        arguments["depth"] = args.depth

    result = call_tool(endpoint, token, "brain_recall", arguments, timeout=args.timeout)
    emit(result, args.raw, args.quiet)
    return 0


def cmd_store(args: argparse.Namespace, endpoint: str, token: str) -> int:
    arguments: dict[str, Any] = {
        "action": "remember",
        "content": args.content,
        "type": args.type,
        "importance": args.importance,
    }
    if args.project:
        arguments["project"] = args.project
    if args.tags:
        arguments["tags"] = [t.strip() for t in args.tags.split(",") if t.strip()]
    if args.source:
        arguments["source"] = args.source
    if args.domain:
        arguments["domain"] = args.domain

    result = call_tool(endpoint, token, "brain_store", arguments, timeout=args.timeout)
    emit(result, args.raw, args.quiet)
    return 0


def cmd_reinforce(args: argparse.Namespace, endpoint: str, token: str) -> int:
    arguments = {"action": "reinforce", "memory_ids": args.memory_ids}
    result = call_tool(endpoint, token, "brain_store", arguments, timeout=args.timeout)
    emit(result, args.raw, args.quiet)
    return 0


def cmd_forget(args: argparse.Namespace, endpoint: str, token: str) -> int:
    arguments: dict[str, Any] = {
        "action": "forget",
        "memory_id": args.memory_id,
        "mode": args.mode,
        "confirm": True,
    }
    if args.reason:
        arguments["reason"] = args.reason
    result = call_tool(endpoint, token, "brain_store", arguments, timeout=args.timeout)
    emit(result, args.raw, args.quiet)
    return 0


def cmd_health(args: argparse.Namespace, endpoint: str, token: str) -> int:
    """Real auth check via MCP initialize handshake. /health is unauth-only."""
    result, session_id = mcp_call(
        endpoint,
        token,
        "initialize",
        {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
        },
        timeout=args.timeout,
    )
    server = result.get("serverInfo", {})
    payload = {
        "ok": True,
        "endpoint": f"{endpoint}/mcp",
        "token_prefix": redact(token),
        "session_established": bool(session_id),
        "server_name": server.get("name"),
        "server_version": server.get("version"),
        "protocol_version": result.get("protocolVersion"),
    }
    emit(payload, args.raw, args.quiet)
    return 0


def cmd_status(args: argparse.Namespace, endpoint: str, token: str) -> int:
    payload = {
        "endpoint": f"{endpoint}/mcp",
        "token_prefix": redact(token),
        "token_source": args._token_source,
        "auth_scheme": "Authorization: Bearer",
    }
    emit(payload, args.raw, args.quiet)
    return 0


# ---------------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sb",
        description="Shared-Brain CLI (direct-HTTPS, no MCP host required).",
    )
    parser.add_argument("--endpoint", help="Base URL (default https://shared-brain.us)")
    parser.add_argument("--token", help="Bearer token (prefer env/file/op)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Request timeout in seconds (default {DEFAULT_TIMEOUT})")
    parser.add_argument("--raw", action="store_true",
                        help="Print response body unchanged (no pretty JSON)")
    parser.add_argument("--quiet", action="store_true",
                        help="Print only the most useful field (id, memory_id, status)")

    sub = parser.add_subparsers(dest="command", required=True)

    p_recall = sub.add_parser("recall", help="Search persistent memory")
    p_recall.add_argument("query", help="Free-text query")
    p_recall.add_argument("--project")
    p_recall.add_argument("--max-results", type=int)
    p_recall.add_argument("--min-relevance", type=float)
    p_recall.add_argument("--compact", action="store_true")
    p_recall.add_argument("--domains", help="Comma-separated list")
    p_recall.add_argument("--depth", type=int, choices=[1, 2, 3])
    p_recall.set_defaults(func=cmd_recall)

    p_store = sub.add_parser("store", help="Remember a new memory")
    p_store.add_argument("content", help="Memory body (use quotes)")
    p_store.add_argument("--type", required=True,
                         choices=["knowledge", "incident", "decision", "lesson",
                                  "observation", "procedure", "episodic"])
    p_store.add_argument("--project")
    p_store.add_argument("--importance", type=float, default=0.7)
    p_store.add_argument("--tags", help="Comma-separated tags")
    p_store.add_argument("--source")
    p_store.add_argument("--domain")
    p_store.set_defaults(func=cmd_store)

    p_reinforce = sub.add_parser("reinforce", help="Boost one or more memories")
    p_reinforce.add_argument("memory_ids", nargs="+", help="Memory UUID(s)")
    p_reinforce.set_defaults(func=cmd_reinforce)

    p_forget = sub.add_parser("forget", help="Delete or suppress a memory")
    p_forget.add_argument("memory_id", help="Memory UUID")
    p_forget.add_argument("--mode", choices=["delete", "suppress"], default="suppress")
    p_forget.add_argument("--reason", help="Why this memory is being removed")
    p_forget.set_defaults(func=cmd_forget)

    p_health = sub.add_parser("health", help="Verify Bearer auth via MCP initialize")
    p_health.set_defaults(func=cmd_health)

    p_status = sub.add_parser("status", help="Show endpoint, token source, redacted prefix")
    p_status.set_defaults(func=cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        token, source = resolve_token(args.token)
        endpoint = resolve_endpoint(args.endpoint)
        args._token_source = source
        return args.func(args, endpoint, token)
    except SbError as e:
        print(f"sb: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("sb: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())

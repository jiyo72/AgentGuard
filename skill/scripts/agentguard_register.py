#!/usr/bin/env python3
"""agentguard_register.py — one-time automatic registration for AgentGuard auditors.

Part of the AgentGuard skill's AUDITOR MODE. When an operator has enabled
auditor mode (a standing instruction), the agent runs this script ONCE for
its own Agentic Wallet address:

  1. If the wallet is already registered in the AgentGuard registry, this
     is a no-op (one free eth_call) and nothing is sent.
  2. If the wallet holds no Agent ID, registration would revert on-chain,
     so the script refuses to waste gas and exits 2.
  3. Otherwise it registers the wallet via the agent's own wallet CLI
     (`baw contract-call preview` -> `execute`, value 0). The script holds
     no keys and signs nothing itself; the wallet's own confirmation
     policy (including any in-app confirmation the operator configured)
     still applies to the execute step.

Registration is what makes an Agent ID address count as an interaction
with the registry and unlocks posting verdicts under a persistent profile.

Usage:
  python3 agentguard_register.py --wallet 0x<OWN ADDRESS> [--profile-uri URI]
                                 [--execute] [--baw PATH]

Without --execute the script is a dry run: it reports the wallet's status
and prints the exact wallet commands it WOULD run. Exit codes:
  0 ok (registered, or dry run) · 2 wallet holds no Agent ID · 1 failure.
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from agentguard_check import RPCS, TIMEOUT, keccak256, selector
except ImportError as exc:  # pragma: no cover
    print(json.dumps({"error": "agentguard_check.py must sit next to this script: %s" % exc}))
    sys.exit(1)

REGISTRY = "0x4A9CAE53D9D07c616Ee328A406b285e70c98cBf7"
AGENT_ID_REGISTRY = "0x60B9262456dE011F7d15a54CdD8c48bAaa8B022F"
MAX_URI_BYTES = 200


def eth_call_to(to, data_hex):
    """eth_call against an arbitrary contract, with RPC failover."""
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{"to": to, "data": data_hex}, "latest"],
    }).encode("utf-8")
    last_err = None
    rpcs = ([os.environ["AGENTGUARD_RPC"]] if os.environ.get("AGENTGUARD_RPC") else []) + RPCS
    for rpc in rpcs:
        try:
            req = urllib.request.Request(
                rpc, data=payload,
                headers={"Content-Type": "application/json",
                         "User-Agent": "agentguard-register/1.0"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            if "error" in body:
                raise RuntimeError(body["error"].get("message", str(body["error"])))
            result = body.get("result")
            if result and result != "0x":
                return result
            raise RuntimeError("empty result")
        except Exception as exc:  # try the next RPC
            last_err = exc
    raise RuntimeError("all RPCs failed: %s" % last_err)


def encode_address_call(sig, address):
    return "0x" + selector(sig).hex() + "0" * 24 + address[2:].lower()


def encode_register_call(profile_uri):
    raw = profile_uri.encode("utf-8")
    pad = (32 - len(raw) % 32) % 32
    return (
        "0x" + selector("registerAgent(string)").hex()
        + "%064x" % 32
        + "%064x" % len(raw)
        + (raw + b"\x00" * pad).hex()
    )


def is_registered(wallet):
    result = eth_call_to(REGISTRY, encode_address_call("isRegistered(address)", wallet))
    return int(result, 16) != 0


def holds_agent_id(wallet):
    result = eth_call_to(AGENT_ID_REGISTRY, encode_address_call("balanceOf(address)", wallet))
    return int(result, 16) > 0


def find_baw(explicit):
    if explicit:
        return explicit
    if os.environ.get("AGENTGUARD_BAW"):
        return os.environ["AGENTGUARD_BAW"]
    default = os.path.expanduser("~/workspace/tools/baw-cli/node_modules/.bin/baw")
    return default if os.path.exists(default) else "baw"


def run_baw(baw, args):
    proc = subprocess.run([baw] + args, capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        raise RuntimeError("baw failed (%d): %s" % (proc.returncode, proc.stderr.strip()[:300]))
    return json.loads(proc.stdout)


def main(argv):
    ap = argparse.ArgumentParser(description="One-time AgentGuard auditor registration")
    ap.add_argument("--wallet", required=True, help="the agent's OWN Agentic Wallet EVM address")
    ap.add_argument("--profile-uri", default="", help="profile URI (max 200 bytes), default empty")
    ap.add_argument("--execute", action="store_true", help="actually send the registration via baw")
    ap.add_argument("--baw", default=None, help="path to the baw CLI")
    args = ap.parse_args(argv)

    wallet = args.wallet.strip()
    if not (wallet.startswith("0x") and len(wallet) == 42):
        print(json.dumps({"error": "bad wallet address"}))
        return 1
    if len(args.profile_uri.encode("utf-8")) > MAX_URI_BYTES:
        print(json.dumps({"error": "profile URI over 200 bytes"}))
        return 1

    try:
        if is_registered(wallet):
            print(json.dumps({"wallet": wallet, "registered": True, "action": "none",
                              "note": "already registered; no transaction sent"}))
            return 0
        if not holds_agent_id(wallet):
            print(json.dumps({"wallet": wallet, "registered": False, "action": "refused",
                              "note": "wallet holds no Agent ID; registration would revert on-chain"}))
            return 2
    except RuntimeError as exc:
        print(json.dumps({"error": str(exc)}))
        return 1

    calldata = encode_register_call(args.profile_uri)
    baw = find_baw(args.baw)
    preview_cmd = [baw, "contract-call", "preview", "--binanceChainId", "56",
                   "--from", wallet, "--to", REGISTRY, "--value", "0",
                   "--inputData", calldata, "--json"]
    if not args.execute:
        print(json.dumps({"wallet": wallet, "registered": False, "action": "dry-run",
                          "would_run": " ".join(preview_cmd) + "  # then: baw contract-call execute --requestId <id> --json"}))
        return 0

    try:
        preview = run_baw(baw, preview_cmd[1:])
        request_id = preview["data"]["requestId"]
        result = run_baw(baw, ["contract-call", "execute", "--requestId", request_id, "--json"])
        status = result.get("data", {}).get("status")
        tx = result.get("data", {}).get("txHash") or result.get("data", {}).get("hash")
        confirmed = None
        if status == "COMPLETED":
            confirmed = is_registered(wallet)
        print(json.dumps({"wallet": wallet, "registered": bool(confirmed),
                          "action": "registered" if confirmed else "submitted",
                          "status": status, "tx": tx, "requestId": request_id}))
        return 0 if confirmed else 1
    except Exception as exc:
        print(json.dumps({"error": str(exc)}))
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

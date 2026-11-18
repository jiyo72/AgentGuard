#!/usr/bin/env python3
"""agentguard_check.py — read-only pre-flight verdict lookup for BSC contracts.

Queries the AgentGuard on-chain verdict registry (AgentGuardRegistry,
0x4A9CAE53D9D07c616Ee328A406b285e70c98cBf7, BNB Smart Chain / chainId 56)
for the community consensus on one target contract:

    check(address)              -> aggregate counts, consensus score/status
    targetAuditorCount(address) -> cross-check on the verdict count

Prints one line of JSON to stdout:

    {"target": "0x...", "consensusStatus": "SAFE|CAUTION|DANGER|UNRATED",
     "consensusScore": 0, "safeCount": 0, "cautionCount": 0,
     "dangerCount": 0, "totalVerdicts": 0}

Python 3 standard library only. No keys, no signing, no wallet access —
two eth_call reads against public BSC RPCs, with failover. Keccak-256 is
implemented in pure Python below because hashlib.sha3_256 is NIST SHA3,
which is NOT the Ethereum Keccak variant (different padding).

Usage:
    python3 agentguard_check.py <0x target address>
    AGENTGUARD_RPC=https://your-rpc python3 agentguard_check.py <address>

Exit codes: 0 ok · 2 bad input · 1 every RPC failed / inconsistent data.
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request

REGISTRY = "0x4A9CAE53D9D07c616Ee328A406b285e70c98cBf7"
RPCS = [
    "https://bsc-dataseed1.binance.org",
    "https://bsc-dataseed2.binance.org",
    "https://bsc-rpc.publicnode.com",
    "https://bsc.publicnode.com",
]
TIMEOUT = 12  # seconds per RPC attempt

STATUS_NAMES = {0: "UNRATED", 1: "SAFE", 2: "CAUTION", 3: "DANGER"}
ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# ---------------------------------------------------------------------------
# Pure-Python Keccak-256 (Keccak-f[1600], rate 136 bytes, 0x01 domain pad).
# Validated against: keccak256("") =
# c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 and the
# ERC-20 selectors balanceOf(address)=70a08231, transfer(address,uint256)=a9059cbb.
# ---------------------------------------------------------------------------

_MASK64 = (1 << 64) - 1
_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
# Rotation offsets r[x][y], flattened at index x + 5*y.
_KECCAK_ROT = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
]


def _rotl64(v, n):
    return ((v << n) | (v >> (64 - n))) & _MASK64 if n else v


def _keccak_f1600(state):
    for rc in _KECCAK_RC:
        # Theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # Rho + Pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(
                    state[x + 5 * y], _KECCAK_ROT[x + 5 * y])
        # Chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = (
                    b[x + 5 * y]
                    ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
                ) & _MASK64
        # Iota
        state[0] ^= rc
    return state


def keccak256(data: bytes) -> bytes:
    rate = 136  # (1600 - 2*256) / 8
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0x00)
    padded.append(0x80)
    state = [0] * 25
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        state = _keccak_f1600(state)
    out = bytearray()
    for i in range(4):  # 4 lanes x 8 bytes = 32-byte digest
        out += state[i].to_bytes(8, "little")
    return bytes(out)


def selector(signature: str) -> bytes:
    return keccak256(signature.encode("ascii"))[:4]


# ---------------------------------------------------------------------------
# Minimal JSON-RPC eth_call client + hand ABI decoding.
# check(address) returns six static words:
#   (uint32 safeCount, uint32 cautionCount, uint32 dangerCount,
#    uint32 verdictCount, uint256 consensusScore, uint8 consensusStatus)
# targetAuditorCount(address) returns one uint256 word.
# ---------------------------------------------------------------------------


def eth_call(rpc, data_hex):
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": REGISTRY, "data": data_hex}, "latest"],
    }).encode("utf-8")
    req = urllib.request.Request(
        rpc, data=payload,
        headers={"Content-Type": "application/json",
                 "User-Agent": "agentguard-check/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    if "error" in body:
        raise RuntimeError("RPC error: %s" % body["error"].get("message", body["error"]))
    result = body.get("result")
    if not result or result == "0x":
        raise RuntimeError("empty eth_call result")
    return result


def encode_address_call(sig, address):
    return "0x" + selector(sig).hex() + "0" * 24 + address[2:].lower()


def decode_check(result_hex):
    raw = bytes.fromhex(result_hex[2:])
    if len(raw) != 6 * 32:
        raise RuntimeError("check() returned %d bytes, expected 192" % len(raw))
    words = [int.from_bytes(raw[32 * i:32 * i + 32], "big") for i in range(6)]
    safe, caution, danger, total, score, status = words
    if status not in STATUS_NAMES:
        raise RuntimeError("check() returned unknown consensusStatus %d" % status)
    if safe + caution + danger != total:
        raise RuntimeError("check() counts inconsistent: %d+%d+%d != %d"
                           % (safe, caution, danger, total))
    return safe, caution, danger, total, score, status


def decode_count(result_hex):
    raw = bytes.fromhex(result_hex[2:])
    if len(raw) != 32:
        raise RuntimeError("targetAuditorCount() returned %d bytes, expected 32"
                           % len(raw))
    return int.from_bytes(raw, "big")


def query_registry(target):
    """Try each RPC in turn; return the decoded verdict or raise."""
    check_data = encode_address_call("check(address)", target)
    count_data = encode_address_call("targetAuditorCount(address)", target)
    rpcs = list(RPCS)
    custom = os.environ.get("AGENTGUARD_RPC")
    if custom:
        rpcs.insert(0, custom)
    errors = []
    for rpc in rpcs:
        try:
            safe, caution, danger, total, score, status = decode_check(
                eth_call(rpc, check_data))
            auditors = decode_count(eth_call(rpc, count_data))
            # One active verdict per auditor per target, so the auditor
            # count must equal the verdict count — a mismatch means the
            # node served inconsistent state; do not trust it.
            if auditors != total:
                raise RuntimeError(
                    "inconsistent state: targetAuditorCount=%d but verdictCount=%d"
                    % (auditors, total))
            return {
                "target": target.lower(),
                "consensusStatus": STATUS_NAMES[status],
                "consensusScore": score,
                "safeCount": safe,
                "cautionCount": caution,
                "dangerCount": danger,
                "totalVerdicts": total,
            }
        except (RuntimeError, ValueError, OSError, urllib.error.URLError) as exc:
            errors.append("%s: %s" % (rpc, exc))
    raise RuntimeError("all BSC RPCs failed — " + " | ".join(errors))


def main(argv):
    if len(argv) != 2 or argv[1] in ("-h", "--help"):
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: python3 agentguard_check.py <0x target address>",
              file=sys.stderr)
        return 2
    target = argv[1].strip()
    if not ADDR_RE.match(target):
        print("error: %r is not a valid BSC address "
              "(expected 0x followed by 40 hex characters)" % target,
              file=sys.stderr)
        return 2
    try:
        verdict = query_registry(target)
    except RuntimeError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(verdict))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

# AgentGuard — integration notes

How to consume the AgentGuard verdict registry directly, without the
skill's helper script. Everything here is read-only and free: the
registry's reads are `view` functions.

- **Registry:** `0x4A9CAE53D9D07c616Ee328A406b285e70c98cBf7` — BNB Smart
  Chain, chainId 56.
- **Source:** Sourcify `exact_match`; the deployed bytecode is the
  `AgentGuardRegistry` source in the hackathon repo.

## From another contract

`check()` is O(1) — aggregates are maintained incrementally on every
post/update/revoke — so it is cheap enough to call inside a guard clause
before your contract interacts with an unknown address.

```solidity
interface IAgentGuard {
    function check(address target) external view returns (
        uint32 safeCount,
        uint32 cautionCount,
        uint32 dangerCount,
        uint32 verdictCount,
        uint256 consensusScore,
        uint8 consensusStatus // 0 none, 1 SAFE, 2 CAUTION, 3 DANGER
    );
}

contract Example {
    IAgentGuard constant AGENTGUARD =
        IAgentGuard(0x4A9CAE53D9D07c616Ee328A406b285e70c98cBf7);

    function requireNotDanger(address target) internal view {
        (, , , , , uint8 status) = AGENTGUARD.check(target);
        require(status != 3, "AgentGuard: DANGER consensus");
    }
}
```

Decide your own policy on the other statuses: `verdictCount == 0` means
UNRATED (no auditor has looked — that is not a pass), and CAUTION (2)
means at least a plurality of auditors flagged reservations. A common
sane default: block on DANGER, require an explicit operator decision for
CAUTION and for UNRATED above a value threshold, pass on SAFE.

## From an agent (raw eth_call)

Calldata for `check(address)` is the 4-byte selector `0xc23697a8` followed
by the target address left-padded to 32 bytes:

```
eth_call(
  to   = 0x4A9CAE53D9D07c616Ee328A406b285e70c98cBf7,
  data = 0xc23697a8 + "000000000000000000000000" + <target, 40 hex chars>
)
```

The result is six 32-byte words, in order: `safeCount`, `cautionCount`,
`dangerCount`, `verdictCount`, `consensusScore`, `consensusStatus`.
`targetAuditorCount(address)` (selector `0x83a847e5`) returns one word —
the number of auditors with an active verdict on the target; because each
auditor holds exactly one active verdict per target, it must equal
`verdictCount`, which makes it a cheap consistency check against a node
serving stale or mixed state. The skill's
`scripts/agentguard_check.py` is a dependency-free reference
implementation of exactly this (pure-Python Keccak + hand ABI decoding +
RPC failover) — copy its approach into any runtime.

Per-auditor detail is available when you need provenance or freshness:
`getVerdict(target, auditor)` returns `(exists, status, score,
reportHash, reportURI, updatedAt)`, and `listVerdicts(target, offset,
limit)` paginates the auditor list (limit clamps at 100).

## The consensus rule (exact)

For a target with active verdicts:

- **consensusStatus** is the status (SAFE / CAUTION / DANGER) with the
  **highest count** of active verdicts. **Ties break toward the more
  cautious status** (DANGER > CAUTION > SAFE), implemented by scanning
  from most to least cautious and replacing only on a *strictly* greater
  count.
- **consensusScore** is the arithmetic mean of all active verdict scores,
  every auditor weighted equally, integer division (rounded down).
- A target with no verdicts returns all zeros and consensus status `0`
  (none / UNRATED) — never a misleading default.

Status codes everywhere in the API: `1 = SAFE`, `2 = CAUTION`,
`3 = DANGER`. Scores are 0–100, set by each auditor from their own audit.

## Roadmap — not yet built

> **Roadmap, not existing features.** The following do **not** exist yet;
> do not call, link, or promise them.

Two distribution layers are planned on top of the same registry, so
agents can consume verdicts without speaking raw `eth_call`: (1) an
**MCP server** exposing a `check_contract` tool (address in → the JSON
verdict the skill prints, out) for MCP-native agent frameworks, and (2) a
**hosted read API** — a thin, cacheable HTTP mirror of `check()` /
`listVerdicts()` for dashboards and bots that prefer REST over JSON-RPC.
Both would be read-only projections of the on-chain state; the contract
above remains the single source of truth, and writes would still go
through holders' own wallets.

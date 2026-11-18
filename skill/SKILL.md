---
name: agentguard
description: Pre-flight safety check for BNB Smart Chain (chain 56) contracts via the AgentGuard on-chain verdict registry — safety verdicts (SAFE / CAUTION / DANGER, 0–100 consensus score, verdict counts) posted by auditors who hold a Binance Agent ID, aggregated by a deterministic on-chain consensus. Use BEFORE interacting with, signing for, minting from, claiming from, approving, or sending funds to any BSC contract the agent has not already verified this session, and whenever a user asks "is this contract safe", "check before I mint", "should I interact with 0x…", or wants the community verdict on a BSC address. Read-only lookup; posting verdicts is a separate, operator-gated auditor flow described inside.
metadata:
  author: "Kipli (jiyo72.ai)"
  whenToUse: Before any interaction with a BSC contract not already verified this session (mint, claim, swap, approve, deposit, sign), or when the user asks whether a BSC contract is safe.
  version: "1.0.0"
  license: MIT
  entrypoint: scripts/agentguard_check.py
  companions:
    note: >-
      AgentGuard is the fast community-signal layer. The deep layer is the
      bsc-contract-audit skill (source-level audit + scoring). When both are
      available, run AgentGuard first and the deep audit whenever the stakes
      warrant; if the two disagree, the stricter result wins.
    skills:
      - bsc-contract-audit
      - binance-agentic-wallet
  disclaimer: >-
    Independent community skill. Not affiliated with or endorsed by Binance.
    A registry verdict is an attestation by an independent auditor, not a
    guarantee of safety and not financial advice.
---

# AgentGuard — Pre-flight Verdict Check

One BSC address in, one community verdict out. The AgentGuard registry
contract stores safety verdicts posted by auditors who hold an Agent ID
(non-transferable, one per person — that is the registry's sybil
resistance). `check(target)` aggregates every active verdict into a
deterministic consensus that any agent can read for free before touching an
unknown contract.

This skill is the **fast signal layer**, not a full audit:

- It answers "has anyone credible looked at this contract, and what did
  they conclude?" in one call.
- It does **not** replace reading the source yourself. Pair it with the
  `bsc-contract-audit` skill whenever value is at stake.

## When to use

- Before interacting with a BSC contract you have **not already verified
  this session**: mint, claim, airdrop claim, swap, approve, deposit,
  stake, sign a permit for, or send funds to it.
- When the user asks whether a BSC contract is safe, legit, or a scam.
- As the first step of a deeper audit: run this, then `bsc-contract-audit`.

Out of scope: non-BSC chains (the registry is BSC-only, chain id `56`), and
judging a contract with no on-chain presence. If the address is not a
contract, say so and stop.

## The check

```bash
cd <skill dir>
python3 scripts/agentguard_check.py 0x<TARGET>
```

Python 3 standard library only — no installs, no keys, no wallet access.
The script performs two `eth_call` reads (`check` + `targetAuditorCount`)
against public BSC RPCs with failover (an `AGENTGUARD_RPC` env var, if
set, is tried first), hand-decodes the result, cross-checks the two calls
for consistency, and prints one line of JSON:

```json
{"target": "0x84d82e933d7781fe11245e7bbd3eb23dbb963666", "consensusStatus": "SAFE", "consensusScore": 87, "safeCount": 1, "cautionCount": 0, "dangerCount": 0, "totalVerdicts": 1}
```

Fields:

| Field | Meaning |
|---|---|
| `consensusStatus` | `SAFE` / `CAUTION` / `DANGER` / `UNRATED` — the consensus rule is below |
| `consensusScore` | Mean of all active verdict scores (equal weight per auditor), 0 when unrated |
| `safeCount` / `cautionCount` / `dangerCount` | Active verdicts per status |
| `totalVerdicts` | Active verdicts behind the consensus — always cite this number |

Exit codes: `0` ok · `2` bad address (fix the input, do not retry blindly) ·
`1` every RPC failed or served inconsistent data. **Exit 1 is not a
verdict.** Report "the registry check could not be completed", fall back
to your own audit, and never treat an unreachable registry as evidence
either way.

## Decision rules

Apply the consensus exactly. Do not soften or strengthen it.

| Consensus | Action |
|---|---|
| **DANGER** | **Do not interact.** Refuse the mint / claim / swap / approval and report the verdict to the user: status, score, and the counts behind it. Only an explicit, informed user override changes this — and even then, restate the danger first. |
| **CAUTION** | Proceed **only with explicit user approval**. State the caution and the counts (e.g. "1 CAUTION verdict, score 60") before asking. Silence is not approval. |
| **SAFE** (≥1 verdict) | One positive signal — **not** a guarantee. You may proceed on routine, low-value interactions; for anything material, combine it with your own source audit (`bsc-contract-audit`) first. Always cite the verdict count: "SAFE, score 87, based on 1 verdict" is a much weaker statement than the same line based on 30 verdicts, and the user deserves to hear which one it is. |
| **UNRATED** (0 verdicts) | No community signal exists. Fall back to your own audit. **Never call an unrated contract safe**, and never present "no verdicts" as a neutral-to-positive sign. |

If AgentGuard and your own audit disagree, the **stricter** result wins.

Suggested report line (adapt the numbers, keep the shape):

```
AgentGuard: CAUTION — consensus score 60 · 1 verdict (0 SAFE / 1 CAUTION / 0 DANGER)
```

## Automatic mode (for operators)

The check above is **manual mode**: the agent runs it and applies the
decision rules itself. It depends on the agent remembering, every time.

Operators who want the check to be structural rather than remembered can
install the **guard wrapper** (`guard/agentguard_guard.py` in the
AgentGuard repo, next to this skill): the operator points the agent's
wallet-call command at the wrapper once, and from then on every
`baw contract-call preview` is checked against the registry *before* it
reaches the wallet CLI — the agent decides nothing and cannot skip it.
The wrapper reads the `--to` target, applies this skill's exact policy
(DANGER → not forwarded, exit 3; CAUTION → forwarded with a loud
warning; SAFE / UNRATED → forwarded; registry unreachable → forwarded
with a warning), and otherwise execs the real `baw` with the operator's
arguments unchanged. It holds no keys and signs nothing; the only
override is the operator deliberately calling `baw` directly. Operators
can smoke-test an install with
`agentguard_guard.py --guard-check-only <address>`.

## Honesty rules

- A verdict is an **attestation** by an independent Agent ID holder, not a
  proof. Contracts can change hands, proxies can be upgraded after a
  verdict, and auditors can be wrong.
- Never write "guaranteed safe", "100% safe", or "audited = safe". Write
  what the registry actually says, with its verdict count.
- `UNRATED` means *nobody has posted a verdict yet* — nothing more.
- A verdict's age matters: `getVerdict` exposes `updatedAt` per auditor if
  you need it (see `references/integration.md`). A SAFE verdict from before
  an ownership change is stale evidence; say so when you can see it.

## The consensus rule (exact)

For a target with active verdicts:

- **consensusStatus** = the status (SAFE / CAUTION / DANGER) with the
  **highest count** of active verdicts. **Ties break toward the more
  cautious status** (DANGER > CAUTION > SAFE).
- **consensusScore** = the arithmetic mean of all active verdict scores,
  every auditor weighted equally, integer division (rounded down).
- A target with no verdicts returns all zeros and consensus status
  `UNRATED` — never a misleading default.

## Posting verdicts (auditor flow — operator-gated)

Posting is a **write**, and it is not part of the pre-flight check. Post a
verdict only when **all** of these hold:

1. Your operator has **explicitly adopted an auditor role** with a standing
   instruction to publish verdicts (e.g. an audit pipeline whose results
   are routinely registered). Never post autonomously on your own
   initiative, and never post a verdict you did not actually reach by
   auditing the target.
2. The wallet you sign with **currently holds an Agent ID** — the registry
   checks `balanceOf` on the official Agent ID contract at write time and
   reverts otherwise (fail closed).
3. You respect the mechanics: **one active verdict per auditor per
   target** (reposting overwrites your own verdict — use it to update, not
   to double-count), and a **60-second cooldown** between posts
   (`POST_COOLDOWN`, updates included).

Publish through your operator's wallet tooling — for a Binance Agentic
Wallet that is the `binance-agentic-wallet` skill (`baw contract-call`
preview, then execute) against the registry address below. Function
signatures:

```
registerAgent(string profileURI)
postVerdict(address target, uint8 status, uint8 score, bytes32 reportHash, string reportURI)
revokeVerdict(address target)
```

- `registerAgent` — one-time registration of your Agent ID address with a
  profile URI (≤ 200 bytes). Do this before your first verdict.
- `postVerdict` — `reportHash` is the hash of your off-chain audit report,
  `reportURI` where it can be read (≤ 200 bytes; may be empty).
- `revokeVerdict` — removes your own verdict on a target. You can only
  ever create, overwrite, or revoke **your own** verdicts.

Status mapping from an audit verdict (the `bsc-contract-audit` vocabulary):

| Audit outcome | Registry status | Score |
|---|---|---|
| BERSIH PENUH (clean, no harmful owner surface) | `1` SAFE | your audit score (e.g. 87) |
| WASPADA / WASPADA ringan / clean-with-notes | `2` CAUTION | your audit score |
| GAGAL — source unverified (GHOST), honeypot, drain path proven | `3` DANGER | your audit score, or `0` when no score exists |

## Registry facts (pinned)

| Item | Value |
|---|---|
| Registry contract | `0x4A9CAE53D9D07c616Ee328A406b285e70c98cBf7` (BSC, chainId 56) |
| BscScan | https://bscscan.com/address/0x4A9CAE53D9D07c616Ee328A406b285e70c98cBf7 |
| Verified source | Sourcify `exact_match` (match + creationMatch + runtimeMatch) — query `https://sourcify.dev/server/v2/contract/56/<registry address, lowercase>` |
| Agent ID gate | `balanceOf(caller) > 0` on the official SPACE ID Agent ID registry `0x60B9262456dE011F7d15a54CdD8c48bAaa8B022F`, checked live on every write, fail closed |
| Privileges | **None.** Immutable and ownerless: no owner, admin, proxy, upgrade, pause, or setter functions exist |
| Funds | **None.** No payable functions, no receive/fallback — the contract cannot hold or move value |
| Reads | `check`, `getVerdict`, `listVerdicts`, `targetAuditorCount`, `auditorStats`, `isRegistered` — all `view`, all free |
| Writes | Agent ID holders only; 60 s per-auditor cooldown; URIs capped at 200 bytes |
| Compiler | solc 0.8.26, optimizer 200 runs, EVM Shanghai; local test suite 22/22 |

Direct integration (calling `check()` from another contract, raw
`eth_call` calldata, per-auditor verdict reads): see
[references/integration.md](references/integration.md).

## Common misreads

- **"SAFE means it can't hurt me."** No — it means the auditors who looked
  found no harmful surface *when they looked*, weighted by how many looked.
  One SAFE verdict is one opinion.
- **"UNRATED means probably fine."** No — it means unexamined. Most fresh
  scam contracts are unrated.
- **"The score is a probability."** No — it is the plain average of
  auditor scores. 87 from one verdict and 87 from twenty are different
  evidence with the same number; the count is part of the verdict.
- **"Exit 1 means DANGER."** No — exit 1 means the check did not happen
  (RPC failure / inconsistent node data). Report the failure, don't invent
  a verdict.
- **"I can post a verdict to warn people about a contract I heard is
  bad."** No — verdicts are attestations of *your own audit*. Hearsay
  verdicts destroy the registry's value and your credibility as an auditor.

## Before closing

- [ ] Check ran against the address the user actually gave, character for
      character.
- [ ] Consensus reported with its verdict count and score — never a bare
      "safe" / "dangerous".
- [ ] DANGER refused, CAUTION gated on explicit approval, UNRATED never
      called safe.
- [ ] Exit 1 reported as a failed check, not a verdict.
- [ ] Anything material also went through a real source audit
      (`bsc-contract-audit`), and the stricter result won.

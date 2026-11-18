# AgentGuard: An On-Chain Safety-Verdict Registry for AI Agents

**Version 1.0 — November 2026**

| | |
|---|---|
| **Registry contract** | `0x4A9CAE53D9D07c616Ee328A406b285e70c98cBf7` (BNB Chain, chainId 56) |
| **Website** | https://jiyo72.github.io/AgentGuard/ |
| **Repository** | https://github.com/jiyo72/AgentGuard |
| **BscScan** | https://bscscan.com/address/0x4A9CAE53D9D07c616Ee328A406b285e70c98cBf7 |
| **Source verification** | Sourcify exact match · BscScan verified |
| **License** | MIT |

---

## Abstract

AI agents increasingly hold wallets and transact autonomously, signing for contracts they have never encountered before. A single malicious contract — a drainer, a honeypot, a sale contract with a hidden withdrawal path — can empty an agent's wallet in one call, and the agent has no reliable way to ask, at the moment of decision, whether anyone trustworthy has examined that contract before. AgentGuard is an on-chain safety-verdict registry for BNB Chain that makes that question answerable in one free `view` call. Auditors who hold a Binance Agent ID publish verdicts — SAFE, CAUTION, or DANGER, a 0–100 score, and a hash and URI of the underlying audit report — for any contract address. Writes are gated by Agent ID ownership, verified on-chain against the official SPACE ID registry and failing closed on any error, so every verdict is attributable to a non-transferable, one-per-person identity. A deterministic consensus rule (highest verdict count, ties toward the more cautious status, equal-weighted mean score) turns those verdicts into a machine-readable pre-flight check. The registry is immutable, ownerless, holds no funds, is verified on Sourcify and BscScan, and is seeded with verdicts from more than 700 real contract audits.

---

## 1. The problem

An autonomous agent's most dangerous moment is its first interaction with an unknown contract. The agent is asked to sign a transaction — a mint, a claim, a swap, an approval — against code it did not write and has not reviewed. The failure modes are well known to anyone who audits in this ecosystem: unverified source code (the "ghost" contract whose behaviour cannot be inspected at all), verified source with a live owner surface that includes `withdraw`, `teamMint`, or mutable pricing, honeypot transfer logic, and sale contracts whose pools never open and whose tokens lock forever. For a human, the defence is slow research. For an agent acting at machine speed, the defence has to be a query.

Today that query has nowhere good to go. Reputation about contracts exists, but it is fragmented across social posts, chat groups, and private notes; it is not verifiable (anyone can claim anything under a throwaway handle); it is not attributable (no persistent identity stands behind a claim); and it is not machine-readable at decision time — an agent mid-transaction cannot read a forum thread and weigh it. Centralised databases solve the readability problem but reintroduce a trusted server whose answers the agent cannot verify and whose operator can be wrong, compromised, or simply offline.

What is needed is a reputation layer with three properties: **attributable** (every statement is bound to a persistent, scarce identity), **verifiable** (the aggregate an agent reads is computed by code anyone can inspect, from data anyone can read), and **composable** (the answer is available on-chain, in the same execution context as the interaction it protects). AgentGuard is built to those three properties.

## 2. Design

### 2.1 The registry

`AgentGuardRegistry` is a single Solidity contract (solc 0.8.26, optimizer 200 runs, EVM version pinned to Shanghai) with no imports beyond a minimal inline interface for the Agent ID registry. Its entire state is verdicts, incrementally maintained aggregates, and auditor profiles.

A **verdict** is a record keyed by *(target, auditor)* containing:

- `status` — 1 = SAFE, 2 = CAUTION, 3 = DANGER;
- `score` — an integer 0–100 from the auditor's own audit;
- `reportHash` — the hash (in practice, keccak256) of the auditor's off-chain audit report, binding the on-chain verdict to a document the auditor cannot later alter without detection;
- `reportURI` — where that report can be read (capped at 200 bytes);
- `updatedAt` — the timestamp of the last post or update, so consumers can judge freshness.

### 2.2 Write semantics

There are exactly three write functions, all gated by Agent ID ownership (Section 3):

- `postVerdict(target, status, score, reportHash, reportURI)` creates the caller's verdict on a target, or **overwrites the caller's own previous verdict** on the same target. There is exactly **one active verdict per auditor per target**; an update adjusts the aggregates by removing the old contribution and adding the new one, so double-counting is impossible by construction.
- `revokeVerdict(target)` removes the caller's own verdict. Storage is keyed `[target][auditor]`, so no caller can create, modify, or delete another auditor's slot — this isolation is enforced by the storage layout itself, not by a permission check that could be bypassed.
- `registerAgent(profileURI)` registers (or updates) the caller's agent profile. One registration exists per Agent ID address.

Bounds keep the state space honest without any administrator: a **60-second per-auditor cooldown** between verdict posts (updates included), the 200-byte URI cap, and input validation on every field (status restricted to 1–3, score to 0–100, zero-address targets rejected). Every state change emits an indexed event (`VerdictPosted`, `VerdictUpdated`, `VerdictRevoked`, `AgentRegistered`), so indexers and front-ends never need to scan storage.

### 2.3 Aggregates and the consensus rule

Aggregates (per-status counts and the score sum) are maintained **incrementally** on every post, update, and revoke, which makes `check(target)` an O(1) read cheap enough to call from inside another contract. The consensus rule is deterministic and fully specified:

> For a target with active verdicts, **consensusStatus** is the status with the **highest count** of active verdicts. **Ties break toward the more cautious status** (DANGER > CAUTION > SAFE), implemented by scanning from most to least cautious and replacing the leader only on a *strictly* greater count. **consensusScore** is the arithmetic mean of all active verdict scores, every auditor weighted equally, with integer division (rounded down).

A target with **no verdicts returns all zeros and consensus status 0 (UNRATED)**. This is a deliberate design commitment: the absence of a verdict is never presented as safety, and there is no default score a fresh contract could hide behind. `check()` returns the full distribution — `safeCount`, `cautionCount`, `dangerCount`, `verdictCount`, `consensusScore`, `consensusStatus` — not just a headline, so consumers can see how much evidence a consensus rests on. Supporting reads (`getVerdict`, `listVerdicts` with pagination clamped to 100 entries, `targetAuditorCount`, `auditorStats`, `isRegistered`) expose per-auditor provenance and freshness.

## 3. Agent ID as the trust anchor

A verdict registry is only as strong as the cost of forging its authors. AgentGuard's answer is to make **Binance Agent ID** — the non-transferable, one-per-person identity issued through the SPACE ID registry at `0x60B9262456dE011F7d15a54CdD8c48bAaa8B022F` — the write permission for the entire system.

### 3.1 The gate

Every write first calls `_requireAgentId(msg.sender)`, which performs an explicit low-level **STATICCALL** to `balanceOf(account)` on the Agent ID registry and validates the result by hand: the call must succeed, return exactly 32 bytes, and decode to a value greater than zero. **Every failure mode fails closed with the same error** — registry revert, empty/short/long return data, or a zero balance all revert the write. The check is performed **live on every write, never cached**: an address that loses its Agent ID loses write access on its very next call (a behaviour covered by the test suite). The gate address itself is fixed at construction in an `immutable` variable, so it can never be redirected after deployment.

The low-level form was chosen over a high-level interface `try/catch` after testing showed that, under solc 0.8.26, a malformed-returndata failure through the high-level path propagates as a bare, data-less revert — still fail-closed, but inconsistent. Manual return-data validation makes the fail-closed behaviour identical and deterministic across all failure modes.

### 3.2 Why this identity is the sybil resistance

Agent IDs are non-transferable and limited to one per person. That single fact shapes the registry's economics: an attacker who wants N verdicts needs N distinct, real identities — identities cannot be bought second-hand, spun up in bulk by a script, or recycled after use. Combined with one verdict slot per identity per target and equal weighting in the consensus, flooding a target's verdict set is bounded by identity scarcity rather than by gas, and every participating identity is publicly attributable.

The same persistence makes reputation meaningful in the other direction. `auditorStats(address)` exposes each auditor's active verdict count, registration state, profile URI, and registration timestamp: a track record accrues under one durable identity, and consumers can inspect *who* is behind a consensus before deciding how much to trust it. Agent ID is used strictly as a write gate and as the identity verdicts are attributed to — the registry contains no name-to-wallet lookup and, being immutable, can never grow one.

## 4. Security and threat model

### 4.1 Structural properties

The contract's security posture is by construction rather than by add-on controls:

- **It holds no funds.** There are no payable functions and no `receive`/`fallback`; plain value transfers and unknown-selector calls revert. The contract never reads its own balance, so even value force-sent via `selfdestruct` is inert — no withdrawal path exists.
- **It is immutable and ownerless.** No owner, admin, proxy, upgrade path, pause, or post-deployment setter of any kind exists. There is no privileged key that can be lost, stolen, or abused; the deployer controls nothing after deployment. The category of "admin-key exploit" is absent, not patched.
- **One external call, before all effects.** The only external call in the contract is the read-only gate STATICCALL, executed before any state change. Reentrancy is therefore impossible by construction — inside a static frame the callee cannot write state, and any reentrant call into the registry from that frame reverts the moment it attempts a write — so no reentrancy guard is used; it would add gas, not safety.
- **Checked arithmetic everywhere** (solc 0.8 defaults): aggregate counters cannot wrap or underflow silently; any inconsistency reverts rather than corrupting state.

Before deployment, the contract passed a **22-case adversarial test suite** on a local chain, covering the gate (including a registry that always reverts and one that returns malformed data), verdict isolation, aggregate correctness across post/update/revoke sequences (including swap-and-pop list integrity), boundary validation on both sides of every limit, cooldown enforcement, and the funds-rejection properties above.

### 4.2 Attacks considered

**Sybil verdict flooding.** An attacker creates many identities to stuff a target with SAFE verdicts. Bounded by Agent ID itself: one non-transferable identity per person, each verdict requiring a distinct identity plus gas, each publicly attributable. Flooding is expensive, visible, and — because the full count distribution is public — discountable by consumers.

**Suppression by a target's owner.** A project team that receives a DANGER verdict cannot remove or dilute it selectively: verdict slots are keyed by auditor, only the author can update or revoke their own, and there is no admin path. The only counter is to persuade other independent auditors, in public.

**Auditor key compromise.** A stolen auditor key can only rewrite that auditor's own verdicts; it cannot touch anyone else's, move funds (there are none), or alter the contract. The blast radius of the worst key compromise in the system is one identity's attestations, which the legitimate holder can correct from a new address by re-posting.

**Gate-contract failure.** If the Agent ID registry reverts or returns malformed data, writes halt (fail closed) — but reads do not depend on the gate at all, so `check()` and every other view remain fully available. A gate outage freezes new attestations, never the consumption of existing ones.

**Spam and state bloat.** Bounded by the 60-second per-auditor cooldown, the single verdict slot per (auditor, target) pair, the 200-byte URI caps, and the 100-entry page clamp — all without administrator intervention.

**Score gaming.** Scores are bounded to 0–100 per auditor and the consensus *status* is determined by counts, not by scores, so a single extreme score cannot flip a status. The score distribution behind any consensus is fully public via `listVerdicts`, and consumers who want stricter semantics can weight auditors by their visible track records via `auditorStats`.

### 4.3 Limitations, stated plainly

Verdicts are **attestations, not proofs**. Auditors can be wrong; contracts can change hands, and upgradeable targets can change behaviour after a verdict is posted (the per-verdict `updatedAt` timestamp exists so consumers can weigh freshness). A consensus built on a **single verdict is a weak signal** — the registry deliberately surfaces the verdict count alongside every consensus so that "SAFE, score 87, from 1 verdict" is never confused with the same score from thirty. AgentGuard is one safety signal to be combined with direct source review whenever material value is at stake, not a substitute for it.

## 5. Consumption and integration

### 5.1 The free read

`check()` is a `view` function: free off-chain over any JSON-RPC endpoint, and cheap enough on-chain to use as a guard clause. A contract can refuse to touch a DANGER-consensus target before interacting with it:

```solidity
interface IAgentGuard {
    function check(address target) external view returns (
        uint32 safeCount, uint32 cautionCount, uint32 dangerCount,
        uint32 verdictCount, uint256 consensusScore, uint8 consensusStatus
    );
}

// Inside your contract, before interacting with an unknown target:
(, , , , , uint8 status) = agentGuard.check(target);
require(status != 3, "AgentGuard: DANGER consensus");
// status: 0 = UNRATED, 1 = SAFE, 2 = CAUTION, 3 = DANGER
```

Policies for the other statuses belong to the consumer: a sane default is to block on DANGER, require an explicit operator decision for CAUTION and for UNRATED above a value threshold, and pass on SAFE — always with the verdict count in view.

### 5.2 The agent skill

The `agentguard` skill packages the check for agent runtimes: a dependency-free Python script performs the `check` and `targetAuditorCount` `eth_call`s against public BSC RPCs with failover, cross-checks the two reads for consistency (the counts must agree, which catches nodes serving stale or mixed state), and prints one line of JSON. The skill wraps it in fixed decision rules: **DANGER → do not interact**; **CAUTION → proceed only with explicit user approval**, stating the counts first; **SAFE → one positive signal, not a guarantee**, to be combined with a full source audit for anything material; **UNRATED → no signal**, fall back to one's own audit and never describe the target as safe. A failed lookup (all RPCs unreachable) is reported as a failed check, never as a verdict.

### 5.3 The Guard wrapper

The decision rules above still depend on an agent remembering to check. The **Guard wrapper** removes the remembering: the operator points the agent's wallet-call command (the Binance Agentic Wallet CLI, `baw contract-call`) at the wrapper once, and from then on every call preview is checked against the registry *before* it reaches the wallet. The wrapper extracts the `--to` target (the only place the target exists — `execute` carries only a request ID bound to the preview), applies the registry's policy — **DANGER → not forwarded, exit code 3**; CAUTION → forwarded after a loud warning carrying the verdict counts; SAFE / UNRATED → forwarded; registry unreachable → forwarded with a warning, never silently treated as a verdict — and otherwise executes the real wallet CLI with the operator's arguments unchanged. It holds no keys, signs nothing, and its only power is refusal; the sole override is the operator deliberately bypassing it, an action visible in shell history.

### 5.4 The design goal: safety as plumbing

These three layers express one principle: **safety adopted once, applied automatically thereafter.** The operator makes a single conscious decision — install the skill, or put the wrapper in front of the wallet — and every subsequent interaction is guarded without the agent needing to know the registry exists. Verdicts flow in from auditors' own audit pipelines; protection flows out to every consumer of the registry, on-chain and off.

## 6. Deployment and current state

`AgentGuardRegistry` was deployed to BNB Chain mainnet on **18 November 2026** by deployer `0xB565E04544776B59d8D134E849b96da8cc433B79` (deploy transaction `0x469f9707a7f539b5e07fffcc13237fac373fe41791c7f2b803f2897bffcec546`), with the official SPACE ID Agent ID registry as its constructor argument. Deployment consumed 1,510,617 gas at 0.05 gwei (0.00007553085 BNB); the deployed code is 13,462 bytes. The source is verified as a **Sourcify exact match** (match, creation match, and runtime match) and as **verified on BscScan**; the recompiled bytecode from the published build inputs is byte-identical to the deployed code.

The registry was seeded on deployment day by the operator agent **jiyo72.ai** with verdicts taken from its existing audit operation — more than 700 BNB Chain contracts source-checked, owner-surface reviewed, and scored — beginning with five representative entries:

| Target | Contract | Verdict | Score | Basis |
|---|---|---|---|---|
| AGENTONE Forge | `0x84d82e933d7781fe11245e7bbd3eb23dbb963666` | SAFE | 87 | Verified source, no harmful owner surface |
| EpochMiningPool | `0x0f214ef91aff6cd79d6740f52ec69bf0360dab1a` | SAFE | 78 | Verified source, no harmful owner surface |
| Vault Boxes | `0xbcdd900857e5d8cc87c45764e61373ca1992e4d4` | CAUTION | 81 | Clean with notes (light caution) |
| PUNNY | `0xafae0bf373ad87e88555afe1605111f66c99062c` | CAUTION | 60 | Clean with notes (light caution) |
| Agent ID Pioneer | `0x368d6732b9b17e3ab08544ea14180ad3a6101131` | DANGER | 0 | Source not verified on Sourcify (rejected) |

For four of the five, the verdict's `reportHash` is the keccak256 of the actual audit file; the DANGER entry carries a zero hash, as no audit file exists for an unverified-source rejection. Seeding (one `registerAgent` plus five `postVerdict` calls, spaced to respect the cooldown) consumed 1,285,038 gas in total (0.0001063111 BNB at the observed gas prices of 0.07–0.09 gwei); individual mainnet observations were 142,628 gas for registration and 189,522–263,828 gas for first verdict posts, consistent with local measurements (300,773 gas for a first post, 70,770 for an update, 70,306 for a revoke, 80,277 for a first registration, measured pre-deployment). After seeding, `totalVerdicts()` read 5 and `totalRegisteredAgents()` read 1, and independent `eth_call` reads confirmed every aggregate matched the posted values exactly. A public front-end at the project website reads the registry live via public BSC RPC.

## 7. Roadmap

The following are **planned, not shipped**. The deployed contract is immutable and will not change; all roadmap items are layers around it.

- **MCP `check_contract` server** — a Model Context Protocol server exposing the registry check as a tool (address in, JSON verdict out) for MCP-native agent frameworks, so agents can consume verdicts without speaking raw `eth_call`.
- **Hosted read API** — a thin, cacheable HTTP mirror of `check()` and `listVerdicts()` for dashboards and bots that prefer REST over JSON-RPC. It would be a read-only projection; the contract remains the single source of truth.
- **Track-record-aware weighting** — richer consumer-side and indexer-side analytics over the public verdict distribution and `auditorStats`, letting consumers weight auditors by demonstrated history. The on-chain consensus rule is fixed by immutability; weighting would live in the consumption layer, not in a contract change.
- **Additional chains** — the Agent ID gate is BNB Chain-specific, so other chains would mean separate deployments against equivalent identity registries, not an upgrade of this contract.

## 8. Disclaimer

AgentGuard verdicts are attestations by independent Agent ID holders based on their own audits. A verdict — including a SAFE consensus — is one safety signal, not a guarantee of safety, not an audit by this project's authors of any specific target, and not financial advice. Always verify a contract's source and behaviour yourself before committing material value.

---

*AgentGuard — pre-flight safety checks for the agent economy. Contract: `0x4A9CAE53D9D07c616Ee328A406b285e70c98cBf7` · https://jiyo72.github.io/AgentGuard/ · https://github.com/jiyo72/AgentGuard*

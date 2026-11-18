# AgentGuard

**An on-chain safety-verdict registry for AI agents on BNB Chain.**

Auditors who hold a Binance **Agent ID** publish safety verdicts (SAFE / CAUTION / DANGER, a 0–100 score, and the hash + URI of the underlying audit report) for any contract address. Any agent or contract can then query the aggregate verdict **for free** before interacting with an unknown contract — a pre-flight safety check for the agent economy.

- **Registry contract:** `0x4A9CAE53D9D07c616Ee328A406b285e70c98cBf7` (BNB Chain, chainId 56)
- **BscScan:** https://bscscan.com/address/0x4A9CAE53D9D07c616Ee328A406b285e70c98cBf7
- **Source verification:** Sourcify exact match (match, creation match, runtime match)
- **Live demo:** see `docs/` (static site in `docs/`, no build step, reads the registry directly via public BSC RPC)

## Why Agent ID is the trust anchor

Every write to the registry is gated by Agent ID ownership: the contract verifies, with a read-only call to the official SPACE ID Agent ID contract (`0x60B9262456dE011F7d15a54CdD8c48bAaa8B022F`), that the caller holds an Agent ID — and fails closed if that check cannot be completed. A verdict is only as credible as the non-transferable, one-per-person Agent ID behind it, and each auditor's track record accumulates under that same identity. Agent ID is therefore not a login decoration: it is the registry's sybil resistance.

## Safety design

- The contract **holds no funds** — there is no payable function and no withdrawal path.
- It is **immutable and ownerless** — no admin, no proxy, no upgrade, no pause. Nobody, including the deployer, can change its behaviour after deployment.
- The only external call is the read-only Agent ID `balanceOf` check, performed before any state change.
- One active verdict per auditor per target; auditors can only update or revoke their own verdicts.
- A 60-second per-auditor cooldown bounds spam.

## Querying (free, no wallet needed)

```solidity
interface IAgentGuard {
    function check(address target) external view returns (
        uint32 safeCount, uint32 cautionCount, uint32 dangerCount,
        uint32 totalVerdicts, uint256 consensusScore, uint8 consensusStatus
    );
}
```

Consensus rule: the status with the highest verdict count wins; ties resolve toward the **more cautious** status (DANGER > CAUTION > SAFE). The consensus score is the equal-weighted average of active verdict scores. A target with no verdicts returns zeros (status 0 = UNRATED) — the absence of a verdict is never presented as safety.

## Agent skill

`skill/` contains a ready-to-install agent skill (`SKILL.md` + a stdlib-only Python check script) that makes any agent call AgentGuard automatically before interacting with an unverified BSC contract.

## Seeded verdicts

The registry is seeded with verdicts from 700+ real contract audits performed by the operator agent (jiyo72.ai) in the BNB Chain Agent ID ecosystem — including AGENTONE (SAFE 87), EpochMiningPool (SAFE 78), Vault Boxes (CAUTION 81), PUNNY (CAUTION 60) and Agent ID Pioneer (DANGER 0, unverified source).

## Disclaimer

Verdicts are attestations by independent Agent ID holders based on their own audits. They are one safety signal, not a guarantee and not financial advice.

## License

MIT

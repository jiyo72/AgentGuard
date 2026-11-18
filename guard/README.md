# AgentGuard Guard — the always-on wrapper for `baw contract-call`

Your agent checks contracts when it remembers to. This wrapper makes the
check **structural**: install it once, and every contract call your agent
makes through the Binance Agentic Wallet CLI is looked up in the
AgentGuard on-chain verdict registry
(`0x4A9CAE53D9D07c616Ee328A406b285e70c98cBf7`, BSC) *before* the call
reaches the wallet. The agent itself decides nothing — there is no
prompt to forget, no step to skip, no instruction to talk it out of.

## Install (2 minutes)

You need the check script from the `agentguard` skill
(`agentguard_check.py`) somewhere the wrapper can find it — the simplest
layout is both files in one folder. Then point your agent's wallet-call
command at the wrapper instead of at `baw`:

```bash
# before
baw contract-call preview --binanceChainId 56 --from <wallet> \
    --to <contract> --value 0 --inputData 0x... --json

# after — same command, wrapper in front
python3 /path/to/agentguard_guard.py contract-call preview \
    --binanceChainId 56 --from <wallet> --to <contract> \
    --value 0 --inputData 0x... --json
```

Configuration is via environment variables, all optional:

| Variable | Meaning | Default |
|---|---|---|
| `AGENTGUARD_BAW` | Path to the real `baw` binary | `~/workspace/tools/baw-cli/node_modules/.bin/baw` |
| `AGENTGUARD_CHECK` | Path to `agentguard_check.py` | searched: next to the wrapper, `../skill/scripts/`, the installed skill |
| `AGENTGUARD_RPC` | Custom BSC RPC for the lookup | public BSC RPCs with failover |

Test your install without touching the wallet:

```bash
python3 agentguard_guard.py --guard-check-only 0x84d82e933d7781fe11245e7bbd3eb23dbb963666
# {"target": "0x84d8...", "consensusStatus": "SAFE", "consensusScore": 87, ...}
```

## Policy

The check runs on the `--to` target of `contract-call preview` — the
only place the target address exists (`execute` carries just a
`requestId` and replays what preview already checked).

| Registry consensus | What happens |
|---|---|
| **DANGER** | The call is **not forwarded**. Block message with the verdict counts on stderr, exit code **3**. baw never sees the call. |
| **CAUTION** | Forwarded, after a loud warning line with the verdict counts on stderr. The baw preview still shows its own risk panel — read it before executing. |
| **SAFE** | Forwarded. One short info line on stderr, with the score and verdict count. |
| **UNRATED** (0 verdicts) | Forwarded. One short info line on stderr. Unrated means *nobody has audited this yet* — it is not a safety signal. |
| Check unreachable (RPCs down) | Forwarded with a warning. An unreachable registry never wedges your wallet — and is never treated as a verdict. |
| Non-BSC chain / no `--to` | Forwarded; the registry is BSC-only and has nothing to say. |

## Honesty notes

- **One install covers every later call.** That is the point: the
  protection does not depend on the agent's memory, mood, or prompt.
  Until you uninstall it, there is no unguarded `contract-call` path
  through this command.
- **The override is intentional and visible.** A DANGER block can be
  bypassed only by the operator calling `baw` directly, bypassing the
  wrapper on purpose — an action that shows up in shell history and
  logs. The wrapper never offers a quiet `--force` flag.
- **The wrapper holds no power over your wallet.** It has no keys,
  signs nothing, and forwards your arguments to baw byte-for-byte
  (via `exec`, inheriting stdio, exiting with baw's own exit code).
  Its only network traffic is two read-only `eth_call` lookups against
  public BSC RPCs. Its only power is refusal.
- **A verdict is an attestation, not a guarantee.** Verdicts are posted
  by independent Agent ID holders based on their own audits. SAFE with
  1 verdict is one opinion; read the counts the wrapper prints. The
  deep check remains a real source audit (e.g. the `bsc-contract-audit`
  skill) whenever real value is at stake.

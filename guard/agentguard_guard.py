#!/usr/bin/env python3
"""agentguard_guard.py — AgentGuard wrapper for `baw contract-call`.

WHAT THIS IS
    A transparent pass-through shim that sits in front of the Binance
    Agentic Wallet CLI (`baw`). The operator points their agent's
    wallet-call command at this script ONCE:

        agentguard_guard.py contract-call preview --binanceChainId 56 \
            --from <wallet> --to <contract> --value 0 --inputData 0x... --json

    and from then on, every `contract-call preview` is checked against
    the AgentGuard on-chain verdict registry
    (0x4A9CAE53D9D07c616Ee328A406b285e70c98cBf7, BSC) BEFORE it reaches
    baw. The agent decides nothing — the check lives in the command
    path, not in the agent's judgement, so it cannot be skipped,
    forgotten, or talked out of it.

SAFETY CONTRACT (read this before trusting the wrapper)
    * This wrapper NEVER holds keys, NEVER signs anything, and NEVER
      modifies the call. It does not add, remove, or alter a single
      argument: on a pass decision it exec()s the real baw binary with
      the operator's original argv, byte for byte, inheriting stdio.
    * Its only network activity is two read-only eth_call lookups
      against public BSC RPCs (via agentguard_check.py) — the same
      reads anyone can make.
    * All signing, preview parsing, risk display, and user confirmation
      still happen inside baw exactly as they do without the wrapper.
    * The ONLY power this script has is refusal: on a DANGER consensus
      it declines to forward and exits 3. The operator can always
      override by calling baw directly — deliberately, and visibly in
      their own shell history. There is no silent bypass.

POLICY (applied to the `--to` target of `contract-call preview`)
    DANGER   -> do NOT forward; block message on stderr; exit 3.
    CAUTION  -> forward, after a loud warning with the verdict counts
                on stderr (the baw preview still shows its own risk
                panel; review it before executing).
    SAFE     -> forward; one short info line on stderr.
    UNRATED  -> forward; one short info line on stderr. UNRATED means
                "no auditor has posted a verdict yet" — it is NOT a
                safety signal.
    Check could not be completed (every RPC down / check script not
    found) -> forward with a warning on stderr. Availability wins over
    silent insecurity: an unreachable registry must never wedge the
    operator's wallet, and must never be mistaken for a verdict either.

PARSER NOTES (verified against `baw contract-call preview --help` and
the binance-agentic-wallet skill docs, external-sign.md)
    * The target contract address is the value of the `--to` flag
      (also accepted: `--to=<address>`). Extraction is BY FLAG NAME,
      never by position: `--from` also carries an address (the wallet
      itself, and it appears BEFORE `--to` in baw's canonical shape),
      and `--inputData` may embed addresses inside calldata. Neither is
      ever treated as the target.
    * `contract-call execute` takes only `--requestId` — the target is
      bound server-side to the preview, so there is no address in argv
      to check. The wrapper forwards execute unchanged; the guard
      already ran at preview time, which is the only moment the target
      is visible.
    * If `--binanceChainId` names a chain other than 56, the BSC-only
      registry has nothing to say about that chain's contracts: the
      check is skipped (one note line) and the call forwarded.
    * Anything else (other baw commands, help, Solana previews with
      --unsignedTx and no --to) is forwarded untouched.

CONFIGURATION (environment)
    AGENTGUARD_BAW    Path to the real baw binary.
                      Default: ~/workspace/tools/baw-cli/node_modules/.bin/baw
    AGENTGUARD_CHECK  Path to agentguard_check.py. Default search:
                      alongside this script, ../skill/scripts/ (repo
                      package layout), the installed agentguard skill.
    AGENTGUARD_RPC    Custom BSC RPC for the check (passed through to
                      agentguard_check.py, which honours it natively).

TEST MODE
    agentguard_guard.py --guard-check-only <0x address>
        Print the registry verdict JSON for one address and exit
        (0 ok, 1 check failed, 2 bad address). Never invokes baw.

Python 3 standard library only. No keys, no signing, no wallet access.
"""

import importlib.util
import json
import os
import re
import sys

DEFAULT_BAW = os.path.expanduser(
    "~/workspace/tools/baw-cli/node_modules/.bin/baw")
REGISTRY_CHAIN_ID = "56"  # the AgentGuard registry lives on BSC only
EXIT_BLOCKED = 3
ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def eprint(msg):
    print(msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# Forwarding: replace this process with the real baw, original argv intact.
# ---------------------------------------------------------------------------

def forward(args):
    baw = os.environ.get("AGENTGUARD_BAW", DEFAULT_BAW)
    try:
        os.execvpe(baw, [baw] + args, os.environ)
    except OSError as exc:
        eprint("[agentguard] could not execute baw at %s: %s" % (baw, exc))
        return 127
    return 127  # unreachable: execvpe only returns by raising


# ---------------------------------------------------------------------------
# Verdict lookup: import agentguard_check.py and call its query_registry().
# ---------------------------------------------------------------------------

def _check_script_candidates():
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = []
    env_path = os.environ.get("AGENTGUARD_CHECK")
    if env_path:
        candidates.append(env_path)
    candidates += [
        # Co-located copy (simplest install: both files in one folder).
        os.path.join(here, "agentguard_check.py"),
        # Repo package layout: repo/guard/ next to repo/skill/.
        os.path.join(here, "..", "skill", "scripts", "agentguard_check.py"),
        # Dev workspace layout: agentid-hackathon/guard/ in ~/workspace.
        os.path.join(here, "..", "..", "custom-skills", "agentguard",
                     "scripts", "agentguard_check.py"),
        # Installed skill locations.
        os.path.expanduser("~/workspace/custom-skills/agentguard/scripts/"
                           "agentguard_check.py"),
        os.path.expanduser("~/.agents/skills/agentguard/scripts/"
                           "agentguard_check.py"),
    ]
    return [os.path.normpath(p) for p in candidates]


def run_check(target):
    """Return (verdict dict, None) on success, (None, error str) on failure."""
    for path in _check_script_candidates():
        if os.path.isfile(path):
            try:
                spec = importlib.util.spec_from_file_location(
                    "agentguard_check", path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return module.query_registry(target), None
            except Exception as exc:  # RPC failure / inconsistent data
                return None, str(exc)
    return None, ("agentguard_check.py not found (looked in: %s; "
                  "set AGENTGUARD_CHECK to its path)"
                  % ", ".join(_check_script_candidates()))


# ---------------------------------------------------------------------------
# Argument parsing — by flag name, never by position.
# ---------------------------------------------------------------------------

def flag_value(tokens, name):
    """Value of `--name <value>` or `--name=<value>`; None if absent or
    if the flag is present but its value is missing / another flag."""
    prefix = name + "="
    for i, tok in enumerate(tokens):
        if tok == name:
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("--"):
                return tokens[i + 1]
            return None
        if tok.startswith(prefix):
            return tok[len(prefix):]
    return None


def counts_line(verdict):
    return ("%d verdict(s): %d SAFE / %d CAUTION / %d DANGER, "
            "consensus score %d"
            % (verdict["totalVerdicts"], verdict["safeCount"],
               verdict["cautionCount"], verdict["dangerCount"],
               verdict["consensusScore"]))


def guard_preview(tokens):
    """Apply the AgentGuard policy to a `contract-call preview` argv tail.

    Returns None to forward the call, or an exit code to stop with.
    """
    chain = flag_value(tokens, "--binanceChainId")
    if chain is not None and chain != REGISTRY_CHAIN_ID:
        eprint("[agentguard] chain %s: registry is BSC-only (56) — "
               "check skipped, forwarding." % chain)
        return None

    target = flag_value(tokens, "--to")
    if target is None:
        eprint("[agentguard] no --to target in this call — nothing to "
               "check, forwarding.")
        return None
    if not ADDR_RE.match(target):
        eprint("[agentguard] --to value %r is not an EVM address — "
               "check skipped, forwarding." % target)
        return None

    verdict, err = run_check(target)
    if verdict is None:
        eprint("[agentguard] WARNING: verdict check for %s could not be "
               "completed (%s). Forwarding anyway — an unreachable "
               "registry is not evidence of safety." % (target, err))
        return None

    status = verdict["consensusStatus"]
    if status == "DANGER":
        eprint("[agentguard] BLOCKED: %s has a DANGER consensus in the "
               "AgentGuard registry (%s)."
               % (target, counts_line(verdict)))
        eprint("[agentguard] The call was NOT forwarded to baw. "
               "Operator override: run baw directly — deliberate, and "
               "visible in your shell history.")
        return EXIT_BLOCKED
    if status == "CAUTION":
        eprint("[agentguard] *** WARNING: %s has a CAUTION consensus in "
               "the AgentGuard registry (%s). Forwarding — read the baw "
               "preview carefully before you execute. ***"
               % (target, counts_line(verdict)))
        return None
    # SAFE or UNRATED: one short info line, then forward.
    eprint("[agentguard] %s (%s) — forwarding."
           % (status, counts_line(verdict)))
    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def check_only(address):
    if not address or not ADDR_RE.match(address):
        eprint("error: %r is not a valid BSC address (expected 0x "
               "followed by 40 hex characters)" % address)
        return 2
    verdict, err = run_check(address)
    if verdict is None:
        eprint("error: %s" % err)
        return 1
    print(json.dumps(verdict))
    return 0


def main(argv):
    args = argv[1:]

    if args and args[0] == "--guard-check-only":
        if len(args) != 2:
            eprint("usage: agentguard_guard.py --guard-check-only "
                   "<0x address>")
            return 2
        return check_only(args[1])

    if args[:1] == ["contract-call"]:
        sub = args[1] if len(args) > 1 else None
        if sub == "preview":
            stop = guard_preview(args[2:])
            if stop is not None:
                return stop
        elif sub == "execute":
            # No address exists in an execute argv (only --requestId);
            # the target was checked when it was previewed.
            eprint("[agentguard] execute replays a call already checked "
                   "at preview — forwarding.")
        # Any other contract-call shape (help, bare group): forward.

    # Everything else is forwarded to baw untouched.
    return forward(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv))

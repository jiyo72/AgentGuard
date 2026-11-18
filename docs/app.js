"use strict";
/*
 * AgentGuard front-end.
 *
 * Read path: plain JSON-RPC eth_call via fetch against public BNB Chain RPC
 * endpoints (with failover). No wallet, no login, no credentials of any kind
 * are ever requested by this page — writes are done by holders from their own
 * wallets, outside this page.
 *
 * The ABI codec below is hand-rolled (no external JS dependencies) and covers
 * exactly the AgentGuardRegistry read functions this page uses:
 *   check(address)
 *   getVerdict(address,address)
 *   listVerdicts(address,uint256,uint256)
 *   auditorStats(address)
 *   isRegistered(address)
 *   targetAuditorCount(address)
 *   totalVerdicts()
 *   totalRegisteredAgents()
 * Function signatures are taken verbatim from artifacts/AgentGuardRegistry.json.
 */

/* ============================ CONFIG ============================ */

const CONFIG = {
  // Placeholder until the registry is deployed. While this is the zero
  // address, the page shows a clear "deployment pending" state.
  contractAddress: "0x4A9CAE53D9D07c616Ee328A406b285e70c98cBf7",
  chainId: 56, // BNB Chain
  rpcEndpoints: [
    "https://bsc-dataseed.binance.org",
    "https://bsc-dataseed1.binance.org",
    "https://bsc-dataseed2.binance.org",
    "https://bsc-rpc.publicnode.com",
    "https://bsc-dataseed1.defibit.io"
  ],
  // Official SPACE ID Agent ID registry (write gate reference, shown in copy).
  agentIdRegistry: "0x60B9262456dE011F7d15a54CdD8c48bAaa8B022F",
  pageSize: 10,
  // Seeded showcase: name + address pairs with the verdict recorded in our
  // audit history (~/workspace/hunt-new-projects-watch/state.json,
  // batchDecisions, November 2026). Verdict text is from those records —
  // these are audit-record verdicts, shown as the registry's seed set.
  seededTargets: [
    {
      name: "AGENTONE",
      address: "0x84d82e933d7781fe11245e7bbd3eb23dbb963666",
      chip: "FULL PASS",
      tone: "safe",
      record: "BERSIH PENUH + GO 87/100 — Sourcify exact match; full source read found no owner, admin, pause, blacklist, or setter surface."
    },
    {
      name: "EpochMiningPool",
      address: "0x0f214ef91aff6cd79d6740f52ec69bf0360dab1a",
      chip: "FULL PASS",
      tone: "safe",
      record: "BERSIH PENUH — no owner/admin/withdraw/rescue/upgrade surface; second-layer CAUTION 78/100 was a market-viability drag (the mined token was nearly unsellable), not a contract-safety finding."
    },
    {
      name: "Vault Boxes",
      address: "0xbcdd900857e5d8cc87c45764e61373ca1992e4d4",
      chip: "LIGHT CAUTION",
      tone: "caution",
      record: "WASPADA ringan (light caution) + second-layer CAUTION 81/100 — verified source, but the live owner retains limited setter powers, so it was not auto-trusted."
    },
    {
      name: "PUNNY",
      address: "0xafae0bf373ad87e88555afe1605111f66c99062c",
      chip: "LIGHT CAUTION",
      tone: "caution",
      record: "WASPADA ringan (light caution) + second-layer CAUTION 60/100 — capped by a mutable baseURI: team-hosted metadata the live owner can change after mint."
    },
    {
      name: "Agent ID Pioneer",
      address: "0x368d6732b9b17e3ab08544ea14180ad3a6101131",
      chip: "REJECTED",
      tone: "danger",
      record: "GAGAL — rejected under the GHOST rule: no matching verified source on Sourcify, so the contract was never minted or trusted."
    }
  ]
};

// ===== AGENTGUARD-CODEC-BEGIN =====
/* ------------------------------------------------------------------
 * Minimal, dependency-free Keccak-256 + ABI codec.
 * Pure functions only (no DOM, no CONFIG) so they can be unit-tested
 * outside the browser. Verified against ethers v6 AbiCoder output.
 * ------------------------------------------------------------------ */

function agHexToBytes(hex) {
  if (typeof hex !== "string") throw new Error("expected hex string");
  let h = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0) h = "0" + h;
  if (!/^[0-9a-fA-F]*$/.test(h)) throw new Error("invalid hex");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function agBytesToHex(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
  return s;
}

function agUtf8ToBytes(str) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let cp = str.charCodeAt(i);
    if (cp < 0x80) {
      out.push(cp);
    } else if (cp < 0x800) {
      out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    } else if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < str.length) {
      const lo = str.charCodeAt(++i);
      cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
      out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    } else {
      out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    }
  }
  return new Uint8Array(out);
}

function agBytesToUtf8(bytes) {
  let s = "";
  let i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i];
    let cp, n;
    if (b0 < 0x80) { cp = b0; n = 1; }
    else if ((b0 & 0xe0) === 0xc0) { cp = b0 & 0x1f; n = 2; }
    else if ((b0 & 0xf0) === 0xe0) { cp = b0 & 0x0f; n = 3; }
    else if ((b0 & 0xf8) === 0xf0) { cp = b0 & 0x07; n = 4; }
    else { cp = 0xfffd; n = 1; }
    if (n > 1) {
      if (i + n > bytes.length) { cp = 0xfffd; n = 1; }
      else {
        for (let k = 1; k < n; k++) cp = (cp << 6) | (bytes[i + k] & 0x3f);
      }
    }
    i += n;
    if (cp > 0xffff) {
      cp -= 0x10000;
      s += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
    } else {
      s += String.fromCharCode(cp);
    }
  }
  return s;
}

/* --- Keccak-256 (Keccak-f[1600], rate 136 bytes, 0x01 domain padding) --- */

const AG_KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
];
const AG_KECCAK_ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
const AG_KECCAK_PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];
const AG_MASK64 = (1n << 64n) - 1n;

function agRotl64(x, n) {
  const s = BigInt(n);
  return ((x << s) | (x >> (64n - s))) & AG_MASK64;
}

function agKeccakF1600(st) {
  const bc = [0n, 0n, 0n, 0n, 0n];
  for (let round = 0; round < 24; round++) {
    // Theta
    for (let i = 0; i < 5; i++) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
    for (let i = 0; i < 5; i++) {
      const t = bc[(i + 4) % 5] ^ agRotl64(bc[(i + 1) % 5], 1);
      for (let j = 0; j < 25; j += 5) st[j + i] ^= t;
    }
    // Rho + Pi
    let t = st[1];
    for (let i = 0; i < 24; i++) {
      const j = AG_KECCAK_PILN[i];
      const tmp = st[j];
      st[j] = agRotl64(t, AG_KECCAK_ROTC[i]);
      t = tmp;
    }
    // Chi
    for (let j = 0; j < 25; j += 5) {
      for (let i = 0; i < 5; i++) bc[i] = st[j + i];
      for (let i = 0; i < 5; i++) st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
    }
    // Iota
    st[0] ^= AG_KECCAK_RC[round];
  }
}

function agKeccak256(input) {
  const RATE = 136;
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const padded = Array.from(bytes);
  padded.push(0x01);
  while (padded.length % RATE !== 0) padded.push(0);
  padded[padded.length - 1] |= 0x80;
  const st = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += RATE) {
    for (let i = 0; i < RATE / 8; i++) {
      let lane = 0n;
      for (let b = 7; b >= 0; b--) lane = (lane << 8n) | BigInt(padded[off + i * 8 + b]);
      st[i] ^= lane;
    }
    agKeccakF1600(st);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = st[i];
    for (let b = 0; b < 8; b++) { out[i * 8 + b] = Number(lane & 0xffn); lane >>= 8n; }
  }
  return out;
}

function agFunctionSelector(signature) {
  return "0x" + agBytesToHex(agKeccak256(agUtf8ToBytes(signature)).slice(0, 4));
}

/* --- ABI encoding (static argument types only: address, uint*, bool) --- */

function agIsValidAddress(a) {
  return typeof a === "string" && /^0x[0-9a-fA-F]{40}$/.test(a);
}

function agIsZeroAddress(a) {
  return typeof a === "string" && /^0x0{40}$/i.test(a);
}

function agEncodeWord(value) {
  let v = BigInt(value);
  if (v < 0n || v >= (1n << 256n)) throw new Error("uint out of range");
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

function agEncodeCall(signature, types, values) {
  if (types.length !== values.length) throw new Error("types/values length mismatch");
  const parts = [agHexToBytes(agFunctionSelector(signature))];
  for (let i = 0; i < types.length; i++) {
    const t = types[i], val = values[i];
    if (t === "address") {
      if (!agIsValidAddress(val)) throw new Error("invalid address argument");
      parts.push(agEncodeWord(BigInt(val)));
    } else if (t === "bool") {
      parts.push(agEncodeWord(val ? 1n : 0n));
    } else if (/^uint(8|16|32|64|128|256)?$/.test(t)) {
      parts.push(agEncodeWord(BigInt(val)));
    } else {
      throw new Error("unsupported argument type: " + t);
    }
  }
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return "0x" + agBytesToHex(out);
}

/* --- ABI decoding --- */

function agReadWord(bytes, off) {
  if (off < 0 || off + 32 > bytes.length) throw new Error("ABI data too short");
  let v = 0n;
  for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(bytes[off + i]);
  return v;
}

function agWordToAddress(bytes, off) {
  if (off < 0 || off + 32 > bytes.length) throw new Error("ABI data too short");
  return "0x" + agBytesToHex(bytes.slice(off + 12, off + 32));
}

function agWordToHex(bytes, off) {
  if (off < 0 || off + 32 > bytes.length) throw new Error("ABI data too short");
  return "0x" + agBytesToHex(bytes.slice(off, off + 32));
}

function agDecodeString(bytes, headOff) {
  const rel = Number(agReadWord(bytes, headOff));
  const start = rel; // offsets in top-level returns are absolute from data start
  const len = Number(agReadWord(bytes, start));
  if (start + 32 + len > bytes.length) throw new Error("ABI string out of bounds");
  return agBytesToUtf8(bytes.slice(start + 32, start + 32 + len));
}

function agDecodeStringInTuple(bytes, tupleStart, headOff) {
  const rel = Number(agReadWord(bytes, tupleStart + headOff));
  const start = tupleStart + rel;
  const len = Number(agReadWord(bytes, start));
  if (start + 32 + len > bytes.length) throw new Error("ABI string out of bounds");
  return agBytesToUtf8(bytes.slice(start + 32, start + 32 + len));
}

function agDecodeUint(data) {
  const bytes = typeof data === "string" ? agHexToBytes(data) : data;
  return agReadWord(bytes, 0);
}

function agDecodeBool(data) {
  return agDecodeUint(data) !== 0n;
}

/* check(address) -> (uint32 safeCount, uint32 cautionCount, uint32 dangerCount,
 *                   uint32 verdictCount, uint256 consensusScore, uint8 consensusStatus) */
function agDecodeCheck(data) {
  const bytes = typeof data === "string" ? agHexToBytes(data) : data;
  return {
    safeCount: Number(agReadWord(bytes, 0)),
    cautionCount: Number(agReadWord(bytes, 32)),
    dangerCount: Number(agReadWord(bytes, 64)),
    verdictCount: Number(agReadWord(bytes, 96)),
    consensusScore: Number(agReadWord(bytes, 128)),
    consensusStatus: Number(agReadWord(bytes, 160))
  };
}

/* getVerdict(address,address) -> (bool exists, uint8 status, uint8 score,
 *   bytes32 reportHash, string reportURI, uint64 updatedAt) */
function agDecodeGetVerdict(data) {
  const bytes = typeof data === "string" ? agHexToBytes(data) : data;
  return {
    exists: agReadWord(bytes, 0) !== 0n,
    status: Number(agReadWord(bytes, 32)),
    score: Number(agReadWord(bytes, 64)),
    reportHash: agWordToHex(bytes, 96),
    reportURI: agDecodeString(bytes, 128),
    updatedAt: Number(agReadWord(bytes, 160))
  };
}

/* auditorStats(address) -> (uint32 verdictCount, bool registered,
 *   string profileURI, uint64 registeredAt) */
function agDecodeAuditorStats(data) {
  const bytes = typeof data === "string" ? agHexToBytes(data) : data;
  return {
    verdictCount: Number(agReadWord(bytes, 0)),
    registered: agReadWord(bytes, 32) !== 0n,
    profileURI: agDecodeString(bytes, 64),
    registeredAt: Number(agReadWord(bytes, 96))
  };
}

/* listVerdicts(address,uint256,uint256) -> VerdictView[] where
 * VerdictView = (address auditor, uint8 status, uint8 score,
 *                bytes32 reportHash, string reportURI, uint64 updatedAt) */
function agDecodeListVerdicts(data) {
  const bytes = typeof data === "string" ? agHexToBytes(data) : data;
  const arrayStart = Number(agReadWord(bytes, 0));
  const len = Number(agReadWord(bytes, arrayStart));
  const headBase = arrayStart + 32;
  const items = [];
  for (let i = 0; i < len; i++) {
    const elStart = headBase + Number(agReadWord(bytes, headBase + i * 32));
    items.push({
      auditor: agWordToAddress(bytes, elStart),
      status: Number(agReadWord(bytes, elStart + 32)),
      score: Number(agReadWord(bytes, elStart + 64)),
      reportHash: agWordToHex(bytes, elStart + 96),
      reportURI: agDecodeStringInTuple(bytes, elStart, 128),
      updatedAt: Number(agReadWord(bytes, elStart + 160))
    });
  }
  return items;
}

// ===== AGENTGUARD-CODEC-END =====

/* ============================ RPC client ============================ */

let agRpcId = 0;

async function agRpcCall(method, params) {
  let lastError = null;
  for (const endpoint of CONFIG.rpcEndpoints) {
    const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer = controller ? setTimeout(() => controller.abort(), 12000) : null;
    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: ++agRpcId, method, params }),
        signal: controller ? controller.signal : undefined
      });
      if (timer) clearTimeout(timer);
      if (!res.ok) throw new Error("HTTP " + res.status);
      const json = await res.json();
      if (json.error) throw new Error(json.error.message || "RPC error");
      return json.result;
    } catch (e) {
      if (timer) clearTimeout(timer);
      lastError = e;
    }
  }
  throw lastError || new Error("All RPC endpoints failed");
}

async function agEthCall(dataHex) {
  return agRpcCall("eth_call", [{ to: CONFIG.contractAddress, data: dataHex }, "latest"]);
}

async function agCallCheck(target) {
  const data = agEncodeCall("check(address)", ["address"], [target]);
  return agDecodeCheck(await agEthCall(data));
}

async function agCallTargetAuditorCount(target) {
  const data = agEncodeCall("targetAuditorCount(address)", ["address"], [target]);
  return Number(agDecodeUint(await agEthCall(data)));
}

async function agCallListVerdicts(target, offset, limit) {
  const data = agEncodeCall(
    "listVerdicts(address,uint256,uint256)",
    ["address", "uint256", "uint256"],
    [target, BigInt(offset), BigInt(limit)]
  );
  return agDecodeListVerdicts(await agEthCall(data));
}

async function agCallAuditorStats(auditor) {
  const data = agEncodeCall("auditorStats(address)", ["address"], [auditor]);
  return agDecodeAuditorStats(await agEthCall(data));
}

async function agCallIsRegistered(agent) {
  const data = agEncodeCall("isRegistered(address)", ["address"], [agent]);
  return agDecodeBool(await agEthCall(data));
}

async function agCallTotalVerdicts() {
  const data = agEncodeCall("totalVerdicts()", [], []);
  return Number(agDecodeUint(await agEthCall(data)));
}

async function agCallTotalRegisteredAgents() {
  const data = agEncodeCall("totalRegisteredAgents()", [], []);
  return Number(agDecodeUint(await agEthCall(data)));
}

/* ============================ UI ============================ */

const AG_STATUS = {
  0: { label: "UNRATED", cls: "" },
  1: { label: "SAFE", cls: "badge-safe" },
  2: { label: "CAUTION", cls: "badge-caution" },
  3: { label: "DANGER", cls: "badge-danger" }
};

const agState = {
  target: null,
  totalAuditors: 0,
  offset: 0
};

function agEl(id) { return document.getElementById(id); }

function agShortenAddress(a) {
  return a && a.length > 14 ? a.slice(0, 8) + "…" + a.slice(-6) : a;
}

function agSafeUriHref(uri) {
  if (typeof uri !== "string") return null;
  const u = uri.trim();
  if (!u || /[\s"'<>]/.test(u)) return null;
  if (/^https?:\/\//i.test(u)) return u;
  if (/^ipfs:\/\//i.test(u)) {
    const rest = u.slice("ipfs://".length);
    if (!rest || /[\s"'<>]/.test(rest)) return null;
    return "https://ipfs.io/ipfs/" + rest;
  }
  return null;
}

function agFormatTime(unixSeconds) {
  if (!unixSeconds) return "";
  try {
    return new Date(unixSeconds * 1000).toLocaleString(undefined, {
      year: "numeric", month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit"
    });
  } catch (e) {
    return "";
  }
}

function agIsDeployed() {
  return agIsValidAddress(CONFIG.contractAddress) && !agIsZeroAddress(CONFIG.contractAddress);
}

function agShowPendingNotice(context) {
  const note = agEl("result-note");
  const card = agEl("check-result");
  card.hidden = false;
  agEl("result-badge").textContent = "PENDING";
  agEl("result-badge").className = "badge";
  agEl("result-address").textContent = context || "";
  agEl("result-score").textContent = "—";
  agEl("result-total").textContent = "—";
  agEl("result-safe").textContent = "—";
  agEl("result-caution").textContent = "—";
  agEl("result-danger").textContent = "—";
  agEl("verdict-explorer").hidden = true;
  note.textContent = "The AgentGuard contract is not deployed yet, so there is no live on-chain consensus to read. Once the deployment address is configured, this check reads the registry directly.";
}

async function agRunCheck(address) {
  const errorEl = agEl("check-error");
  errorEl.hidden = true;
  if (!agIsValidAddress(address)) {
    errorEl.textContent = "That does not look like a valid BNB Chain address (expected 0x followed by 40 hex characters).";
    errorEl.hidden = false;
    return;
  }
  const target = address.toLowerCase();
  if (location.hash !== "#check=" + target) {
    try { history.replaceState(null, "", "#check=" + target); } catch (e) { /* file:// */ }
  }
  if (!agIsDeployed()) { agShowPendingNotice(target); return; }

  const btn = agEl("check-button");
  btn.disabled = true;
  btn.textContent = "Checking…";
  try {
    const [summary, total] = await Promise.all([
      agCallCheck(target),
      agCallTargetAuditorCount(target)
    ]);
    agState.target = target;
    agState.totalAuditors = total;
    agState.offset = 0;
    agRenderResult(target, summary);
    if (summary.verdictCount > 0) {
      await agLoadVerdictPage(0);
    } else {
      agEl("verdict-explorer").hidden = true;
    }
  } catch (e) {
    errorEl.textContent = "Could not reach the BNB Chain RPC endpoints. Please try again in a moment.";
    errorEl.hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = "Check";
  }
}

function agRenderResult(target, s) {
  const card = agEl("check-result");
  card.hidden = false;
  const st = AG_STATUS[s.consensusStatus] || AG_STATUS[0];
  const badge = agEl("result-badge");
  badge.textContent = s.verdictCount === 0 ? "UNRATED" : st.label;
  badge.className = "badge" + (s.verdictCount === 0 ? "" : (st.cls ? " " + st.cls : ""));
  agEl("result-address").textContent = target;
  agEl("result-score").textContent = s.verdictCount === 0 ? "—" : String(s.consensusScore);
  agEl("result-total").textContent = String(s.verdictCount);
  agEl("result-safe").textContent = String(s.safeCount);
  agEl("result-caution").textContent = String(s.cautionCount);
  agEl("result-danger").textContent = String(s.dangerCount);
  agEl("result-note").textContent = s.verdictCount === 0
    ? "No verdicts yet — no Agent ID auditor has published a verdict for this contract. Treat it as unreviewed, not as safe."
    : "Consensus follows the registry rule: the status with the most active verdicts wins, ties break toward the more cautious status, and the score is the equal-weighted mean of all active verdict scores.";
}

async function agLoadVerdictPage(offset) {
  const listEl = agEl("verdict-list");
  const explorer = agEl("verdict-explorer");
  explorer.hidden = false;
  listEl.innerHTML = "";
  const loading = document.createElement("li");
  loading.className = "verdict-item";
  loading.textContent = "Loading verdicts…";
  listEl.appendChild(loading);
  try {
    const items = await agCallListVerdicts(agState.target, offset, CONFIG.pageSize);
    agState.offset = offset;
    agRenderVerdicts(items);
  } catch (e) {
    listEl.innerHTML = "";
    const li = document.createElement("li");
    li.className = "verdict-item";
    li.textContent = "Could not load the verdict list. Please try again.";
    listEl.appendChild(li);
  }
}

function agRenderVerdicts(items) {
  const listEl = agEl("verdict-list");
  listEl.innerHTML = "";
  for (const v of items) {
    const li = document.createElement("li");
    li.className = "verdict-item";

    const top = document.createElement("div");
    top.className = "verdict-top";

    const auditor = document.createElement("span");
    auditor.className = "verdict-auditor";
    auditor.textContent = agShortenAddress(v.auditor);
    auditor.title = v.auditor;
    top.appendChild(auditor);

    const st = AG_STATUS[v.status] || AG_STATUS[0];
    const status = document.createElement("span");
    status.className = "verdict-status " +
      (v.status === 1 ? "safe-text" : v.status === 2 ? "caution-text" : v.status === 3 ? "danger-text" : "");
    status.textContent = st.label;
    top.appendChild(status);

    const score = document.createElement("span");
    score.className = "verdict-score";
    score.textContent = "score " + v.score + "/100";
    top.appendChild(score);

    li.appendChild(top);

    const meta = document.createElement("div");
    meta.className = "verdict-meta";
    const parts = [];
    const when = agFormatTime(v.updatedAt);
    if (when) parts.push("updated " + when);
    if (v.reportHash && !/^0x0{64}$/.test(v.reportHash)) parts.push("report hash " + v.reportHash.slice(0, 18) + "…");
    meta.textContent = parts.join(" · ");
    li.appendChild(meta);

    if (v.reportURI) {
      const reportLine = document.createElement("div");
      reportLine.className = "verdict-meta";
      const href = agSafeUriHref(v.reportURI);
      if (href) {
        const a = document.createElement("a");
        a.href = href;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.textContent = "Audit report: " + v.reportURI;
        reportLine.appendChild(a);
      } else {
        reportLine.textContent = "Audit report: " + v.reportURI;
      }
      li.appendChild(reportLine);
    }

    listEl.appendChild(li);
  }

  const total = agState.totalAuditors;
  const from = total === 0 ? 0 : agState.offset + 1;
  const to = Math.min(agState.offset + items.length, total);
  agEl("page-info").textContent = total === 0 ? "" : "Verdicts " + from + "–" + to + " of " + total;
  agEl("page-prev").disabled = agState.offset <= 0;
  agEl("page-next").disabled = agState.offset + items.length >= total;
}

function agRenderSeeded() {
  const grid = agEl("seed-grid");
  if (!grid) return;
  for (const t of CONFIG.seededTargets) {
    const card = document.createElement("article");
    card.className = "seed-card";

    const name = document.createElement("div");
    name.className = "seed-name";
    name.textContent = t.name;
    card.appendChild(name);

    const addr = document.createElement("div");
    addr.className = "seed-address";
    addr.textContent = t.address;
    addr.title = t.address;
    card.appendChild(addr);

    const chip = document.createElement("span");
    chip.className = "chip chip-" + t.tone;
    chip.textContent = t.chip;
    card.appendChild(chip);

    const record = document.createElement("p");
    record.className = "seed-record";
    record.textContent = t.record;
    card.appendChild(record);

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "seed-check-btn";
    btn.textContent = "Check on AgentGuard";
    btn.addEventListener("click", () => {
      agEl("check-input").value = t.address;
      document.getElementById("check").scrollIntoView({ behavior: "smooth" });
      agRunCheck(t.address);
    });
    card.appendChild(btn);

    grid.appendChild(card);
  }
}

async function agRunAuditorLookup(address) {
  const errorEl = agEl("auditor-error");
  const resultEl = agEl("auditor-result");
  errorEl.hidden = true;
  resultEl.hidden = true;
  if (!agIsValidAddress(address)) {
    errorEl.textContent = "Enter a valid address (0x followed by 40 hex characters).";
    errorEl.hidden = false;
    return;
  }
  if (!agIsDeployed()) {
    errorEl.textContent = "The AgentGuard contract is not deployed yet — auditor lookups activate with deployment.";
    errorEl.hidden = false;
    return;
  }
  try {
    const [stats, registered] = await Promise.all([
      agCallAuditorStats(address.toLowerCase()),
      agCallIsRegistered(address.toLowerCase())
    ]);
    agEl("auditor-count").textContent = String(stats.verdictCount);
    agEl("auditor-registered").textContent = registered || stats.registered ? "yes" : "no";
    const profileRow = agEl("auditor-profile-row");
    const profileEl = agEl("auditor-profile");
    profileEl.textContent = "";
    if (stats.profileURI) {
      const href = agSafeUriHref(stats.profileURI);
      if (href) {
        const a = document.createElement("a");
        a.href = href;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.textContent = stats.profileURI;
        profileEl.appendChild(a);
      } else {
        profileEl.textContent = stats.profileURI;
      }
      profileRow.hidden = false;
    } else {
      profileRow.hidden = true;
    }
    resultEl.hidden = false;
  } catch (e) {
    errorEl.textContent = "Could not reach the BNB Chain RPC endpoints. Please try again in a moment.";
    errorEl.hidden = false;
  }
}

function agInitCopyButtons() {
  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const target = document.getElementById(btn.getAttribute("data-copy-target"));
      if (!target) return;
      const text = target.innerText;
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = "Copied";
      } catch (e) {
        const range = document.createRange();
        range.selectNodeContents(target);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        btn.textContent = "Selected";
      }
      setTimeout(() => { btn.textContent = "Copy"; }, 1600);
    });
  });
}

async function agLoadGlobalStats() {
  try {
    const [verdicts, agents] = await Promise.all([
      agCallTotalVerdicts(),
      agCallTotalRegisteredAgents()
    ]);
    agEl("stat-verdicts").textContent = String(verdicts);
    agEl("stat-agents").textContent = String(agents);
  } catch (e) {
    // Leave the placeholders as-is; stats are informational only.
  }
}

function agInit() {
  agRenderSeeded();
  agInitCopyButtons();

  const deployed = agIsDeployed();
  agEl("footer-contract").textContent = deployed ? CONFIG.contractAddress : "deployment pending";
  if (!deployed) {
    agEl("pending-banner").hidden = false;
  } else {
    agLoadGlobalStats();
  }

  agEl("check-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    agRunCheck(agEl("check-input").value.trim());
  });

  agEl("page-prev").addEventListener("click", () => {
    const next = Math.max(0, agState.offset - CONFIG.pageSize);
    if (agState.target) agLoadVerdictPage(next);
  });
  agEl("page-next").addEventListener("click", () => {
    const next = agState.offset + CONFIG.pageSize;
    if (agState.target && next < agState.totalAuditors) agLoadVerdictPage(next);
  });

  agEl("auditor-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    agRunAuditorLookup(agEl("auditor-input").value.trim());
  });

  // Deep link: #check=0x...
  const m = /#check=(0x[0-9a-fA-F]{40})/.exec(location.hash || "");
  if (m) {
    agEl("check-input").value = m[1];
    agRunCheck(m[1]);
  }
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", agInit);
  } else {
    agInit();
  }
}

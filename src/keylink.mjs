// agentwork key-link v1 (agentwork docs/KEYLINK.md): canonical record, cid, Ed25519 role signatures.
import { createHash, randomBytes } from "node:crypto";
import { publicFromDid, signEd25519, verifyEd25519, ss58 } from "./keys.mjs";

const DOMAIN = "agentwork-keylink/1|";
export const NETS = { "flop-devnet": "0x99c172c095340ace980631f9123544c6bebd4839f3437e463533422d8be2d631" };

/** Python json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True) */
export function canonical(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") { if (!Number.isInteger(v)) throw new Error("floats are not allowed"); return String(v); }
  if (typeof v === "string") return JSON.stringify(v).replace(/[\u007f-\uffff]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => canonical(k) + ":" + canonical(v[k])).join(",") + "}";
}
export const recordCid = (r) => "0x" + createHash("sha256").update(DOMAIN + canonical(r), "ascii").digest("hex");
export const sigMessage = (role, cid) => Buffer.from(`${DOMAIN}sig|${role}|${cid}`, "ascii");
const b64u = (b) => Buffer.from(b).toString("base64url");

export const IMD_SEAT_COLLECTION = "0x0000ec93127baa929e58e97dd0095a2bfb38ec1d"; // identity.md seats, Ethereum (chain 1)

/** Path A record: the agent's did:key IS its FLOP account. With `seat`, it also names the IMD seat + device
 *  (agentwork requires the seat holder's EVM signature and the device's signature for that; Manna signs neither). */
export function makeRecord({ did, net = "flop-devnet", seat, issued = Date.now(), expires, nonce = randomBytes(8).toString("hex") }) {
  const pk = publicFromDid(did);
  const r = { v: "agentwork.keylink/1", did, flop: { account: "0x" + pk.toString("hex"), scheme: "ed25519", net }, issued, nonce };
  if (NETS[net]) r.flop.genesis = NETS[net];
  if (expires) r.expires = expires;
  if (seat) {
    const addr = /^0x[0-9a-f]{40}$/;
    for (const k of ["collection", "identityRegistry", "evm"]) if (!addr.test(seat[k] || "")) throw new Error(`seat.${k} must be lowercase 0x + 40 hex`);
    if (!/^[0-9]+$/.test(String(seat.tokenId)) || !/^[0-9]+$/.test(String(seat.agentId))) throw new Error("seat.tokenId/agentId must be decimal");
    if (seat.device && !/^[0-9a-f]{64}$/.test(seat.device)) throw new Error("seat.device must be 64 lowercase hex (IMD deviceKey)");
    r.imd = { chainId: seat.chainId ?? 1, collection: seat.collection, tokenId: String(seat.tokenId), agentId: String(seat.agentId), identityRegistry: seat.identityRegistry };
    if (seat.device) r.imd.device = seat.device;
    r.evm = { address: seat.evm };
  }
  return r;
}

/** EIP-191 text the seat holder signs (identical to agentwork keylink.evm_text). */
export function evmText(r, cid) {
  const lines = ["agentwork key-link v1", "I link the identities below. This moves no funds and grants no spending rights.",
    `cid: ${cid}`, `did: ${r.did}`, `flop: ${ss58(Buffer.from(r.flop.account.slice(2), "hex"))} (${r.flop.scheme}, ${r.flop.net})`];
  if (r.imd) lines.push(`imd seat: chain ${r.imd.chainId} collection ${r.imd.collection} token ${r.imd.tokenId} agent ${r.imd.agentId}`);
  lines.push(`evm: ${r.evm.address}`, `issued: ${r.issued}`);
  return lines.join("\n");
}

export function signDid(record, seed) {
  const cid = recordCid(record);
  return { cid, sig: b64u(signEd25519(seed, sigMessage("did", cid))) };
}

/** Verify the Ed25519 roles (did, flop-ed25519, device). EVM and sr25519 roles are reported as unchecked. */
export function verifyEd25519Roles(doc) {
  const r = doc.record, sigs = doc.sigs || {};
  const cid = recordCid(r);
  const res = { cid, checked: [], unchecked: [], errors: [] };
  const need = ["did"];
  const flopPk = r.flop?.account?.slice(2);
  const didPk = publicFromDid(r.did).toString("hex");
  if (r.flop?.scheme === "sr25519" || flopPk !== didPk) need.push("flop");
  if (r.imd?.device) need.push("device");
  if (r.evm) need.push("evm");
  for (const role of need) {
    const s = sigs[role];
    if (!s) { res.errors.push(`missing ${role} signature`); continue; }
    if (role === "evm" || (role === "flop" && r.flop.scheme !== "ed25519")) { res.unchecked.push(role); continue; }
    const pk = role === "did" ? Buffer.from(didPk, "hex") : role === "flop" ? Buffer.from(flopPk, "hex") : Buffer.from(r.imd.device, "hex");
    const raw = role === "did" ? Buffer.from(s, "base64url") : Buffer.from(s.replace(/^0x/, ""), "hex");
    if (verifyEd25519(pk, sigMessage(role, cid), raw)) res.checked.push(role); else res.errors.push(`${role} signature does not verify`);
  }
  res.ok = res.errors.length === 0;
  res.ss58 = flopPk ? ss58(Buffer.from(flopPk, "hex")) : null;
  return res;
}

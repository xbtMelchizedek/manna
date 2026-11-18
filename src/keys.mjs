// Ed25519 identity: seed -> public key -> did:key + FLOP AccountId32 + SS58 (prefix 42).
// node:crypto only. Seeds live in mode-600 files and are never printed.
import { createHash, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function b58encode(buf) {
  let n = BigInt("0x" + (Buffer.from(buf).toString("hex") || "0"));
  let out = "";
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of buf) { if (b === 0) out = "1" + out; else break; }
  return out;
}
export function b58decode(s) {
  let n = 0n;
  for (const c of s) { const i = B58.indexOf(c); if (i < 0) throw new Error("bad base58"); n = n * 58n + BigInt(i); }
  let hex = n.toString(16); if (hex.length % 2) hex = "0" + hex; if (n === 0n) hex = "";
  const lead = s.length - s.replace(/^1+/, "").length;
  return Buffer.concat([Buffer.alloc(lead), Buffer.from(hex, "hex")]);
}

const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");
const priv = (seed) => createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: "der", type: "pkcs8" });
const pubk = (pk) => createPublicKey({ key: Buffer.concat([SPKI_ED25519, pk]), format: "der", type: "spki" });

export function publicFromSeed(seed) {
  return createPublicKey(priv(seed)).export({ format: "der", type: "spki" }).subarray(-32);
}
export const signEd25519 = (seed, msg) => edSign(null, Buffer.from(msg), priv(seed));
export const verifyEd25519 = (pk, msg, sig) => { try { return edVerify(null, Buffer.from(msg), pubk(Buffer.from(pk)), Buffer.from(sig)); } catch { return false; } };

export function didFromPublic(pk) { return "did:key:z" + b58encode(Buffer.concat([Buffer.from([0xed, 0x01]), Buffer.from(pk)])); }
export function publicFromDid(did) {
  if (!did.startsWith("did:key:z")) throw new Error("not a did:key");
  const b = b58decode(did.slice(9));
  if (b[0] !== 0xed || b[1] !== 0x01 || b.length !== 34) throw new Error("not an Ed25519 did:key");
  return b.subarray(2);
}
export function ss58(pk, prefix = 42) {
  const payload = Buffer.concat([Buffer.from([prefix]), Buffer.from(pk)]);
  const h = createHash("blake2b512").update(Buffer.concat([Buffer.from("SS58PRE"), payload])).digest();
  return b58encode(Buffer.concat([payload, h.subarray(0, 2)]));
}
export function identityFromPublic(pk) {
  return { did: didFromPublic(pk), account_id32: "0x" + Buffer.from(pk).toString("hex"), ss58: ss58(pk), scheme: "ed25519" };
}

/** Create (or load) the agent's own FLOP key: a separate Ed25519 seed, NOT the IMD device key (KEYLINK.md §2). */
export function loadOrCreateSeed(path) {
  if (existsSync(path)) {
    const st = statSync(path);
    if ((st.mode & 0o077) !== 0) throw new Error(`${path} must be mode 600 (run: chmod 600 ${path})`);
    const hex = readFileSync(path, "utf8").trim();
    if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`${path} is not a 64-hex seed`);
    return { seed: Buffer.from(hex, "hex"), created: false };
  }
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const seed = randomBytes(32);
  writeFileSync(path, seed.toString("hex") + "\n", { mode: 0o600 });
  chmodSync(path, 0o600);
  return { seed, created: true };
}

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { identityFromPublic, publicFromSeed, ss58, didFromPublic, publicFromDid, loadOrCreateSeed } from "../src/keys.mjs";
import { canonical, recordCid, makeRecord, signDid, verifyEd25519Roles, evmText } from "../src/keylink.mjs";
import { readDeviceKey } from "../src/imd.mjs";
import { SpendGuard, MockFlopCompute, buyModelCall } from "../src/compute.mjs";

const V = JSON.parse(readFileSync(new URL("../fixtures/keylink-v1.json", import.meta.url)));
const testSeed = (label) => createHash("sha256").update("agentwork public test key: " + label).digest();

test("path A vectors: did:key, AccountId32, SS58 match agentwork", () => {
  for (const p of V.path_a) {
    const id = identityFromPublic(publicFromSeed(testSeed(p.key_label)));
    assert.equal(id.did, p.did);
    assert.equal(id.account_id32, p.account_id32);
    assert.equal(id.ss58, p.ss58);
    assert.equal(publicFromDid(p.did).toString("hex"), p.ed25519_pub_hex);
  }
});

test("SS58 Substrate dev-key sanity vector", () => {
  assert.equal(ss58(Buffer.from(V.ss58_sanity.pub_hex, "hex")), V.ss58_sanity.ss58);
});

test("canonical + cid match agentwork for every valid and invalid vector", () => {
  for (const v of [...V.valid, ...V.invalid]) if (v.cid) assert.equal(recordCid(v.doc.record), v.cid, v.name);
  assert.equal(canonical({ b: 1, a: "é" }), '{"a":"\\u00e9","b":1}');
  assert.throws(() => canonical({ x: 1.5 }));
});

test("Ed25519 role signatures: valid vectors verify, tampered ones fail", () => {
  for (const v of V.valid) {
    const r = verifyEd25519Roles(v.doc);
    assert.equal(r.ok, true, `${v.name}: ${r.errors}`);
    if (v.doc.sigs.evm) assert.deepEqual(r.unchecked, ["evm"]);
  }
  for (const name of ["tampered-after-signing", "role-swap-replay", "path-b-missing-flop-sig"]) {
    const v = V.invalid.find((x) => x.name === name);
    assert.equal(verifyEd25519Roles(v.doc).ok, false, name);
  }
});

test("EVM text matches agentwork for the seat vector", () => {
  const v = V.valid.find((x) => x.doc.record.evm);
  assert.equal(evmText(v.doc.record, v.cid), v.evm_text);
});

test("makeRecord + signDid round-trip (path A, and seat link lists pending signers)", () => {
  const seed = testSeed("manna-test");
  const did = didFromPublic(publicFromSeed(seed));
  const r = makeRecord({ did, issued: 1795000000000, nonce: "00000000000000aa" });
  const { sig } = signDid(r, seed);
  assert.equal(verifyEd25519Roles({ record: r, sigs: { did: sig } }).ok, true);
  const seat = { collection: "0x0000ec93127baa929e58e97dd0095a2bfb38ec1d", identityRegistry: "0x" + "11".repeat(20), tokenId: "42", agentId: "7", evm: "0x" + "22".repeat(20), device: "ab".repeat(32) };
  const r2 = makeRecord({ did, seat, issued: 1795000000000, nonce: "00000000000000ab" });
  const res = verifyEd25519Roles({ record: r2, sigs: { did: signDid(r2, seed).sig } });
  assert.equal(res.ok, false);
  assert.deepEqual(res.errors.sort(), ["missing device signature", "missing evm signature"]);
  assert.throws(() => makeRecord({ did, seat: { ...seat, evm: "0xABC" } }));
});

test("seed file is created mode 600 and refused when group/world readable", () => {
  const d = mkdtempSync(join(tmpdir(), "manna-"));
  const f = join(d, "k", "seed");
  const { created } = loadOrCreateSeed(f);
  assert.equal(created, true);
  assert.equal(statSync(f).mode & 0o777, 0o600);
  assert.equal(loadOrCreateSeed(f).created, false);
  writeFileSync(f, "00".repeat(32), { mode: 0o644 });
  execFileSync("chmod", ["644", f]);
  assert.throws(() => loadOrCreateSeed(f), /mode 600/);
});

test("IMD config: reads only the public deviceKey", () => {
  const d = mkdtempSync(join(tmpdir(), "imd-"));
  writeFileSync(join(d, "config.json"), JSON.stringify({ deviceKey: "cd".repeat(32), devicePrivateKey: "SECRET-DO-NOT-READ", wallet: "0x" + "33".repeat(20) }));
  const r = readDeviceKey(join(d, "config.json"));
  assert.equal(r.deviceKey, "cd".repeat(32));
  assert.equal(JSON.stringify(r).includes("SECRET"), false);
});

test("CLI never prints the seed", () => {
  const d = mkdtempSync(join(tmpdir(), "manna-cli-"));
  const env = { ...process.env, MANNA_HOME: d, IDENTITYMD_HOME: join(d, "noimd") };
  const o = execFileSync("node", [new URL("../bin/manna.mjs", import.meta.url).pathname, "init"], { env }).toString();
  const seed = readFileSync(join(d, "agent.ed25519.seed"), "utf8").trim();
  assert.equal(o.includes(seed), false);
  const j = JSON.parse(o);
  assert.match(j.ss58, /^5[1-9A-HJ-NP-Za-km-z]{47}$/);
  const w = JSON.parse(execFileSync("node", [new URL("../bin/manna.mjs", import.meta.url).pathname, "link"], { env }).toString());
  assert.equal(verifyEd25519Roles(w.doc).ok, true);
});

test("spend guard: devnet refused, caps enforced, live backend refused", async () => {
  const g = new SpendGuard();
  const be = new MockFlopCompute();
  assert.match((await buyModelCall({ backend: be, guard: g, net: "flop-devnet", model: "m", prompt: "hi", maxFlop: "0.01" })).refused, /not allowed/);
  assert.match((await buyModelCall({ backend: be, guard: g, net: "flop-testnet", model: "m", prompt: "hi", maxFlop: "0.5" })).refused, /call cap/);
  for (let i = 0; i < 50; i++) await buyModelCall({ backend: be, guard: g, net: "flop-testnet", model: "m", prompt: "hi", maxFlop: "0.01" });
  assert.match((await buyModelCall({ backend: be, guard: g, net: "flop-testnet", model: "m", prompt: "hi", maxFlop: "0.01" })).refused, /daily cap/);
  assert.match((await buyModelCall({ backend: {}, guard: new SpendGuard(), net: "flop-testnet", model: "m", prompt: "x", maxFlop: "0.01" })).refused, /not available/);
});

test("live devnet read (MANNA_LIVE=1)", { skip: process.env.MANNA_LIVE !== "1" }, async () => {
  const { connect, balance, agents } = await import("../src/chain.mjs");
  const api = await connect("flop-devnet");
  try {
    const b = await balance(api, "5CMBVyvH7ueNprajtTdKTqLLyNo2bjqndvPbrTYoBmmAhpJz");
    assert.ok(BigInt(b.free) >= 0n);
    const a = await agents(api, "5CMBVyvH7ueNprajtTdKTqLLyNo2bjqndvPbrTYoBmmAhpJz");
    assert.ok(Array.isArray(a));
  } finally { await api.disconnect(); }
});

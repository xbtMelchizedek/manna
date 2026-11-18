#!/usr/bin/env node
// manna: FLOP identity + read-only FLOP devnet access for IMD swarm agents.
//   manna init                       create the agent's own Ed25519 FLOP key (mode 600) and print its identity
//   manna whoami                     print did:key, AccountId32, SS58 (and the IMD device key if present)
//   manna link [--seat k=v,...]      build + did-sign a key-link record; print what else must sign (device, evm)
//   manna verify-link <file.json>    verify a key-link document's Ed25519 signatures offline
//   manna balance [ss58]             FLOP devnet balance (read-only)
//   manna agents [ss58]              FLOP devnet AgentIdentity records owned by the account (read-only)
//   manna receipts [ss58]            FLOP devnet compute-channel receipts where the account is the agent (read-only)
//   manna compute-status             whether buying model calls on FLOP is possible yet (it is not; read-only)
import { readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { identityFromPublic, loadOrCreateSeed, publicFromSeed, b58decode } from "../src/keys.mjs";
import { makeRecord, signDid, verifyEd25519Roles, evmText, recordCid, sigMessage } from "../src/keylink.mjs";
import { readDeviceKey } from "../src/imd.mjs";

const HOME = process.env.MANNA_HOME ?? join(homedir(), ".manna");
const SEED = join(HOME, "agent.ed25519.seed");
const [cmd, ...rest] = process.argv.slice(2);
const out = (o) => console.log(JSON.stringify(o, null, 1));
const device = () => { try { return readDeviceKey().deviceKey; } catch { return null; } };
const me = () => identityFromPublic(publicFromSeed(loadOrCreateSeed(SEED).seed));
const target = (a) => a ?? me().ss58;
const accountHex = (ss) => "0x" + b58decode(ss).subarray(1, 33).toString("hex");

async function withApi(fn) {
  const { connect } = await import("../src/chain.mjs");
  const api = await connect("flop-devnet");
  try { return await fn(api); } finally { await api.disconnect(); }
}

switch (cmd) {
  case "init": { const { created } = loadOrCreateSeed(SEED); out({ created, seed_file: SEED, ...me(), imd_device: device() }); break; }
  case "whoami": out({ ...me(), imd_device: device(), note: "the FLOP key is separate from the IMD device key (agentwork KEYLINK.md §2)" }); break;
  case "link": {
    const i = rest.indexOf("--seat");
    const seat = i >= 0 ? Object.fromEntries(rest[i + 1].split(",").map((kv) => kv.split("="))) : null;
    if (seat && !seat.device && device()) seat.device = device();
    if (seat?.chainId) seat.chainId = Number(seat.chainId);
    const { seed } = loadOrCreateSeed(SEED);
    const r = makeRecord({ did: me().did, seat });
    const { cid, sig } = signDid(r, seed);
    const doc = { record: r, sigs: { did: sig } };
    const pending = {};
    if (r.imd?.device) pending.device = { signs_hex: sigMessage("device", cid).toString("hex"), encoding: "0x + 128 hex Ed25519 by the IMD device key" };
    if (r.evm) pending.evm = { eip191_text: evmText(r, cid), by: r.evm.address };
    const f = join(HOME, `keylink-${cid.slice(2, 14)}.json`);
    writeFileSync(f, JSON.stringify(doc, null, 1));
    out({ cid, file: f, doc, pending_signatures: pending });
    break;
  }
  case "verify-link": { const doc = JSON.parse(readFileSync(rest[0], "utf8")); out(verifyEd25519Roles(doc)); break; }
  case "balance": { const a = target(rest[0]); out({ account: a, ...(await withApi((api) => import("../src/chain.mjs").then((c) => c.balance(api, a)))) }); break; }
  case "agents": { const a = target(rest[0]); out({ account: a, agents: await withApi((api) => import("../src/chain.mjs").then((c) => c.agents(api, a))) }); break; }
  case "receipts": { const a = target(rest[0]); out({ account: a, ...(await withApi((api) => import("../src/chain.mjs").then((c) => c.receipts(api, accountHex(a))))) }); break; }
  case "compute-status": out({ live: false, reason: "no public agent-credited paid-inference route on FLOP devnet (2026-11-18). The mock backend and spend guard are in src/compute.mjs; the live backend ships after FLOP testnet (target Nov 24) documents session offers.", spend_policy_default: (await import("../src/compute.mjs")).DEFAULT_SPEND_POLICY }); break;
  default: console.error(readFileSync(new URL(import.meta.url)).toString().split("\n").slice(1, 10).join("\n")); process.exit(cmd ? 2 : 0);
}
process.exit(0);

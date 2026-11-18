// Read-only FLOP devnet queries. No extrinsics are built or signed here.
import { ApiPromise, WsProvider } from "@polkadot/api";
import { NETS } from "./keylink.mjs";

export const RPC = { "flop-devnet": "wss://rpc.devnet.flop.network" };

export async function connect(net = "flop-devnet", url = RPC[net]) {
  if (!NETS[net]) throw new Error(`unknown or unsupported network ${net} (devnet only for now)`);
  const api = await ApiPromise.create({ provider: new WsProvider(url), noInitWarn: true });
  if (api.genesisHash.toHex() !== NETS[net]) { await api.disconnect(); throw new Error(`genesis mismatch for ${net}`); }
  return api;
}

export const fmtFlop = (planck) => { const s = BigInt(planck).toString().padStart(19, "0"); return `${s.slice(0, -18)}.${s.slice(-18, -15)}`; };

export async function balance(api, ss58) {
  const { data, nonce } = await api.query.system.account(ss58);
  return { free: data.free.toString(), reserved: data.reserved.toString(), frozen: data.frozen.toString(),
    free_flop: fmtFlop(data.free.toString()), nonce: nonce.toNumber() };
}

export async function agents(api, ss58) {
  const ids = (await api.query.agentIdentity.agentsByOwner(ss58)).toJSON() || [];
  const out = [];
  for (const id of ids) { const a = (await api.query.agentIdentity.agents(id)).toHuman(); out.push({ agentId: id, name: a?.name, status: a?.status, agentType: a?.agentType }); }
  return out;
}

/** Compute-channel receipts where this account is the paying agent (scan capped by `limit` entries). */
export async function receipts(api, accountHex, { limit = 1000 } = {}) {
  const want = accountHex.toLowerCase();
  const found = [];
  let scanned = 0, startKey;
  while (scanned < limit) {
    const page = await api.query.computeChannel.channels.entriesPaged({ args: [], pageSize: 200, startKey });
    if (!page.length) break;
    for (const [k, v] of page) {
      scanned++;
      const c = v.toJSON();
      if (c && String(c.agent).toLowerCase() === want) {
        const id = k.args[0].toHex();
        const settled = (await api.query.computeChannel.settledTurns(id)).toJSON();
        found.push({ channel: id, miner: c.miner, modelHash: c.modelHash, settledTurns: settled });
      }
    }
    startKey = page[page.length - 1][0].toHex();
    if (page.length < 200) break;
  }
  return { scanned, truncated: scanned >= limit, channels: found };
}

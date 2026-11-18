// Buying model calls on FLOP: interface + spend policy. The live backend is OFF until FLOP testnet exposes an
// agent-credited paid-inference route (none on devnet as of 2026-11-18; see README). Only the mock backend runs.
export const DEFAULT_SPEND_POLICY = { maxFlopPerCall: "0.01", maxFlopPerDay: "0.25", allowNets: ["flop-testnet"], expiresHours: 24 };

const toPlanck = (s) => { const [i, f = ""] = String(s).split("."); return BigInt(i) * 10n ** 18n + BigInt((f + "0".repeat(18)).slice(0, 18)); };

export class SpendGuard {
  constructor(policy = DEFAULT_SPEND_POLICY, now = () => Date.now()) {
    this.p = { ...DEFAULT_SPEND_POLICY, ...policy }; this.now = now; this.spent = []; this.start = now();
  }
  check({ net, maxFlop }) {
    if (!this.p.allowNets.includes(net)) return `network ${net} is not allowed by the spend policy`;
    if (this.now() - this.start > this.p.expiresHours * 3600e3) return "spend policy expired; re-approve";
    const want = toPlanck(maxFlop);
    if (want > toPlanck(this.p.maxFlopPerCall)) return `call cap ${maxFlop} > ${this.p.maxFlopPerCall} FLOP`;
    const day = this.spent.filter((s) => this.now() - s.t < 86400e3).reduce((a, s) => a + s.planck, 0n);
    if (day + want > toPlanck(this.p.maxFlopPerDay)) return `daily cap ${this.p.maxFlopPerDay} FLOP would be exceeded`;
    return null;
  }
  record(planck) { this.spent.push({ t: this.now(), planck: BigInt(planck) }); }
}

/** Mock backend: deterministic, no network. Shape mirrors what a FLOP session receipt needs to carry. */
export class MockFlopCompute {
  constructor() { this.n = 0; }
  async call({ model, prompt, maxFlop }) {
    this.n++;
    const costPlanck = toPlanck(maxFlop) / 2n;
    return { output: `[mock:${model}] ${prompt.slice(0, 40)}`, receipt: { channel: "0x" + String(this.n).padStart(64, "0"), costPlanck: costPlanck.toString(), settled: false, backend: "mock" } };
  }
}

export async function buyModelCall({ backend, guard, net, model, prompt, maxFlop }) {
  const why = guard.check({ net, maxFlop });
  if (why) return { ok: false, refused: why };
  if (!(backend instanceof MockFlopCompute)) return { ok: false, refused: "live FLOP compute backend is not available yet" };
  const r = await backend.call({ model, prompt, maxFlop });
  guard.record(r.receipt.costPlanck);
  return { ok: true, ...r };
}

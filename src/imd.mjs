// Read the IMD worker's PUBLIC device key from its config (~/.identitymd/config.json or $IDENTITYMD_HOME).
// Manna never reads, copies or prints `devicePrivateKey`.
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export function imdConfigPath(env = process.env) { return join(env.IDENTITYMD_HOME ?? join(homedir(), ".identitymd"), "config.json"); }

export function readDeviceKey(path = imdConfigPath()) {
  const cfg = JSON.parse(readFileSync(path, "utf8"));
  const k = cfg.deviceKey;
  if (typeof k !== "string" || !/^[0-9a-f]{64}$/.test(k)) throw new Error("IMD config has no 64-hex deviceKey");
  return { deviceKey: k, wallet: typeof cfg.wallet === "string" ? cfg.wallet : null, tokenId: cfg.tokenId ?? null };
}

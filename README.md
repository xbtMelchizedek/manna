# Manna

Gives identity.md (IMD) swarm agents a **FLOP identity** and **read-only FLOP devnet access**:

- one Ed25519 key per agent. It is the agent's FLOP `AccountId32`/SS58 and also its `did:key`.
- key-link records (agentwork key-link v1) that tie the FLOP key to an IMD seat. The seat holder
  co-signs them.
- reads FLOP devnet balances, `AgentIdentity` records and compute-channel receipts.
- a spend guard and a mock backend for buying model calls on FLOP. The live backend stays off until
  FLOP documents a paid-inference route agents can use (target: testnet, Nov 24 2026).

It ships as a Node CLI (`manna`) and an IMD reference skill
(`skills/flop-agent-identity/SKILL.md`, which passes the identitymd-skill-crafting
`check-skill.mjs` validator).

Status: **M1** (2026-11-18). Devnet only. Nothing here moves funds.

## Use

```bash
npm ci
export MANNA_HOME=~/.manna             # seed file lives here, mode 600
node bin/manna.mjs init                # new agent key (never the IMD device key)
node bin/manna.mjs whoami              # did:key, AccountId32, SS58, IMD device pubkey if present
node bin/manna.mjs link --seat chainId=8453,collection=0x0000ec93…,tokenId=…,agentId=…,identityRegistry=0x…,evm=0x…
node bin/manna.mjs verify-link link.json
node bin/manna.mjs balance             # or: balance <ss58>
node bin/manna.mjs agents
node bin/manna.mjs receipts            # scans up to 1000 channels; output says when it truncated
node bin/manna.mjs compute-status
```

`link` signs only the `did` role, with the agent's key. It prints the EIP-191 text and the
device-signing message. The seat holder signs those with their own wallet and device. Manna never
asks for those keys.

The IMD worker config (`$IDENTITYMD_HOME/config.json` or `~/.identitymd/config.json`) is read for
the **public** `deviceKey` only. `devicePrivateKey` is never read.

## Tests

`npm test` runs 10 offline tests, including the agentwork key-link v1 vectors (canonical bytes, CIDs,
did/device signatures, tamper failures) and seed-file permission checks. The CLI never prints the
seed, and the spend guard refuses non-testnet networks, over-cap spends and the live backend.
`MANNA_LIVE=1 npm test` adds a read-only devnet read. It passed on 2026-11-18.

## Threat model

- **Key separation.** The agent key is not the IMD device key, and the device key is not a
  wallet. Linking happens through signed records, not shared secrets.
- **Seed at rest.** The seed is a 32-byte (hex) file in `MANNA_HOME`, created with mode 600. Manna
  refuses to load it if group or other users can read it. It is not encrypted. Use disk
  encryption or a secrets manager on a shared host.
- **Network pinning.** Every chain read checks the devnet genesis hash first and refuses any
  other chain. There is no mainnet code path.
- **Spending.** `buyModelCall` goes through `SpendGuard`. Defaults: max 0.01 FLOP per call,
  0.25 per day, testnet only. The live backend throws. Raising the caps belongs to the owner, not
  the agent.
- **Link forgery.** A link that names an IMD seat is invalid without the seat holder's EVM
  signature. `verify-link` checks the Ed25519 roles offline. EVM verification is left to the
  verifier's EVM library.
- **Not covered:** a compromised host, RPC lies (reads are not proofs), and IMD protocol
  security.

## License

MIT. Key-link spec and vectors: xbtMelchizedek/agentwork (`docs/KEYLINK.md`, Apache-2.0,
fixture reused with attribution).

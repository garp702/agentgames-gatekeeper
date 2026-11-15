// Probe the official gatekeeper circuit's semantics with snarkjs fullProve.
// Questions answered empirically (the circuit is the referee):
//  1. Public-signal order of a successful proof.
//  2. Is public[0] == Poseidon(salt, taskId)? (commitment hypothesis)
//  3. Boundary semantics: balance==minimum? amount==cap? current==expiry?
//  4. For every trap: decision=1 refused, decision=0 provable (and vice versa
//     for the valid case). Proof time + size + local verification.
const path = require("path");
const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");

const WASM = path.join(__dirname, "..", "circuits", "gatekeeper.wasm");
const ZKEY = path.join(__dirname, "..", "circuits", "gatekeeper_final.zkey");
const VK = require("../circuits/verification_key.json");

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const field = (hexOrNum) => (BigInt(hexOrNum) % P).toString();

// Official sample values (event page), VK = the registered gatekeeper vkHash
// from /api/circuit-info, address = a full 160-bit test address.
const VKHASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ADDR = "0xDe42000000000000000000000000000000009f01";
const ADDR2 = "0xDe42000000000000000000000000000000009f02";

const BASE = {
  taskId: "24",
  minimum: "1000",
  publicBalance: "1460",
  expiryBlock: "19842201",
  currentBlock: "19832000",
  recipient: BigInt(ADDR).toString(),
  conditionRecipient: BigInt(ADDR).toString(),
  amount: "500",
  maxTransfer: "1000",
  registeredVkHash: field(VKHASH),
  proofVkHash: field(VKHASH),
  salt: "987654321",
  decision: "1",
};

async function prove(input) {
  const t0 = Date.now();
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const ms = Date.now() - t0;
    return { ok: true, proof, publicSignals, ms, bytes: Buffer.byteLength(JSON.stringify(proof)) };
  } catch (e) {
    return { ok: false, ms: Date.now() - t0, err: String(e.message || e).split("\n")[0] };
  }
}

async function main() {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;

  // 1+2: valid approve — public order, commitment, verify, size, time.
  const v = await prove(BASE);
  console.log("VALID decision=1:", v.ok, v.ms + "ms", v.bytes + "B");
  if (v.ok) {
    console.log("publicSignals:", JSON.stringify(v.publicSignals));
    const commit = F.toString(poseidon([987654321n, 24n]));
    console.log("Poseidon(salt,taskId) == public[0]:", commit === v.publicSignals[0]);
    const okVerify = await snarkjs.groth16.verify(VK, v.publicSignals, v.proof);
    console.log("groth16.verify:", okVerify);
  }

  // warm timing (2nd run)
  const v2 = await prove(BASE);
  console.log("VALID decision=1 (warm):", v2.ok, v2.ms + "ms");

  const cases = [
    ["valid, decision=0 (must FAIL)", {} , "0", false],
    ["balance == minimum, decision=1", { publicBalance: "1000" }, "1", null],
    ["balance == minimum-1, decision=1 (must FAIL)", { publicBalance: "999" }, "1", false],
    ["amount == cap, decision=1", { amount: "1000" }, "1", null],
    ["amount == cap+1, decision=1 (must FAIL)", { amount: "1001" }, "1", false],
    ["amount == cap+1, decision=0", { amount: "1001" }, "0", true],
    ["current == expiry, decision=1", { currentBlock: "19842201" }, "1", null],
    ["current == expiry-1, decision=1", { currentBlock: "19842200" }, "1", null],
    ["current == expiry+1, decision=1 (must FAIL)", { currentBlock: "19842202" }, "1", false],
    ["current == expiry+1, decision=0", { currentBlock: "19842202" }, "0", true],
    ["vk mismatch, decision=1 (must FAIL)", { proofVkHash: field("0x1111111111111111111111111111111111111111111111111111111111111111") }, "1", false],
    ["vk mismatch, decision=0", { proofVkHash: field("0x1111111111111111111111111111111111111111111111111111111111111111") }, "0", true],
    ["recipient mismatch, decision=1 (must FAIL)", { recipient: BigInt(ADDR2).toString() }, "1", false],
    ["recipient mismatch, decision=0", { recipient: BigInt(ADDR2).toString() }, "0", true],
    ["threshold mismatch, decision=0", { publicBalance: "900" }, "0", true],
  ];
  for (const [name, over, dec, expect] of cases) {
    const r = await prove({ ...BASE, ...over, decision: dec });
    console.log(`${name}: provable=${r.ok} (${r.ms}ms)${expect === null ? "" : expect === r.ok ? " [as expected]" : " [!!! UNEXPECTED]"}`);
  }
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });

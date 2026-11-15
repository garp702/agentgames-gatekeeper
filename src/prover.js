// Groth16 proof generation with snarkjs against the OFFICIAL circuit
// artifacts (circuits/gatekeeper.wasm + gatekeeper_final.zkey, downloaded
// from the URLs published by https://agentgames.zkverify.io/api/circuit-info;
// SHA-256 recorded in README.md).
//
// The circuit enforces decision == computed verdict (assert at
// GatekeeperEvaluation_79:102), so a wrong decision simply has no witness.
// prove() therefore tries the checklist's decision first and, if the witness
// is refused, flips the decision once — the flip is counted as a fallback so
// any semantics drift is visible in logs/tests instead of silently costing
// points.
const path = require("path");
const crypto = require("crypto");
const snarkjs = require("snarkjs");

const WASM = path.join(__dirname, "..", "circuits", "gatekeeper.wasm");
const ZKEY = path.join(__dirname, "..", "circuits", "gatekeeper_final.zkey");
const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Deterministic per-task salt: HMAC(secret, "salt:"+task_id) mod p.
// Deterministic => platform retries of the same task yield the same proof
// (rules §1.2: task IDs are idempotency keys). The salt is a private circuit
// input; only its Poseidon commitment to the taskId is public.
function saltFor(secret, taskId) {
  const h = crypto.createHmac("sha256", secret).update("salt:" + taskId).digest("hex");
  return (BigInt("0x" + h) % BN128_PRIME).toString();
}

async function fullProve(input) {
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  return { proof, publicSignals, ms: Date.now() - t0 };
}

// Returns { proof, publicSignals, ms, flipped } or throws if neither
// decision is provable (should not happen for well-formed tasks).
async function proveDecision(circuitInput, secret, taskId) {
  const salt = saltFor(secret, taskId);
  try {
    const r = await fullProve({ ...circuitInput, salt });
    return { ...r, flipped: false };
  } catch (e1) {
    const flippedInput = {
      ...circuitInput,
      salt,
      decision: circuitInput.decision === "1" ? "0" : "1",
    };
    const r = await fullProve(flippedInput);
    return { ...r, flipped: true };
  }
}

module.exports = { proveDecision, saltFor };

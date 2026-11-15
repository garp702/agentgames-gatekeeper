// Deterministic decision logic for Proof Gatekeeper tasks.
//
// Pure functions, no I/O, no LLM — the build guide (/build, "WHAT TO BUILD" #3)
// requires the final call to be enforced by deterministic code: APPROVE only
// when EVERY check passes, otherwise REJECT with a reason_code.
//
// The checks implement the event page's "Seven things to ship" checklist and
// the trap encyclopedia (agentgames.zkverify.io/events/proof-gatekeeper).
// The same comparisons are enforced inside the official circuit (verified
// empirically against gatekeeper.wasm — see test/probe-circuit.js), so a
// decision produced here is always provable; boundary semantics below are
// the circuit's, not guesses:
//   balance >= minimum      (equality is APPROVABLE)
//   amount  <= max_transfer (equality is APPROVABLE)
//   current_block < expiry_block (equality means EXPIRED)

const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// --- field conversions (envelope -> circuit field elements) -----------------
// ASSUMPTION A1 (taskId): the platform's sample task_id "gk_24_9d1" maps to
// circuit input taskId = 24 (the integer embedded in the id). This matches
// the only published worked example (Poseidon(salt, 24) reproduces the
// circuit commitment for that task). To be confirmed on practice tasks.
// ASSUMPTION A2 (VK hashes): registered_vk / proof_vk hex hashes are taken
// as big integers reduced mod the BN128 prime (a 256-bit hash does not fit
// one field element; reduction is the canonical embedding).

function taskIdToField(taskId) {
  const m = String(taskId).match(/\d+/);
  if (m) return BigInt(m[0]).toString();
  // Fallback for ids with no digits: FNV-1a 64 of the string, mod p.
  let h = 0xcbf29ce484222325n;
  const s = String(taskId);
  for (let i = 0; i < s.length; i++) {
    h ^= BigInt(s.charCodeAt(i));
    h = (h * 0x100000001b3n) % (1n << 64n);
  }
  return (h % BN128_PRIME).toString();
}

function hexToField(hex) {
  return (BigInt(hex) % BN128_PRIME).toString();
}

function addressToField(addr) {
  return BigInt(addr).toString(); // 160-bit address fits the field directly
}

function parseUint(v) {
  // Envelope numeric fields arrive as decimal strings or numbers.
  if (typeof v === "number") return BigInt(v);
  if (typeof v === "string" && /^\d+$/.test(v.trim())) return BigInt(v.trim());
  return null;
}

function isHex(v, minLen = 1) {
  return typeof v === "string" && /^0x[0-9a-fA-F]+$/.test(v) && v.length >= minLen + 2;
}

// --- the checklist -----------------------------------------------------------
// Each rule cites its source. `seenProofTx` is a Map<proof_tx, task_id> of
// references already accepted in earlier tasks (checklist item 05).
//
// Returns one of:
//   { ok: true, decision: "APPROVE"|"REJECT", reason_code, circuitInput|null,
//     reused: boolean }
//   { ok: false, error } for structurally unusable tasks (fail closed).

function decide(task, seenProofTx) {
  const input = task && task.input;
  if (!input || typeof input !== "object") {
    return { ok: false, error: "missing input object" };
  }
  const {
    registered_vk, proof_vk, minimum, public_balance,
    expiry_block, current_block, recipient, condition_recipient,
    amount, max_transfer, proof_tx,
  } = input;

  // Structural validation (guide: parse the task payload — checklist item 01).
  const min = parseUint(minimum);
  const bal = parseUint(public_balance);
  const amt = parseUint(amount);
  const cap = parseUint(max_transfer);
  const exp = parseUint(expiry_block);
  const cur = parseUint(current_block);
  if ([min, bal, amt, cap, exp, cur].some((x) => x === null)) {
    return { ok: false, error: "numeric field missing or malformed" };
  }
  if (!isHex(registered_vk) || !isHex(proof_vk)) {
    return { ok: false, error: "vk field missing or malformed" };
  }
  if (!isHex(recipient) || !isHex(condition_recipient)) {
    return { ok: false, error: "recipient field missing or malformed" };
  }
  if (typeof proof_tx !== "string" || proof_tx.length === 0) {
    return { ok: false, error: "proof_tx missing" };
  }

  // Field checks, in trap-encyclopedia order. First failure wins.
  let decision = "APPROVE";
  let reason = "VALID_CONDITION"; // event page: valid condition -> APPROVE

  // Checklist 02 / trap VK_SUBSTITUTION: the proof's VK must match the VK
  // registered for this condition. (Guide §04: "The verification key matches
  // the key registered for this condition.")
  if (proof_vk.toLowerCase() !== registered_vk.toLowerCase()) {
    decision = "REJECT"; reason = "VK_SUBSTITUTION";
  }
  // Checklist 03 / trap THRESHOLD_MISMATCH: public balance meets the minimum.
  else if (bal < min) {
    decision = "REJECT"; reason = "THRESHOLD_MISMATCH";
  }
  // Checklist 04 / trap RECIPIENT_MISMATCH: recipient committed in the proof
  // must match the payment condition address.
  else if (recipient.toLowerCase() !== condition_recipient.toLowerCase()) {
    decision = "REJECT"; reason = "RECIPIENT_MISMATCH";
  }
  // Checklist 06 / trap EXPIRED_CONDITION: condition expires AT expiry_block
  // (circuit-verified: current == expiry is already expired).
  else if (cur >= exp) {
    decision = "REJECT"; reason = "EXPIRED_CONDITION";
  }
  // Trap AMOUNT_OVERFLOW: amount must not exceed the single-transfer cap
  // (circuit-verified: amount == cap is still approvable).
  else if (amt > cap) {
    decision = "REJECT"; reason = "AMOUNT_OVERFLOW";
  }
  // Checklist 05 / trap PROOF_REUSED: the proof reference was already
  // accepted under a DIFFERENT task. Reused tasks carry no proof of ours
  // (event page: "PROOF_REUSED tasks have no proof to submit").
  else if (seenProofTx.has(proof_tx) && seenProofTx.get(proof_tx) !== task.task_id) {
    return { ok: true, decision: "REJECT", reason_code: "PROOF_REUSED", circuitInput: null, reused: true };
  }

  // Circuit inputs (signal names verified against gatekeeper.wasm —
  // test/probe-signals.js). `salt` is filled in by the prover (private).
  const circuitInput = {
    taskId: taskIdToField(task.task_id),
    minimum: min.toString(),
    publicBalance: bal.toString(),
    expiryBlock: exp.toString(),
    currentBlock: cur.toString(),
    recipient: addressToField(recipient),
    conditionRecipient: addressToField(condition_recipient),
    amount: amt.toString(),
    maxTransfer: cap.toString(),
    registeredVkHash: hexToField(registered_vk),
    proofVkHash: hexToField(proof_vk),
    decision: decision === "APPROVE" ? "1" : "0",
  };
  return { ok: true, decision, reason_code: reason, circuitInput, reused: false };
}

module.exports = { decide, taskIdToField, hexToField, BN128_PRIME };

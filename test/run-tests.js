// End-to-end tests: spawn the real server, send HMAC-signed envelopes for
// every documented trap type plus boundary and failure cases, and check
// decision + reason_code + response signature + Groth16 proof validity.
const { spawn } = require("child_process");
const path = require("path");
const crypto = require("crypto");
const snarkjs = require("snarkjs");
const VK = require("../circuits/verification_key.json");

const PORT = 18787;
const SECRET = "test-secret-for-local-tests-only";
const BASE = `http://127.0.0.1:${PORT}/agent`;

const VKHASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const VK_OTHER = "0x1111111111111111111111111111111111111111111111111111111111111111";
const ADDR = "0xDe42000000000000000000000000000000009f01";
const ADDR2 = "0xDe42000000000000000000000000000000009f02";
let txCounter = 0;
const nextTx = () => "0x" + (++txCounter).toString(16).padStart(64, "0");

const sign = (body) => crypto.createHmac("sha256", SECRET).update(body).digest("hex");

function envelope(taskId, overrides = {}) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "competition",
    issued_at: "2026-11-16T10:30:00.000Z",
    deadline_at: "2026-11-16T10:31:00.000Z",
    input: {
      registered_vk: VKHASH,
      proof_vk: VKHASH,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: ADDR,
      condition_recipient: ADDR,
      amount: "500",
      max_transfer: "1000",
      proof_tx: nextTx(),
      ...overrides,
    },
  };
}

async function post(rawBody, signature) {
  const headers = { "content-type": "application/json" };
  if (signature !== undefined) headers["x-agent-games-signature"] = signature;
  const t0 = Date.now();
  const res = await fetch(BASE, { method: "POST", headers, body: rawBody });
  const text = await res.text();
  return { status: res.status, text, json: safeJson(text), ms: Date.now() - t0, respSig: res.headers.get("x-agent-games-signature") };
}
const safeJson = (t) => { try { return JSON.parse(t); } catch { return null; } };
const postSigned = (obj) => { const b = JSON.stringify(obj); return post(b, sign(b)); };

const results = [];
function record(name, pass, detail) {
  results.push({ name, pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}  ${name} — ${detail}`);
}

async function checkProof(name, r, expectDecision, expectTaskIdField) {
  if (!r.json || !r.json.proof) return record(name + " [proof]", false, "no proof in response");
  const okSig = r.respSig === sign(r.text);
  let okVerify = false, sigOk = false;
  try {
    okVerify = await snarkjs.groth16.verify(VK, r.json.public_signals, r.json.proof);
    sigOk = r.json.public_signals[11] === expectDecision && r.json.public_signals[12] === expectTaskIdField;
  } catch (e) { /* recorded below */ }
  record(name + " [proof]", okSig && okVerify && sigOk,
    `respSig=${okSig} verify=${okVerify} pubSignals(decision,taskId)=${sigOk} proofBytes=${Buffer.byteLength(JSON.stringify(r.json.proof))}`);
}

async function main() {
  const server = spawn("node", [path.join(__dirname, "..", "src", "server.js")], {
    env: { ...process.env, AGENT_GAMES_HMAC_SECRET: SECRET, PORT: String(PORT) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let serverLog = "";
  server.stderr.on("data", (d) => { serverLog += d; });
  await new Promise((res) => server.stdout.on("data", res));
  console.log("server up on", PORT);

  try {
    // --- the seven documented trap varieties + boundaries ---
    let r = await postSigned(envelope("gk_101_a1"));
    record("VALID_CONDITION", r.status === 200 && r.json.decision === "APPROVE" && r.json.reason_code === "VALID_CONDITION", `${r.ms}ms`);
    await checkProof("VALID_CONDITION", r, "1", "101");
    const taskA = envelope("gk_102_a2"); // kept for reuse + retry tests

    r = await postSigned(envelope("gk_103_a3", { proof_vk: VK_OTHER }));
    record("VK_SUBSTITUTION", r.json.decision === "REJECT" && r.json.reason_code === "VK_SUBSTITUTION", `${r.ms}ms`);
    await checkProof("VK_SUBSTITUTION", r, "0", "103");

    r = await postSigned(envelope("gk_104_a4", { public_balance: "900" }));
    record("THRESHOLD_MISMATCH", r.json.decision === "REJECT" && r.json.reason_code === "THRESHOLD_MISMATCH", `${r.ms}ms`);
    await checkProof("THRESHOLD_MISMATCH", r, "0", "104");

    r = await postSigned(envelope("gk_105_a5", { recipient: ADDR2 }));
    record("RECIPIENT_MISMATCH", r.json.decision === "REJECT" && r.json.reason_code === "RECIPIENT_MISMATCH", `${r.ms}ms`);
    await checkProof("RECIPIENT_MISMATCH", r, "0", "105");

    r = await postSigned(envelope("gk_106_a6", { current_block: 19842201 })); // current == expiry
    record("EXPIRED_CONDITION (==)", r.json.decision === "REJECT" && r.json.reason_code === "EXPIRED_CONDITION", `${r.ms}ms`);
    await checkProof("EXPIRED_CONDITION (==)", r, "0", "106");

    r = await postSigned(envelope("gk_107_a7", { amount: "1500" }));
    record("AMOUNT_OVERFLOW", r.json.decision === "REJECT" && r.json.reason_code === "AMOUNT_OVERFLOW", `${r.ms}ms`);
    await checkProof("AMOUNT_OVERFLOW", r, "0", "107");

    r = await postSigned(envelope("gk_108_a8", { public_balance: "1000" })); // balance == minimum
    record("BOUNDARY balance==minimum -> APPROVE", r.json.decision === "APPROVE" && r.json.reason_code === "VALID_CONDITION", `${r.ms}ms`);

    r = await postSigned(envelope("gk_109_a9", { amount: "1000" })); // amount == cap
    record("BOUNDARY amount==cap -> APPROVE", r.json.decision === "APPROVE" && r.json.reason_code === "VALID_CONDITION", `${r.ms}ms`);

    // --- proof reuse + idempotent retry ---
    const first = await postSigned(taskA);
    record("REUSE setup (first use)", first.json.decision === "APPROVE", `${first.ms}ms`);
    const taskB = envelope("gk_110_b1", { proof_tx: taskA.input.proof_tx }); // same proof_tx, new task
    r = await postSigned(taskB);
    record("PROOF_REUSED", r.json.decision === "REJECT" && r.json.reason_code === "PROOF_REUSED" && !r.json.proof, `${r.ms}ms`);
    const retry = await postSigned(taskA); // platform retry of the SAME task
    record("IDEMPOTENT RETRY (not reuse)", retry.text === first.text && retry.json.decision === "APPROVE", `${retry.ms}ms`);

    // --- failure behaviour ---
    const goodBody = JSON.stringify(envelope("gk_111_c1"));
    r = await post(goodBody, "deadbeef");
    record("BAD SIGNATURE -> 401", r.status === 401, `status=${r.status}`);
    r = await post(goodBody, undefined);
    record("MISSING SIGNATURE -> 401", r.status === 401, `status=${r.status}`);
    r = await post("this is not json{{{", sign("this is not json{{{"));
    record("MALFORMED JSON (signed) -> 400, no crash", r.status === 400, `status=${r.status}`);
    const broken = envelope("gk_112_c2", { minimum: undefined });
    delete broken.input.minimum;
    r = await postSigned(broken);
    record("MISSING FIELD -> REJECT/INVALID_TASK, no crash", r.status === 200 && r.json.decision === "REJECT" && r.json.reason_code === "INVALID_TASK", `status=${r.status}`);

    // --- preflight + health ---
    const pf = JSON.stringify({ type: "agent-games.preflight.v1" });
    r = await post(pf, sign(pf));
    record("PREFLIGHT reply", r.status === 200 && r.json.ok === true && r.json.protocolVersion === "v1" && r.respSig === sign(r.text), `status=${r.status}`);
    const health = await fetch(BASE.replace("/agent", "/health"));
    const htext = await health.text();
    record("GET HEALTH", health.status === 200 && safeJson(htext).ok === true && health.headers.get("x-agent-games-signature") === sign(htext), `status=${health.status}`);
  } finally {
    server.kill();
  }

  const flips = (serverLog.match(/flipped/g) || []).length;
  const proofFails = (serverLog.match(/proof generation failed/g) || []).length;
  console.log(`\nserver fallbacks: decision flips=${flips}, proof failures=${proofFails}`);
  const failed = results.filter((x) => !x.pass);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  process.exit(failed.length ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });

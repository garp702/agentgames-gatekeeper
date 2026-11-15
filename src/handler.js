// Transport-agnostic Agent Games protocol handler.
//
//   handleRequest({ method, rawBody, signatureHeader })
//     -> { status, body }   (body is the exact string to send; the caller
//                            adds the x-agent-games-signature header via
//                            signResponse(), or uses respond() below)
//
// One handler serves the local test server (src/server.js) and the Vercel
// serverless wrapper (api/agent.js). Protocol facts are from the official
// /build guide and /rules; assumptions are marked A1..A4 (see decision.js
// for A1/A2):
//   A3: the preflight arrives as a POST to the registered path whose JSON is
//       not a gatekeeper task; the guide only fixes the reply shape
//       { ok: true, protocolVersion: "v1" }, signed.
//   A4: a request with a bad signature gets a plain HTTP 401 (the guide
//       says "reject on mismatch" without fixing a body).
//
// Fail-closed policy (guide, non-negotiable): any error, timeout or
// uncertainty => REJECT, never APPROVE by default; the handler never throws.
const { sign, verify } = require("./hmac");
const { decide } = require("./decision");
const { proveDecision } = require("./prover");

const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const SOFT_DEADLINE_MS = 50000; // platform hard deadline is 60 s (guide)

function createHandler({ secret, log = () => {} }) {
  if (!secret) throw new Error("AGENT_GAMES_HMAC_SECRET is required");
  const seenProofTx = new Map(); // proof_tx -> task_id (checklist item 05)
  const responseCache = new Map(); // task_id -> response body (idempotency)
  const stats = { tasks: 0, fallbacks: 0, flips: 0, errors: 0 };

  function signed(status, obj) {
    const body = JSON.stringify(obj);
    return { status, body, signature: sign(secret, body) };
  }

  async function handleTask(task) {
    stats.tasks++;
    // Idempotent replay: the platform may retry the same task_id after a
    // network failure (rules §1.2) — return the original response verbatim.
    if (task.task_id && responseCache.has(task.task_id)) {
      return { status: 200, body: responseCache.get(task.task_id), signature: sign(secret, responseCache.get(task.task_id)) };
    }

    const verdict = decide(task, seenProofTx);
    let responseObj;

    if (!verdict.ok) {
      // Structurally unusable task: fail closed, no proof can be formed.
      stats.errors++;
      log("task rejected as malformed:", verdict.error, "task_id:", task && task.task_id);
      responseObj = { decision: "REJECT", reason_code: "INVALID_TASK", proof_tx: task && task.input ? task.input.proof_tx : undefined };
    } else if (verdict.reused) {
      // PROOF_REUSED: event page — reused tasks have no proof to submit.
      responseObj = { decision: "REJECT", reason_code: "PROOF_REUSED", proof_tx: task.input.proof_tx };
    } else {
      try {
        const proved = await Promise.race([
          proveDecision(verdict.circuitInput, secret, task.task_id),
          new Promise((_, rej) => setTimeout(() => rej(new Error("soft deadline")), SOFT_DEADLINE_MS)),
        ]);
        if (proved.flipped) {
          stats.flips++;
          log("WARNING: circuit flipped the checklist decision for task", task.task_id);
          // The circuit is the referee: adopt its decision. If it flipped to
          // REJECT, keep the checklist's first failing reason if there was
          // one; otherwise mark the drift explicitly.
          const circDecision = verdict.circuitInput.decision === "1" ? "REJECT" : "APPROVE";
          responseObj = {
            decision: circDecision,
            reason_code: circDecision === "REJECT" && verdict.decision === "APPROVE" ? "CIRCUIT_MISMATCH" : verdict.reason_code,
            proof: proved.proof,
            public_signals: proved.publicSignals,
            proof_tx: task.input.proof_tx,
          };
        } else {
          responseObj = {
            decision: verdict.decision,
            reason_code: verdict.reason_code,
            proof: proved.proof,
            public_signals: proved.publicSignals,
            proof_tx: task.input.proof_tx,
          };
        }
      } catch (e) {
        // Proof generation failed entirely: fail closed (guide). The reply
        // is still a signed, well-formed REJECT; it will score as a missing
        // proof (-2) rather than a wrong approval (-6) if the task was bad.
        stats.fallbacks++;
        log("proof generation failed for task", task.task_id, String(e && e.message || e));
        responseObj = { decision: "REJECT", reason_code: verdict.decision === "REJECT" ? verdict.reason_code : "PROOF_FAILED", proof_tx: task.input.proof_tx };
      }
    }

    const out = signed(200, responseObj);
    if (task.task_id) {
      responseCache.set(task.task_id, out.body);
      if (responseCache.size > 2000) responseCache.delete(responseCache.keys().next().value);
    }
    if (task.input && typeof task.input.proof_tx === "string") {
      seenProofTx.set(task.input.proof_tx, task.task_id);
    }
    return out;
  }

  async function handleRequest({ method, rawBody = "", signatureHeader }) {
    try {
      if (method === "GET") {
        // Health check (entry requirement: "passing health check") — reply
        // with the preflight shape, signed.
        return signed(200, { ok: true, protocolVersion: "v1" });
      }
      if (method !== "POST") return signed(405, { error: "method not allowed" });

      // Guide: verify the HMAC over the RAW body BEFORE parsing anything.
      if (!verify(secret, rawBody, signatureHeader)) {
        return { status: 401, body: JSON.stringify({ error: "invalid signature" }), signature: null };
      }

      let parsed;
      try {
        parsed = JSON.parse(rawBody);
      } catch {
        return signed(400, { error: "invalid json" });
      }

      if (parsed && parsed.type === TASK_TYPE) {
        return await handleTask(parsed);
      }
      // A3: anything else that is validly signed is treated as preflight.
      return signed(200, { ok: true, protocolVersion: "v1" });
    } catch (e) {
      stats.errors++;
      log("handler error:", String(e && e.stack || e));
      // Never crash; fail closed with a signed protocol-shaped reply.
      return signed(500, { ok: false, protocolVersion: "v1", error: "internal" });
    }
  }

  return { handleRequest, stats };
}

module.exports = { createHandler, TASK_TYPE };

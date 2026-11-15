# Proof Gatekeeper agent — zkVerify Agent Games, Season 01

A deterministic gatekeeper for the **Proof Gatekeeper** track: it receives
HMAC-signed task envelopes, decides APPROVE / REJECT by a fixed checklist,
and returns a Groth16 proof of the decision generated locally with snarkjs
against the tournament's own circuit. Built locally on 2026-11-15; **not
registered, not deployed** — deployment steps are in [DEPLOY.md](DEPLOY.md).

## Architecture

```
platform --POST signed envelope--> handler --> decision --> prover --> signed response
                                     |            (pure)      (snarkjs)
                                     +-- HMAC verify over raw body, before parsing
```

| File | Role |
|---|---|
| `src/handler.js` | Protocol handler (transport-agnostic): signature check, preflight/health replies, idempotent replay, seen-set for proof reuse, fail-closed error paths. Never throws. |
| `src/decision.js` | The checklist as pure functions. Every rule comments its source in the official guide/event page. Also converts envelope fields to circuit field elements. |
| `src/prover.js` | snarkjs `groth16.fullProve` over the official wasm/zkey; deterministic per-task salt; one decision-flip retry (counted as a fallback) in case of semantics drift. |
| `src/hmac.js` | HMAC-SHA256 sign/verify over raw bodies, timing-safe compare. |
| `src/server.js` | Local HTTP server (Node stdlib) wrapping the handler. |
| `api/agent.js` | Vercel serverless wrapper (raw-body, `bodyParser` off) around the same handler. |
| `circuits/` | Official artifacts, see provenance below. |
| `test/probe-signals.js` | Verifies the circuit's input signal names against the WASM itself (FNV-1a-64 probing). |
| `test/probe-circuit.js` | Empirically probes circuit semantics: public-signal order, the Poseidon commitment, boundary behaviour, trap refusals. |
| `test/run-tests.js` | End-to-end suite against the real server (`npm test`). |

## Confirmed spec (official sources, fetched 2026-11-15)

Sources: `agentgames.zkverify.io/events/proof-gatekeeper`, `/build`,
`/rules`, `/guide`, `/api/circuit-info`.

- **Task envelope**: `{ type: "agent-games.proof-gatekeeper.v1", task_id,
  mode, issued_at, deadline_at, input: { registered_vk, proof_vk, minimum,
  public_balance, expiry_block, current_block, recipient,
  condition_recipient, amount, max_transfer, proof_tx } }`.
- **Response**: signed JSON `{ decision, reason_code, proof,
  public_signals }` (+ `proof_tx` echoed as an optional audit pointer),
  header `x-agent-games-signature` over the raw response body. Preflight
  reply: `{ ok: true, protocolVersion: "v1" }`, signed.
- **HMAC**: header verified over the **raw** request body before parsing.
  Secret = 32-byte random value generated at agent registration, shown
  once, rotatable in the dashboard; env var `AGENT_GAMES_HMAC_SECRET`.
- **Reason codes** (trap encyclopedia): `VALID_CONDITION` (approve),
  `VK_SUBSTITUTION`, `THRESHOLD_MISMATCH`, `PROOF_REUSED`,
  `EXPIRED_CONDITION`, `RECIPIENT_MISMATCH`, `AMOUNT_OVERFLOW`.
- **Trap mix**: valid ~50%, VK substitution ~13%, proof reused ~11%,
  threshold ~8%, expired ~6%, recipient ~6%, amount overflow ~6%.
- **Scoring**: +12 correct, −6 wrong approve, −3 wrong reject, −2 timeout,
  −2 missing/invalid proof, reliability bonus +0…+5 pro-rated by verified
  proofs. **PROOF_REUSED tasks have no proof to submit** and are excluded
  from the proof requirement — the handler answers them without a proof.
- **Deadline**: 60 s hard. Task IDs are idempotency keys (platform retries
  return the original response — handled by the response cache).
- **Circuit**: Groth16/BN128, Circom 2.x. Artifacts served from
  `https://agentgames.zkverify.io/circuits/gatekeeper.wasm` and
  `.../gatekeeper_final.zkey` (per `/api/circuit-info`); registered vkHash
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`.
  Downloaded 2026-11-15, SHA-256:
  - wasm `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` (1,755,820 B)
  - zkey `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` (309,750 B)
  Exported VK: curve bn128, **13 public inputs**, witness size 647.

## Circuit facts established empirically (not published by the site)

The site publishes **no circuit source and no signal names**. Verified here
by probing the WASM (FNV-1a-64 + `getInputSignalSize` after `init(1)`) and
by proving test vectors (`test/probe-*.js`):

- **13 input signals, each size 1**: `taskId, minimum, publicBalance,
  expiryBlock, currentBlock, recipient, conditionRecipient, amount,
  maxTransfer, registeredVkHash, proofVkHash, salt (private), decision`.
  (`getInputSize` = 13; all control names probed return "not found".)
- **Public-signal order**: `[Poseidon(salt, taskId), registeredVkHash,
  proofVkHash, minimum, publicBalance, expiryBlock, currentBlock,
  recipient, conditionRecipient, amount, maxTransfer, decision, taskId]`.
  The commitment hypothesis was confirmed exactly with circomlibjs.
- **The circuit enforces decision == computed verdict** (assert
  `GatekeeperEvaluation_79:102`): a wrong decision has no witness, in
  either direction.
- **Boundary semantics**: balance ≥ minimum approvable; amount ≤ cap
  approvable; **current_block == expiry_block is already expired**
  (valid iff current < expiry).

## Decision checklist (mirrors the guide's "Seven things to ship")

1. Parse + structurally validate the payload.
2. `proof_vk == registered_vk`, else REJECT `VK_SUBSTITUTION`.
3. `public_balance >= minimum`, else REJECT `THRESHOLD_MISMATCH`.
4. `recipient == condition_recipient`, else REJECT `RECIPIENT_MISMATCH`.
5. `current_block < expiry_block`, else REJECT `EXPIRED_CONDITION`.
6. `amount <= max_transfer`, else REJECT `AMOUNT_OVERFLOW`.
7. `proof_tx` unseen under another task, else REJECT `PROOF_REUSED`
   (no proof attached, per the event page).
Otherwise APPROVE `VALID_CONDITION`, with a proof of the decision.

Note: the guide's checklist item "confirm the proof is on-chain via
zkVerifyJS" is realised by the platform's own task construction — the
envelope fields are the evidence, the circuit re-checks the same
comparisons, and the platform re-verifies our proof against its registered
key. There is no separate on-chain lookup in the response path.

## Test results (this VM, ~1.5 shared CPUs, 2026-11-15)

`test/run-tests.js` — **23/23 checks passed**, 0 decision flips, 0 proof
failures, 0 crashes:

| Case | Decision / reason | Latency | Proof |
|---|---|---|---|
| Valid condition | APPROVE / VALID_CONDITION | 1,433 ms (cold), ~500 ms warm | verifies, 723 B |
| VK substitution | REJECT / VK_SUBSTITUTION | 576 ms | verifies |
| Threshold mismatch | REJECT / THRESHOLD_MISMATCH | 533 ms | verifies |
| Recipient mismatch | REJECT / RECIPIENT_MISMATCH | 570 ms | verifies |
| Expired (current == expiry) | REJECT / EXPIRED_CONDITION | 406 ms | verifies |
| Amount overflow | REJECT / AMOUNT_OVERFLOW | 508 ms | verifies |
| Boundary balance == minimum | APPROVE | 415 ms | verifies |
| Boundary amount == cap | APPROVE | 497 ms | verifies |
| Proof reused (2nd task, same proof_tx) | REJECT / PROOF_REUSED, **no proof** | 3 ms | n/a by design |
| Idempotent retry of same task | original response replayed | 2 ms | n/a |
| Bad / missing signature | HTTP 401 | — | — |
| Malformed JSON (signed) | HTTP 400, no crash | — | — |
| Missing field | REJECT / INVALID_TASK, no crash | — | — |
| Preflight-shaped POST | `{ ok: true, protocolVersion: "v1" }`, signed | — | — |
| GET health | ok, signed | — | — |

Raw proving (probe): cold fullProve 1,576 ms, warm ~424–582 ms; proof
JSON 721–724 B; `groth16.verify` true. All far inside the 60 s deadline.

## Assumptions & gaps (must be confirmed at preflight / practice)

- **A0 — HMAC digest/encoding**: the public pages never state it.
  Implemented as HMAC-SHA256, hex. The platform preflight is the
  authoritative check; if it fails, this is the first knob to turn.
- **A1 — taskId conversion**: `task_id` "gk_24_9d1" → circuit `taskId` 24
  (first integer in the id). Matches the only published worked example;
  practice tasks will confirm.
- **A2 — VK hash embedding**: 256-bit VK hashes reduced mod the BN128
  prime into one field element each.
- **A3 — preflight transport**: any validly signed non-task POST gets the
  documented preflight reply; GET returns the same shape for the health
  check. The guide fixes only the reply body.
- **A4 — bad-signature response**: plain HTTP 401 with an error body.
- **INVALID_TASK / CIRCUIT_MISMATCH / PROOF_FAILED reason codes** are
  local fail-closed inventions for situations the documented protocol
  doesn't cover (malformed tasks shouldn't occur in scored play).
- The seen-set and idempotency cache are in-memory: correct for a warm
  serverless instance / single local process; a cold restart forgets
  previously seen proof references. Acceptable for Season 01 (rounds are
  short, one agent), noted as a known limitation.

## Creator Track angle (draft)

The content seed is this build itself: a working gatekeeper whose every
decision is certified by the tournament's own circuit — including the two
findings that only appear when you actually run it: (1) the circuit is a
referee, not a rubber stamp (wrong decisions have no witness, either way),
and (2) verification is necessary, not sufficient — the checks that matter
(VK registration, reuse, expiry semantics at the boundary) live around the
proof. A thread/article can be built from `test/probe-circuit.js` outputs
and the trap matrix above, with the endpoint's practice-mode results added
once live. ipot publishes from his own X account; nothing here posts
anything.

# Deploy runbook — from this local build to a live Gatekeeper endpoint

Target: **Round 04, Monday 2026-11-16, 17:30 WIB** (rounds run daily
17:30 WIB → 03:30 WIB; entry requires a registered endpoint with a passing
health check, a completed signed preflight, and ≥1 practice task).

Legend: **[IPOT]** = only ipot can do it (phone / identity / accounts).
**[PLER]** = pler does it. Nothing here costs money; Vercel's free tier is
enough. Do NOT use the main Binance wallet anywhere in this flow.

## Step 1 — Ipot creates the accounts [IPOT]
1. Agent Games account: open the registration link, **Sign in with X**
   (@yudii5288), claim handle `ipot` (fallbacks: `ipotai`, `ipot_agent`,
   `ipotpler`), bio + country from `../REGISTRATION_PREP.md`.
2. Connect GitHub **garp702** (prize eligibility).
3. Create a free **Vercel** account (vercel.com) — sign up with the same
   GitHub (garp702) is easiest.
4. Add the prize wallet later, deliberately (dashboard profile) — the
   registered wallet receives VFY. Not needed to start competing.

## Step 2 — Hand over deploy access [IPOT → PLER]
Either is fine:
- **Option A (simplest):** ipot connects the GitHub repo (Step 3) to
  Vercel himself in the Vercel dashboard ("Import Project"), sets the env
  var from Step 4, and tells pler the deployment URL.
- **Option B:** ipot gives pler a Vercel deploy token / adds pler to the
  project; pler deploys from this VM with the Vercel CLI.
No wallet keys or seeds are involved at any point.

## Step 3 — Publish the code [PLER]
1. Push `~/workspace/agentgames/gatekeeper/` to a GitHub repo under
   garp702 (private is fine; Vercel imports it either way). `circuits/`
   must be included — `vercel.json` already bundles them into the
   function (`includeFiles`) and sets `maxDuration: 60`.
2. Import the repo in Vercel (framework preset: "Other"; root = repo
   root). The function is `api/agent.js`; the endpoint path will be
   `https://<deployment>.vercel.app/api/agent`.
3. Sanity check from this VM: `GET https://<deployment>.vercel.app/api/agent`
   must return `{ "ok": true, "protocolVersion": "v1" }` with an
   `x-agent-games-signature` header.

## Step 4 — Register the agent + set the secret [IPOT + PLER]
1. **[IPOT]** In the Agent Games dashboard: register an agent for the
   Proof Gatekeeper track with the endpoint URL from Step 3 (full path,
   `/api/agent` included — the platform posts exactly to the registered
   URL). Agent registration involves a SIWE signature from his phone —
   use a wallet that supports EIP-191 `personal_sign` (the prize wallet
   choice from Step 1.4 can be this wallet).
2. **[IPOT]** Dashboard → agent settings → **Rotate Secret**. The
   platform shows the 32-byte HMAC secret **exactly once**. Copy it.
3. **[IPOT → PLER]** Hand the secret to pler (or paste it directly into
   Vercel): set env var **`AGENT_GAMES_HMAC_SECRET`** = that value in the
   Vercel project (Production), then redeploy/restart.
   - Never commit it to the repo; never put it in chat logs beyond the
     one hand-off. `.env` is git-ignored locally.

## Step 5 — Preflight + practice [PLER, dashboard clicks by IPOT if prompted]
1. Trigger **preflight** from the dashboard. It POSTs to the endpoint;
   the agent replies `{ ok: true, protocolVersion: "v1" }`, signed.
   - If preflight fails on signature: assumption A0 (HMAC-SHA256 hex) is
     the first suspect — tell pler the exact dashboard error message.
2. Run **practice tasks** (dashboard; capped at 10 dispatches/hour,
   unscored). Watch for:
   - decisions matching the trap types,
   - proofs verifying on the platform side,
   - **assumption A1** (taskId = integer inside `task_id`) — a practice
     task whose proof the platform rejects would point here first.
3. Confirm the dashboard marks the agent **healthy / active** for Proof
   Gatekeeper.

## Step 6 — Round 04, 2026-11-16 17:30 WIB [PLER monitors]
- 8 tasks arrive across the round window (17:30 WIB → 03:30 WIB). The
  endpoint answers each in ~0.5 s locally; Vercel cold starts add a few
  seconds at most — far inside 60 s.
- Free-tier caution (rules §1.4): if the agent is offline when a task is
  delivered, the task is forfeited. Vercel serverless does not "sleep"
  like free dynos, but keep the deployment on the Production branch and
  don't redeploy mid-round.
- After the round: read the dashboard score together; a correct round is
  worth up to 8 × 12 + reliability ≈ 101 points.

## Rollback / safety
- Rotate Secret (dashboard) instantly invalidates the old secret if
  anything leaks; update the Vercel env var and redeploy.
- The agent never holds keys, funds, or wallet access — worst case of a
  bad round is a low score, nothing else.

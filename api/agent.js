// Vercel serverless wrapper for the gatekeeper handler (CommonJS).
// Register THIS path (e.g. https://<deployment>.vercel.app/api/agent) as the
// agent endpoint on the Agent Games dashboard — the guide warns the platform
// posts to the URL exactly as registered, path included.
//
// vercel.json sets maxDuration and bundles the circuit artifacts.
const { createHandler } = require("../src/handler");

let handler;
function getHandler() {
  if (!handler) {
    handler = createHandler({
      secret: process.env.AGENT_GAMES_HMAC_SECRET,
      log: (...a) => console.error(...a),
    });
  }
  return handler;
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

module.exports = async function agent(req, res) {
  const rawBody = req.method === "POST" ? await readRawBody(req) : "";
  const out = await getHandler().handleRequest({
    method: req.method,
    rawBody,
    signatureHeader: req.headers["x-agent-games-signature"],
  });
  if (out.signature) res.setHeader("x-agent-games-signature", out.signature);
  res.setHeader("content-type", "application/json");
  res.status(out.status).send(out.body);
};

// Disable Vercel's body parser — the HMAC is computed over the RAW body.
module.exports.config = { api: { bodyParser: false } };

// Local HTTP server wrapper around src/handler.js (Node stdlib only).
// Used for local testing and as a fallback host shape; production deploys
// use the Vercel wrapper in api/agent.js with the same handler.
//
//   AGENT_GAMES_HMAC_SECRET=<secret> node src/server.js   (PORT env, default 8787)
const http = require("http");
const { createHandler } = require("./handler");

const secret = process.env.AGENT_GAMES_HMAC_SECRET;
if (!secret) {
  console.error("AGENT_GAMES_HMAC_SECRET is not set (see .env.example)");
  process.exit(1);
}
const { handleRequest, stats } = createHandler({
  secret,
  log: (...a) => console.error(new Date().toISOString(), ...a),
});

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const rawBody = Buffer.concat(chunks).toString("utf8");
    const out = await handleRequest({
      method: req.method,
      rawBody,
      signatureHeader: req.headers["x-agent-games-signature"],
    });
    const headers = { "content-type": "application/json" };
    if (out.signature) headers["x-agent-games-signature"] = out.signature;
    res.writeHead(out.status, headers);
    res.end(out.body);
  });
  req.on("error", () => { try { res.writeHead(400); res.end(); } catch {} });
});

const port = Number(process.env.PORT || 8787);
server.listen(port, () => console.log(`gatekeeper listening on :${port} (stats: ${JSON.stringify(stats)})`));

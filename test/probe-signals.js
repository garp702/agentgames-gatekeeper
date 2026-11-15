// Probe the official gatekeeper.wasm for its input signal names.
// Circom 2.x WASM resolves input signals by the FNV-1a 32-bit hash of the
// signal name, split into (hMSB, hLSB); getInputSignalSize(hMSB, hLSB)
// returns the signal's field-element size, or 0 / traps if undefined.
// This script verifies a candidate list (from a participant's published
// write-up) against the actual circuit, and also sweeps a dictionary of
// plausible alternatives so the result does not depend on trusting it.
const fs = require("fs");
const path = require("path");

const WASM = path.join(__dirname, "..", "circuits", "gatekeeper.wasm");

// Circom 2.x uses FNV-1a 64-bit (see circom_runtime/js/utils.js fnvHash).
function fnv1a64(str) {
  const MOD = 1n << 64n;
  let h = 0xcbf29ce484222325n;
  for (let i = 0; i < str.length; i++) {
    h ^= BigInt(str.charCodeAt(i));
    h = (h * 0x100000001b3n) % MOD;
  }
  return h;
}

async function main() {
  const buffer = fs.readFileSync(WASM);
  const mod = await WebAssembly.compile(buffer);
  console.log("IMPORTS:", JSON.stringify(WebAssembly.Module.imports(mod)));
  console.log("EXPORTS:", JSON.stringify(WebAssembly.Module.exports(mod).map((e) => e.name)));

  const imports = {
    runtime: {
      exceptionHandler: (code) => { throw new Error("wasm exceptionHandler code=" + code); },
      showSharedRWMemory: () => {},
      printErrorMessage: () => {},
      writeBufferMessage: () => {},
    },
  };
  const instance = await WebAssembly.instantiate(mod, imports);
  const ex = instance.exports;
  if (ex.getVersion) console.log("getVersion:", ex.getVersion());
  if (ex.getFieldNumLen32) console.log("getFieldNumLen32:", ex.getFieldNumLen32());
  if (ex.getNVars) console.log("getNVars:", ex.getNVars());
  if (ex.getNPublic) console.log("getNPublic:", ex.getNPublic());
  if (ex.getNInputs) console.log("getNInputs:", ex.getNInputs());

  ex.init(1); // witness calculator protocol: init before probing
  if (ex.getInputSize) console.log("getInputSize:", ex.getInputSize());
  if (ex.getWitnessSize) console.log("getWitnessSize:", ex.getWitnessSize());
  const size = (name) => {
    const h = fnv1a64(name);
    const hMSB = Number(h >> 32n);
    const hLSB = Number(h & 0xffffffffn);
    try {
      return ex.getInputSignalSize(hMSB, hLSB);
    } catch (e) {
      return "TRAP:" + e.message;
    }
  };

  const candidates = [
    // Candidate list from @sidik666's published build log (to be verified):
    "taskId", "minimum", "publicBalance", "expiryBlock", "currentBlock",
    "recipient", "conditionRecipient", "amount", "maxTransfer",
    "registeredVkHash", "proofVkHash", "salt", "decision",
    // Alternatives / controls (should mostly NOT exist):
    "task_id", "public_balance", "max_transfer", "registered_vk", "proof_vk",
    "proofTx", "proof_tx", "balance", "threshold", "expiry", "current",
    "vkHash", "registeredVk", "proofVk", "nonce", "main.taskId", "output",
    "commitment", "verified", "isValid", "approve", "approved",
  ];
  let found = 0;
  for (const c of candidates) {
    const s = size(c);
    if (typeof s === "number" && s > 0) found++;
    console.log(`signal ${JSON.stringify(c)}: size=${s}`);
  }
  console.log("candidates with size>0:", found);
}

main().catch((e) => { console.error(e); process.exit(1); });

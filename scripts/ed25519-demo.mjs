import * as ed25519 from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
ed25519.utils.sha512Sync = (...m) => sha512(...m);

// canonicalize subset: keys in lexicographic order, stable JSON
function canonicalizeSubset(receipt) {
  const subsetKeys = ["id","issued_at","input_hash","output_hash","model_version","policy_version"];
  const obj = {};
  for (const k of subsetKeys) if (receipt[k] !== undefined) obj[k] = receipt[k];

  const sortObj = (o) => {
    if (Array.isArray(o)) return o.map(sortObj);
    if (o && typeof o === "object") {
      const out = {};
      for (const k of Object.keys(o).sort()) out[k] = sortObj(o[k]);
      return out;
    }
    return o;
  };
  const sorted = sortObj(obj);
  return JSON.stringify(sorted);
}

// test-only private key (do not use in prod)
const privHex = "0101010101010101010101010101010101010101010101010101010101010101";
const priv = Uint8Array.from(Buffer.from(privHex, "hex"));

const run = async () => {
  const pub = await ed25519.getPublicKey(priv);
  const pubHex = Buffer.from(pub).toString("hex");

  const receipt = {
    id: "rec_demo_001",
    issued_at: "2025-09-10T12:00:00Z",
    input_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    output_hash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    model_version: "gpt-x-2025-09-01",
    policy_version: "policy-v1.0"
  };

  const msg = new TextEncoder().encode(canonicalizeSubset(receipt));
  const sig = await ed25519.sign(msg, priv);
  const ok = await ed25519.verify(sig, msg, pub);

  console.log("PUBKEY (hex):", pubHex);
  console.log("SIG (base64):", Buffer.from(sig).toString("base64"));
  console.log("VERIFY:", ok ? "PASS" : "FAIL");
};

run().catch(e => { console.error(e); process.exit(1); });

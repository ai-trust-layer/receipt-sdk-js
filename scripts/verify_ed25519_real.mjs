import fs from "node:fs";
import * as ed from "@noble/ed25519";

// Canonizare minimă, în aceeași ordine ca în Py: id, issued_at, input_hash, output_hash, model_version, policy_version
function canonicalizeSubset(r) {
  const keys = ["id","issued_at","input_hash","output_hash","model_version","policy_version"];
  const obj = {};
  for (const k of keys) { if (r[k] === undefined) throw new Error(`missing ${k}`); obj[k] = r[k]; }
  return JSON.stringify(obj);
}

function decodeKid(kid) {
  // așteptat: "ed25519:<hex public key>"
  if (!kid || !kid.startsWith("ed25519:")) throw new Error("kid format not supported");
  const hex = kid.slice("ed25519:".length);
  if (!/^[0-9a-fA-F]+$/.test(hex)) throw new Error("kid pubkey not hex");
  return hex.toLowerCase();
}

export async function verifyReceipt(path) {
  const r = JSON.parse(fs.readFileSync(path, "utf8"));
  const sig = r?.signature;
  if (!sig) return { ok:false, reason:"not_provided" };
  if (sig.alg?.toLowerCase() !== "ed25519") return { ok:false, reason:"alg_unsupported" };
  const pubHex = decodeKid(sig.kid);
  const msg = new TextEncoder().encode(canonicalizeSubset(r));
  const sigBytes = Buffer.from(sig.sig, "base64"); // sig e base64 în spec
  const ok = await ed.verify(sigBytes, msg, pubHex);
  return { ok, reason: ok ? "ok" : "bad_signature" };
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const [,, file] = process.argv;
  if (!file) { console.error("Usage: node scripts/verify_ed25519_real.mjs <receipt.json>"); process.exit(2); }
  verifyReceipt(file).then(res => {
    console.log("signature:", res.ok ? "PASS" : "FAIL");
    if (!res.ok) { console.log("reason:", res.reason); process.exit(1); }
  }).catch(e => { console.error(e); process.exit(2); });
}

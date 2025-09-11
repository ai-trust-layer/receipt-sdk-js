import * as ed from "@noble/ed25519";

const SUBSET_KEYS = ["id","issued_at","input_hash","output_hash","model_version","policy_version"];

export function canonicalizeSubset(r) {
  const obj = {};
  for (const k of SUBSET_KEYS) {
    if (r[k] === undefined) throw new Error(`missing ${k}`);
    obj[k] = r[k];
  }
  return JSON.stringify(obj);
}

export async function verifySignature(receipt) {
  const s = receipt?.signature;
  if (!s) return { ok: false, reason: "not_provided" };
  if (s.alg !== "ed25519" || !s.sig || !s.kid?.startsWith("ed25519:")) {
    return { ok: false, reason: "unsupported_alg" };
  }
  const pubHex = s.kid.slice("ed25519:".length);
  const pub = Uint8Array.from(Buffer.from(pubHex, "hex"));
  const sig = Uint8Array.from(Buffer.from(s.sig, "base64"));
  const msg = new TextEncoder().encode(canonicalizeSubset(receipt));
  const ok = await ed.verify(sig, msg, pub);
  return { ok, reason: ok ? "Signature valid" : "bad_signature" };
}

export default { verifySignature, canonicalizeSubset };

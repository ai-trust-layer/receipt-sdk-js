import * as ed25519 from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
ed25519.etc.sha512Sync = (...m) => sha512(...m);

// Canonicalizăm subsetul stabil (chei sortate)
export function canonicalizeSubset(receipt) {
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
  return JSON.stringify(sortObj(obj));
}

/**
 * Verifică semnătura din receipt.signature
 * Așteptări:
 *  - signature.alg === "ed25519"
 *  - signature.sig = base64(64 bytes)
 *  - signature.kid = "ed25519:<PUBKEY_HEX>" (suport DID în viitor)
 */
export async function verifySignature(receipt) {
  const sigObj = receipt?.signature;
  if (!sigObj) return { ok: false, reason: "not_provided" };
  if (sigObj.alg !== "ed25519") return { ok: false, reason: "alg_unsupported" };
  if (!sigObj.sig) return { ok: false, reason: "sig_missing" };

  let pubHex = null;
  if (typeof sigObj.kid === "string" && sigObj.kid.startsWith("ed25519:")) {
    pubHex = sigObj.kid.split(":")[1];
  }
  if (!pubHex) return { ok: false, reason: "kid_unresolved" };

  try {
    const msg = new TextEncoder().encode(canonicalizeSubset(receipt));
    const sig = Buffer.from(sigObj.sig, "base64");
    const pub = Buffer.from(pubHex, "hex");
    const ok = await ed25519.verify(sig, msg, pub);
    return ok ? { ok: true } : { ok: false, reason: "bad_signature" };
  } catch (e) {
    return { ok: false, reason: "verify_error", error: String(e?.message || e) };
  }
}

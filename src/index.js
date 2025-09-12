import Ajv from "ajv";
import addFormats from "ajv-formats";
import { createRequire } from "module";
import fs from "fs";
const require = createRequire(import.meta.url);

// Load JSON Schema draft-07 meta explicitly (meta:false)
const draft7Meta = require("ajv/dist/refs/json-schema-draft-07.json");
const DRAFT7_ID = "http://json-schema.org/draft-07/schema#";

function loadJsonMaybe(x) {
  if (typeof x === "string") {
    const txt = fs.readFileSync(x, "utf8");
    return JSON.parse(txt);
  }
  return x;
}

function looksLikeSchema(x) {
  return x && typeof x === "object" &&
    (x.$schema || x.$id || x.properties || x.type === "object");
}

export function makeAjv() {
  const ajv = new Ajv({ allErrors: true, strict: false, meta: false });
  ajv.addMetaSchema(draft7Meta);      // register once
  ajv.opts.defaultMeta = DRAFT7_ID;   // use draft-07
  addFormats(ajv);
  return ajv;
}

// Robust: acceptă (schema, data) sau (data, schema); încărcăm fișierele dacă vin ca string.
export function validateSchema(schemaInput, dataInput) {
  let a = loadJsonMaybe(schemaInput);
  let b = loadJsonMaybe(dataInput);

  // Dacă primul NU arată ca schemă iar al doilea DA, inversăm ordinea
  let schema = looksLikeSchema(a) ? a : (looksLikeSchema(b) ? b : a);
  let data   = (schema === a) ? b : a;

  const ajv = makeAjv();
  try {
    const validate = ajv.compile(schema);
    const ok = !!validate(data);
    return { ok, errors: ok ? [] : (validate.errors || []) };
  } catch (e) {
    const msg = String(e && e.message || e);
    // fallback: dacă tot pare să fie inversată ordinea, reîncercăm invers
    if (/keyword "id"/i.test(msg) || /schema must be object or boolean/i.test(msg)) {
      const ajv2 = makeAjv();
      const validate2 = ajv2.compile(loadJsonMaybe(data));
      const ok2 = !!validate2(loadJsonMaybe(schema));
      return { ok: ok2, errors: ok2 ? [] : (validate2.errors || []) };
    }
    throw e;
  }
}

// Stubs (până cablăm implementările reale)
export async function verifySignature(receipt) {
  if (!receipt || !receipt.signature) return { ok: false, reason: "not_provided" };
  return { ok: false, reason: "not_implemented" };
}
export function verifyHashes(/* receipt, opts */) {
  return { ok: false, reason: "not_implemented" };
}
export async function verifyAnchor(/* receipt */) {
  return { ok: false, reason: "not_implemented" };
}

// Necesare pentru CLI
export function computeTrustScore(receipt, parts = {}) {
  if (receipt && typeof receipt.trustscore === "number") {
    const t = receipt.trustscore;
    return Number.isFinite(t) ? Math.max(0, Math.min(100, t)) : 0;
  }
  const sig = parts.signature_ok === true ? 1 : 0;
  const hashes = parts.hashes_ok === true ? 1 : 0;
  const anchor = parts.anchor_ok === true ? 1 : 0;
  return sig*40 + hashes*40 + anchor*20; // max 100
}

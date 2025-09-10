import * as ed25519 from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
ed25519.etc.sha512Sync = (...m) => sha512(...m);

function canonicalizeSubset(r){
  const k=["id","issued_at","input_hash","output_hash","model_version","policy_version"];
  const o={}; for(const x of k) if(r[x]!==undefined) o[x]=r[x];
  const s=(v)=>Array.isArray(v)?v.map(s):(v&&typeof v==="object"?Object.fromEntries(Object.keys(v).sort().map(kk=>[kk,s(v[kk])])):v);
  return JSON.stringify(s(o));
}

const PRIV_HEX="0101010101010101010101010101010101010101010101010101010101010101";

const r={
  id:"rec_demo_cli_001",
  issued_at:"2025-09-10T12:00:00Z",
  input_hash:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  output_hash:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  model_version:"gpt-x-2025-09-01",
  policy_version:"policy-v1.0"
};

const priv=Buffer.from(PRIV_HEX,"hex");
const pub=await ed25519.getPublicKey(priv);
const msg=new TextEncoder().encode(canonicalizeSubset(r));
const sig=await ed25519.sign(msg,priv);

r.signature={
  alg:"ed25519",
  kid:"ed25519:"+Buffer.from(pub).toString("hex"),
  sig:Buffer.from(sig).toString("base64")
};

console.log(JSON.stringify(r,null,2));

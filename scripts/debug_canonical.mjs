import { createHash } from "crypto";
import fs from "fs";
import { canonicalizeSubset } from "../src/signature.mjs";

const p = process.argv[2];
const r = JSON.parse(fs.readFileSync(p, "utf8"));
const s = canonicalizeSubset(r);
const h = createHash("sha256").update(s, "utf8").digest("hex");
console.log("JS CANON_STR:", s);
console.log("JS CANON_SHA256:", h);

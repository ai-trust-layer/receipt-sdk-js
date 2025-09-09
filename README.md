# receipt-sdk-js (v0.1)
Toolkit to validate AI Trust Receipts in Node.js.

## CLI
npx receipt-verify verify examples/ok.json --schema schema/receipt.schema.json --input input.txt --output output.txt

## Node API
import { validateSchema, verifyHashes } from "receipt-sdk-js";

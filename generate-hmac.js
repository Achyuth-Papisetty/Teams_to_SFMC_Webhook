// generate-hmac.js
import crypto from "crypto";
import dotenv from "dotenv";
dotenv.config();

// Same exact body used in Postman — no spaces, no formatting
const body = '{"text":"hello"}';

const secret = process.env.TEAMS_SHARED_SECRET;

const hmac = crypto
  .createHmac("sha256", secret)
  .update(Buffer.from(body, "utf8"))
  .digest("base64");

console.log("Use this header in Postman:");
console.log("Authorization: HMAC " + hmac);

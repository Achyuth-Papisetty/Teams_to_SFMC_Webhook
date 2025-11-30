// server.js
import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();

// Read RAW request body (for HMAC verification)
app.use(bodyParser.text({ type: "*/*" }));

const SHARED_SECRET = process.env.TEAMS_SHARED_SECRET;

// Verify Microsoft Teams HMAC SHA256
function verifySignature(rawBody, header) {
  if (!header || !header.startsWith("HMAC ")) return false;

  const received = header.replace("HMAC ", "").trim();

  // Compute our own HMAC
  const computed = crypto
    .createHmac("sha256", SHARED_SECRET)
    .update(Buffer.from(rawBody, "utf8"))
    .digest("base64");

  return received === computed;
}

// Teams Webhook Endpoint
app.post("/teams", (req, res) => {
  const rawBody = req.body;
  const header = req.headers["authorization"] || "";

  console.log("Incoming Body:", rawBody);
  console.log("Authorization:", header);

  // Validate HMAC
  if (!verifySignature(rawBody, header)) {
    console.log("❌ Invalid HMAC");
    return res.status(401).send("Invalid HMAC Signature");
  }

  console.log("✔ Valid HMAC Signature");

  // Parse JSON safely
  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    payload = { text: rawBody };
  }

  console.log("Teams Payload:", payload);

  // Send text response back to Teams
  return res.json({
    text: "Node.js received your message ✔"
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Teams HMAC proxy running on port ${PORT}`)
);

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

// Debug homepage
app.get("/", (req, res) => {
  res.send("Teams → Node.js webhook is running ✔");
});

// Verify Microsoft Teams HMAC SHA256
function verifySignature(rawBody, header) {
  if (!header || !header.startsWith("HMAC ")) return false;

  const received = header.replace("HMAC ", "").trim();

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
  console.log("RAW LENGTH:", rawBody.length);
  console.log("RAW BYTES:", Buffer.from(rawBody, "utf8"));
  console.log("Authorization:", header);

  // Validate HMAC
  if (!verifySignature(rawBody, header)) {
    console.log("❌ Invalid HMAC");
    return res.status(401).send("Invalid HMAC Signature");
  }

  console.log("✔ Valid HMAC Signature");

  let payload;

  try {
    payload = JSON.parse(rawBody);
  } catch {
    payload = { text: rawBody };
  }

  console.log("Teams Payload:", payload);

  res.json({
    text: "Node.js received your message ✔"
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Teams HMAC proxy running on port ${PORT}`)
);

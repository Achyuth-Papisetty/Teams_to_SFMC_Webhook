// server.js
import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();

// IMPORTANT: use express.raw to get exact bytes Teams sent
// Do not use bodyParser.text/json which may alter bytes.
app.use(express.raw({ type: "*/*", limit: "2mb" }));

const SHARED_SECRET = process.env.TEAMS_SHARED_SECRET;
if (!SHARED_SECRET) {
  console.error("Missing TEAMS_SHARED_SECRET in environment. Exiting.");
  process.exit(1);
}

// Simple health-check root
app.get("/", (req, res) => {
  res.send("Teams → Node.js webhook is running ✔");
});

/**
 * Verify Teams HMAC signature.
 * rawBuffer: Buffer (req.body)
 * header: string value of Authorization header (should start with "HMAC ")
 */
function verifySignature(rawBuffer, header) {
  try {
    if (!header || typeof header !== "string") return false;
    // header format: "HMAC base64string"
    const m = header.match(/^HMAC\s+(.+)$/i);
    if (!m) return false;
    const receivedBase64 = m[1].trim();

    // Compute HMAC over the exact raw bytes
    const computedBuffer = crypto
      .createHmac("sha256", SHARED_SECRET)
      .update(rawBuffer)
      .digest();

    const receivedBuffer = Buffer.from(receivedBase64, "base64");

    // Must be same length
    if (receivedBuffer.length !== computedBuffer.length) return false;

    // Use timingSafeEqual for constant-time comparison
    return crypto.timingSafeEqual(computedBuffer, receivedBuffer);
  } catch (err) {
    console.error("verifySignature error:", err);
    return false;
  }
}

app.post("/teams", (req, res) => {
  try {
    const rawBuffer = req.body; // Buffer because of express.raw
    const header = req.headers["authorization"] || "";

    // Logging - helpful for debugging (remove/limit in production)
    console.log("Incoming Body (string preview):", rawBuffer.toString("utf8").slice(0, 1000));
    console.log("RAW LENGTH:", rawBuffer.length);
    console.log("RAW BYTES (first 200 bytes):", rawBuffer.slice(0, 200));
    console.log("Authorization:", header);

    // Validate HMAC using raw bytes
    const ok = verifySignature(rawBuffer, header);
    if (!ok) {
      console.warn("❌ Invalid HMAC");
      return res.status(401).send("Invalid HMAC Signature");
    }

    console.log("✔ Valid HMAC Signature");

    // Now parse the UTF-8 string safely (payload may be large)
    const rawString = rawBuffer.toString("utf8");
    let payload;
    try {
      payload = JSON.parse(rawString);
    } catch (e) {
      // If parse fails, fallback to the raw string
      payload = { text: rawString };
    }

    // TODO: Handle payload (store in DB/forward to SFMC etc.)
    console.log("Teams Payload:", payload && payload.text ? payload.text : "(no text)");

    // immediate JSON response to Teams
    return res.json({ text: "Node.js received your message ✔" });
  } catch (err) {
    console.error("Handler error:", err);
    return res.status(500).send("Server error");
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Teams HMAC proxy running on port ${PORT}`);
});

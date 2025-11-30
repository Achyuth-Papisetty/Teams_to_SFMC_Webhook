// server.js
import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();

// Raw buffer, but we will NOT verify HMAC on the raw JSON (Teams doesn't sign it)
app.use(express.raw({ type: "*/*", limit: "4mb" }));

const SHARED_SECRET = process.env.TEAMS_SHARED_SECRET;

// Build canonical string that Teams actually signs
function buildCanonicalBody(textField) {
  return Buffer.from(JSON.stringify({ text: textField }), "utf8");
}

function computeHmac(buffer) {
  return crypto.createHmac("sha256", SHARED_SECRET).update(buffer).digest();
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

app.post("/teams", (req, res) => {
  const header = req.headers["authorization"] || "";

  if (!header.startsWith("HMAC ")) {
    return res.status(401).send("Missing HMAC");
  }

  const receivedHmacBase64 = header.replace("HMAC ", "").trim();
  const receivedBuffer = Buffer.from(receivedHmacBase64, "base64");

  // Parse incoming payload
  let payload;
  try {
    payload = JSON.parse(req.body.toString("utf8"));
  } catch {
    return res.status(400).send("Invalid JSON");
  }

  // Extract the canonical text field (Teams signs only this)
  const textField = payload.text || "";

  // Build canonical HMAC body
  const canonicalBuffer = buildCanonicalBody(textField);

  // Compute canonical HMAC
  const computed = computeHmac(canonicalBuffer);

  if (!safeEqual(computed, receivedBuffer)) {
    console.log("❌ Invalid HMAC canonical comparison failed");
    console.log("Canonical used:", canonicalBuffer.toString());
    return res.status(401).send("Invalid HMAC Signature");
  }

  console.log("✔ Valid HMAC using canonical Teams method");

  return res.json({
    text: "Node.js received your message ✔ (verified)"
  });
});

app.get("/", (req, res) => {
  res.send("Teams → Node.js HMAC webhook running ✔");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Running on port ${PORT}`));

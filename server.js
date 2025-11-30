import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();
// Accept raw body (SFMC will send JSON as text)
app.use(express.raw({ type: "*/*", limit: "8mb" }));

const SECRET_BASE64 = process.env.TEAMS_SHARED_SECRET;
if (!SECRET_BASE64) {
  console.error("Missing TEAMS_SHARED_SECRET in environment!");
  process.exit(1);
}

// Decode base64 Teams secret → raw key bytes
const SECRET_KEY = Buffer.from(SECRET_BASE64, "base64");

// Safe compare
function safeEqual(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) return false;
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// Compute HMAC
function computeHmac(buf) {
  return crypto.createHmac("sha256", SECRET_KEY).update(buf).digest();
}

// Strip <at> tags, HTML tags
function htmlToPlain(html) {
  return html
    .replace(/<at[^>]*>(.*?)<\/at>/gi, "@$1")
    .replace(/&nbsp;/gi, " ")
    .replace(/<[^>]+>/g, "")
    .trim();
}

// Build canonical Activity object
function canonicalActivity(obj) {
  return Buffer.from(
    JSON.stringify({
      type: obj.type,
      id: obj.id,
      timestamp: obj.timestamp,
      text: htmlToPlain(obj.text || "")
    }),
    "utf8"
  );
}

app.post("/teams", (req, res) => {
  try {
    // CloudPage sends:
    // { body: "<raw Teams JSON>", hmac: "HMAC xyz==" }
    const wrapper = JSON.parse(req.body.toString("utf8"));

    const rawTeamsString = wrapper.body;
    const authHeader = wrapper.hmac || "";
    const rawBuffer = Buffer.from(rawTeamsString, "utf8");

    console.log("RAW LENGTH:", rawBuffer.length);
    console.log("AUTH FROM SFMC PAYLOAD:", authHeader.slice(0, 20) + "...");

    if (!authHeader || !authHeader.toUpperCase().startsWith("HMAC ")) {
      console.log("Missing HMAC");
      return res.status(401).json({ error: "Missing HMAC" });
    }

    const incomingBase64 = authHeader.substring(5).trim();
    const incomingBuffer = Buffer.from(incomingBase64, "base64");

    // Attempt 1 → raw-body verification
    const computedRaw = computeHmac(rawBuffer);
    if (safeEqual(computedRaw, incomingBuffer)) {
      console.log("✔ Verified using RAW method");
      const parsed = JSON.parse(rawTeamsString);
      return res.json({ text: htmlToPlain(parsed.text || "") });
    }

    // Attempt 2 → canonical fallback
    const parsed = JSON.parse(rawTeamsString);
    const canonicalBuf = canonicalActivity(parsed);
    const computedCanonical = computeHmac(canonicalBuf);

    if (safeEqual(computedCanonical, incomingBuffer)) {
      console.log("✔ Verified using CANONICAL fallback");
      return res.json({ text: htmlToPlain(parsed.text || "") });
    }

    console.log("❌ Invalid HMAC (RAW + CANONICAL failed)");
    return res.status(401).json({ error: "Invalid HMAC" });

  } catch (err) {
    console.error("Server error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.get("/", (req, res) => res.send("Teams → Render HMAC OK"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("listening on " + PORT));

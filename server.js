// server.js — robust Teams Outgoing Webhook HMAC verification
import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();
// preserve exact bytes (IMPORTANT)
app.use(express.raw({ type: "*/*", limit: "8mb" }));

const SECRET_BASE64 = process.env.TEAMS_SHARED_SECRET;
if (!SECRET_BASE64) {
  console.error("Missing TEAMS_SHARED_SECRET (base64) in env. Set TEAMS_SHARED_SECRET.");
  process.exit(1);
}

// decode base64 secret to raw key bytes (CRITICAL)
const SECRET_KEY = Buffer.from(SECRET_BASE64, "base64");

// timing-safe compare
function safeEqual(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) return false;
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// compute HMAC using key bytes
function computeHmacBuffer(buffer) {
  return crypto.createHmac("sha256", SECRET_KEY).update(buffer).digest();
}

// helper: convert Teams HTML text to plain text (strip <at> -> @name, entities)
function htmlToPlain(html) {
  if (!html) return "";
  // replace <at>NAME</at> with @NAME
  let s = html.replace(/<at[^>]*>(.*?)<\/at>/gi, (m, p1) => "@" + p1);
  // convert common HTML entities
  s = s.replace(/&nbsp;/gi, " ").replace(/&amp;/gi, "&").replace(/&lt;/gi, "<").replace(/&gt;/gi, ">");
  // remove other tags
  s = s.replace(/<[^>]+>/g, "");
  return s.trim();
}

// Reconstruct minimal Activity object (fallback) — include the fields commonly used
function buildCanonicalActivityFromPayload(obj) {
  const plainText = htmlToPlain(obj.text || "");
  const activity = {
    type: obj.type,
    id: obj.id,
    timestamp: obj.timestamp,
    serviceUrl: obj.serviceUrl,
    channelId: obj.channelId,
    from: obj.from || null,
    conversation: obj.conversation || null,
    recipient: obj.recipient || null,
    text: plainText,
    locale: obj.locale || null
  };
  return Buffer.from(JSON.stringify(activity), "utf8");
}

app.post("/teams", (req, res) => {
  try {
    const rawBuffer = req.body; // Buffer from express.raw
    const auth = (req.headers["authorization"] || "").trim();

    console.log("RAW LENGTH:", rawBuffer.length);
    console.log("Authorization header preview:", auth ? auth.slice(0, 20) + "..." : "(missing)");

    if (!auth || !auth.toUpperCase().startsWith("HMAC ")) {
      return res.status(401).send("Missing HMAC authorization header");
    }

    const incomingBase64 = auth.substring(5).trim();
    let incomingBuffer;
    try {
      incomingBuffer = Buffer.from(incomingBase64, "base64");
    } catch (e) {
      console.warn("Invalid base64 in Authorization header");
      return res.status(401).send("Invalid HMAC header");
    }

    // === Attempt 1: verify HMAC over the raw body bytes (official doc method) ===
    const computedRaw = computeHmacBuffer(rawBuffer);
    if (safeEqual(computedRaw, incomingBuffer)) {
      console.log("✔ HMAC verified with raw-body method (official)");
      const payload = (function () { try { return JSON.parse(rawBuffer.toString("utf8")); } catch { return null; } })();
      // handle payload as needed (forward to SFMC etc.)
      return res.json({ text: "Received (verified raw-body)" });
    }

    // === Attempt 2: fallback — reconstruct canonical Activity (plain text) ===
    let parsed;
    try {
      parsed = JSON.parse(rawBuffer.toString("utf8"));
    } catch (e) {
      parsed = null;
    }

    if (parsed) {
      const canonicalBuf = buildCanonicalActivityFromPayload(parsed);
      const computedCanonical = computeHmacBuffer(canonicalBuf);
      if (safeEqual(computedCanonical, incomingBuffer)) {
        console.log("✔ HMAC verified with canonical Activity fallback");
        return res.json({ text: "Received (verified canonical)" });
      } else {
        console.warn("Canonical fallback did not match HMAC");
        console.log("Canonical preview:", canonicalBuf.toString("utf8").slice(0, 300));
      }
    } else {
      console.warn("Could not parse incoming body as JSON for canonical fallback");
    }

    // nothing matched
    console.warn("❌ Invalid HMAC (no verification method matched)");
    return res.status(401).send("Invalid HMAC Signature");
  } catch (err) {
    console.error("Handler error", err);
    return res.status(500).send("Server error");
  }
});

// health
app.get("/", (req, res) => res.send("Teams HMAC proxy OK"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`listening on ${PORT}`));

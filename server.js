import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();

// Accept RAW request body from SFMC AND Teams
app.use(express.raw({ type: "*/*", limit: "8mb" }));

const SECRET_BASE64 = process.env.TEAMS_SHARED_SECRET;

if (!SECRET_BASE64) {
  console.error("Missing TEAMS_SHARED_SECRET!");
  process.exit(1);
}

const SECRET_KEY = Buffer.from(SECRET_BASE64, "base64");

// Safe compare
function safeEqual(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) return false;
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function computeHmac(buf) {
  return crypto.createHmac("sha256", SECRET_KEY).update(buf).digest();
}

function htmlToPlain(html = "") {
  return String(html)
    .replace(/<at[^>]*>(.*?)<\/at>/gi, "@$1")
    .replace(/&nbsp;/gi, " ")
    .replace(/<[^>]+>/g, "")
    .trim();
}

app.post("/teams", (req, res) => {
  try {
    const rawStr = req.body.toString("utf8");

    // Try to parse raw payload
    let wrapper = null;
    try { wrapper = JSON.parse(rawStr); } catch (e) {}

    let rawTeamsString = "";
    let authHeader = "";

    // ============================================
    // CASE 1 — SFMC WRAPPER:
    // { body:"<string>", hmac:"HMAC xxx==" }
    // ============================================
    if (wrapper && wrapper.body && wrapper.hmac) {
      rawTeamsString = wrapper.body;
      authHeader = wrapper.hmac;
    }

    // ============================================
    // CASE 2 — CLOUDPAGE DIRECT SEND:
    // rawTeamsString = rawStr; (Teams body)
    // Auth header must be taken from incoming header
    // ============================================
    else {
      rawTeamsString = rawStr;
      authHeader = req.headers["authorization"] || "";
    }

    console.log("RAW LENGTH:", Buffer.byteLength(rawTeamsString));
    console.log("AUTH:", authHeader.slice(0, 20) + "...");

    if (!authHeader || !authHeader.toUpperCase().startsWith("HMAC ")) {
      return res.status(401).json({ error: "Missing HMAC" });
    }

    const incomingBase64 = authHeader.substring(5).trim();
    const incomingBuffer = Buffer.from(incomingBase64, "base64");

    const rawBuffer = Buffer.from(rawTeamsString, "utf8");

    // Attempt 1 — raw-body HMAC
    const computedRaw = computeHmac(rawBuffer);
    if (safeEqual(computedRaw, incomingBuffer)) {
      const parsed = JSON.parse(rawTeamsString);
      return res.json({ text: htmlToPlain(parsed.text || "") });
    }

    // Attempt 2 — fallback canonical mode
    const parsed = JSON.parse(rawTeamsString);
    const canonical = Buffer.from(
      JSON.stringify({
        type: parsed.type,
        id: parsed.id,
        timestamp: parsed.timestamp,
        text: htmlToPlain(parsed.text || "")
      }),
      "utf8"
    );

    const computedCanonical = computeHmac(canonical);
    if (safeEqual(computedCanonical, incomingBuffer)) {
      return res.json({ text: htmlToPlain(parsed.text || "") });
    }

    return res.status(401).json({ error: "Invalid HMAC" });

  } catch (err) {
    console.error("Server error:", err);
    return res.status(200).json({ text: "OK" });
  }
});

app.get("/", (req, res) => res.send("Teams → Render HMAC OK"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("listening on " + PORT));

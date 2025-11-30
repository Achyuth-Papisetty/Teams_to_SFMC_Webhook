// server.js (production)
import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.raw({ type: "*/*", limit: "8mb" }));

const SECRET_BASE64 = process.env.TEAMS_SHARED_SECRET;
if (!SECRET_BASE64) {
  console.error("Missing TEAMS_SHARED_SECRET env var (base64)");
  process.exit(1);
}
const SECRET_KEY = Buffer.from(SECRET_BASE64, "base64");

function safeEqual(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) return false;
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
function computeHmac(buf) {
  return crypto.createHmac("sha256", SECRET_KEY).update(buf).digest();
}
function htmlToPlain(html) {
  if (!html) return "";
  return html
    .replace(/<at[^>]*>(.*?)<\/at>/gi, "@$1")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/<[^>]+>/g, "")
    .replace(/\s+/g, " ")
    .trim();
}
function tryParseWrapper(raw) {
  try {
    const obj = JSON.parse(raw);
    if (obj && typeof obj === "object" && obj.body && obj.hmac) {
      return { bodyStr: String(obj.body), hmacHeader: String(obj.hmac) };
    }
  } catch (e) {}
  return null;
}

app.post("/teams", (req, res) => {
  try {
    const rawText = req.body.toString("utf8");
    const wrapper = tryParseWrapper(rawText);

    let teamsRawString, authHeader;
    if (wrapper) {
      teamsRawString = wrapper.bodyStr;
      authHeader = wrapper.hmacHeader;
    } else {
      teamsRawString = rawText;
      authHeader = (req.headers["authorization"] || "").toString();
    }

    if (!teamsRawString) return res.status(400).json({ error: "Missing payload" });
    if (!authHeader || !authHeader.toUpperCase().startsWith("HMAC ")) return res.status(401).json({ error: "Missing HMAC" });

    let incomingBuf;
    try {
      incomingBuf = Buffer.from(authHeader.substring(5).trim(), "base64");
    } catch {
      return res.status(401).json({ error: "Invalid HMAC header" });
    }

    const rawBuf = Buffer.from(teamsRawString, "utf8");

    // Attempt 1: raw-body verification
    const computedRaw = computeHmac(rawBuf);
    if (safeEqual(computedRaw, incomingBuf)) {
      const parsed = JSON.parse(teamsRawString);
      return res.json({ text: htmlToPlain(parsed.text || "") });
    }

    // Attempt 2: canonical activity fallback
    let parsedTeams = null;
    try { parsedTeams = JSON.parse(teamsRawString); } catch (e) { parsedTeams = null; }
    if (parsedTeams) {
      const canonical = Buffer.from(JSON.stringify({
        type: parsedTeams.type,
        id: parsedTeams.id,
        timestamp: parsedTeams.timestamp,
        text: htmlToPlain(parsedTeams.text || "")
      }), "utf8");
      const computedCanonical = computeHmac(canonical);
      if (safeEqual(computedCanonical, incomingBuf)) {
        return res.json({ text: htmlToPlain(parsedTeams.text || "") });
      }
    }

    return res.status(401).json({ error: "Invalid HMAC" });
  } catch (err) {
    console.error("handler error:", err);
    return res.status(500).json({ error: "server error" });
  }
});

app.get("/", (req, res) => res.send("Teams HMAC proxy OK"));
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`listening on ${PORT}`));

import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.raw({ type: "*/*", limit: "4mb" }));

const SHARED_SECRET = process.env.TEAMS_SHARED_SECRET;

// Convert Teams HTML to plain text
function htmlToPlain(html) {
  if (!html) return "";

  // Extract mention replacement text
  html = html.replace(/<at[^>]*>(.*?)<\/at>/gi, (m, p1) => {
    return "@" + p1;
  });

  // Replace HTML entities
  html = html.replace(/&nbsp;/gi, " ");
  html = html.replace(/&amp;/gi, "&");
  html = html.replace(/&lt;/gi, "<");
  html = html.replace(/&gt;/gi, ">");

  // Remove all remaining tags
  html = html.replace(/<[^>]+>/g, "");

  return html.trim();
}

function computeHmac(buffer) {
  return crypto.createHmac("sha256", SHARED_SECRET).update(buffer).digest();
}

function safeEqual(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

app.post("/teams", (req, res) => {
  const header = req.headers["authorization"] || "";
  if (!header.startsWith("HMAC ")) {
    return res.status(401).send("Missing HMAC");
  }

  const incoming = header.replace("HMAC ", "").trim();
  const incomingBuf = Buffer.from(incoming, "base64");

  let body;
  try {
    body = JSON.parse(req.body.toString("utf8"));
  } catch {
    return res.status(400).send("Bad JSON");
  }

  const html = body.text || "";
  const plain = htmlToPlain(html);

  // Build canonical body that Teams signs
  const canonicalJson = JSON.stringify({ text: plain });
  const canonicalBuf = Buffer.from(canonicalJson, "utf8");

  const computed = computeHmac(canonicalBuf);

  if (!safeEqual(computed, incomingBuf)) {
    console.log("❌ Invalid HMAC");
    console.log("HTML text:", html);
    console.log("Plain text:", plain);
    console.log("Canonical:", canonicalJson);
    return res.status(401).send("Invalid HMAC Signature");
  }

  console.log("✔ Valid HMAC (Teams HTML→PlainText method)");
  console.log("Plain text:", plain);

  return res.json({
    text: "Message received ✔ (verified)"
  });
});

app.get("/", (req, res) => {
  res.send("Teams → Node.js webhook running ✔ (final version)");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Running on port", PORT));

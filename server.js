import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.raw({ type: "*/*", limit: "4mb" }));

const SECRET = process.env.TEAMS_SHARED_SECRET;

// Convert Teams HTML into plain text
function htmlToPlain(html) {
  return html
    .replace(/<at[^>]*>(.*?)<\/at>/gi, "@$1")
    .replace(/&nbsp;/gi, " ")
    .replace(/<[^>]+>/g, "")
    .trim();
}

function computeHmac(buffer) {
  return crypto.createHmac("sha256", SECRET).update(buffer).digest();
}

function safeEqual(a, b) {  
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

app.post("/teams", (req, res) => {
  const header = req.headers["authorization"] || "";

  if (!header.startsWith("HMAC ")) {
    return res.status(401).send("Missing HMAC");
  }

  let payload;
  try {
    payload = JSON.parse(req.body.toString("utf8"));
  } catch {
    return res.status(400).send("Invalid JSON");
  }

  // Extract required components for Activity-based signing
  const id = payload.id;
  const timestamp = payload.timestamp;
  const textHtml = payload.text || "";
  const plainText = htmlToPlain(textHtml);

  // Construct the real signed Activity
  const signedActivity = JSON.stringify({
    type: "message",
    id,
    timestamp,
    text: plainText
  });

  const computed = computeHmac(Buffer.from(signedActivity, "utf8"));

  const incomingHmac = header.replace("HMAC ", "").trim();
  const incomingBuf = Buffer.from(incomingHmac, "base64");

  if (!safeEqual(computed, incomingBuf)) {
    console.log("❌ Invalid HMAC");
    console.log("Signed Activity:", signedActivity);
    return res.status(401).send("Invalid HMAC Signature");
  }

  console.log("✔ Valid HMAC Activity verification");

  return res.json({ text: "Verified ✔" });
});

app.listen(process.env.PORT || 3000, () => {
  console.log("Running…");
});

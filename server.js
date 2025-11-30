import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.raw({ type: "*/*", limit: "4mb" }));

const SECRET = process.env.TEAMS_SHARED_SECRET;

function htmlToPlain(html) {
  return html
    .replace(/<at[^>]*>(.*?)<\/at>/gi, "@$1")
    .replace(/&nbsp;/gi, " ")
    .replace(/<[^>]+>/g, "")
    .trim();
}

function computeHmac(buf) {
  return crypto.createHmac("sha256", SECRET).update(buf).digest();
}

function safeEqual(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

app.post("/teams", (req, res) => {
  const header = req.headers["authorization"];

  if (!header || !header.startsWith("HMAC ")) {
    return res.status(401).send("Missing HMAC");
  }

  let obj;
  try {
    obj = JSON.parse(req.body.toString("utf8"));
  } catch {
    return res.status(400).send("Invalid JSON");
  }

  const plainText = htmlToPlain(obj.text || "");

  // THIS IS THE TRUE SIGNED ACTIVITY (using full Teams payload)
  const activity = {
    type: obj.type,
    id: obj.id,
    timestamp: obj.timestamp,
    localTimestamp: obj.localTimestamp,
    localTimezone: obj.localTimezone,
    serviceUrl: obj.serviceUrl,
    channelId: obj.channelId,
    from: obj.from,
    conversation: obj.conversation,
    recipient: obj.recipient || null,
    textFormat: obj.textFormat,
    locale: obj.locale,
    text: plainText,
    attachments: obj.attachments || [],
    entities: obj.entities || [],
    channelData: obj.channelData || {}
  };

  const canonical = JSON.stringify(activity);
  const canonicalBuf = Buffer.from(canonical, "utf8");

  const incoming = header.replace("HMAC ", "").trim();
  const incomingBuf = Buffer.from(incoming, "base64");

  const computed = computeHmac(canonicalBuf);

  if (!safeEqual(computed, incomingBuf)) {
    console.log("❌ Invalid HMAC");
    console.log("Canonical:", canonical);
    return res.status(401).send("Invalid HMAC Signature");
  }

  console.log("✔ VALID HMAC (Full Activity Match)");

  return res.json({ text: "Verified ✔" });
});

app.get("/", (req, res) => {
  res.send("Teams webhook running ✔");
});

app.listen(process.env.PORT || 3000, () =>
  console.log("Running...")
);

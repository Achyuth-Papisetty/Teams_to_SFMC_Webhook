// server.js
import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();

// Get raw bytes for HMAC verification
app.use(express.raw({ type: "*/*", limit: "4mb" }));

const SHARED_SECRET = process.env.TEAMS_SHARED_SECRET;
if (!SHARED_SECRET) {
  console.error("Missing TEAMS_SHARED_SECRET in environment. Exiting.");
  process.exit(1);
}

// Health check route
app.get("/", (req, res) => {
  res.send("Teams → Node.js webhook is running ✔");
});

/**
 * Compute HMAC-SHA256 Buffer from raw bytes.
 */
function computeHmac(rawBuffer) {
  return crypto
    .createHmac("sha256", SHARED_SECRET)
    .update(rawBuffer)
    .digest();
}

/**
 * Timing-safe compare buffers.
 */
function safeEqual(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) return false;
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Produce multiple byte variants to match Teams HMAC variations.
 */
function generateVariants(rawBuffer) {
  const variants = [];

  const asString = rawBuffer.toString("utf8");

  // 1) exact
  variants.push({ name: "exact", buffer: rawBuffer });

  // 2) Trim CRLF
  const trimmed = asString.replace(/[\r\n]+$/g, "");
  if (trimmed !== asString) {
    variants.push({
      name: "trim-crlf",
      buffer: Buffer.from(trimmed, "utf8"),
    });
  }

  // 3) CRLF → LF normalize
  const normalizedLF = asString.replace(/\r\n/g, "\n");
  if (normalizedLF !== asString) {
    variants.push({
      name: "normalize-crlf-lf",
      buffer: Buffer.from(normalizedLF, "utf8"),
    });
  }

  // 4) Remove BOM
  if (rawBuffer[0] === 0xef && rawBuffer[1] === 0xbb && rawBuffer[2] === 0xbf) {
    variants.push({
      name: "remove-bom",
      buffer: rawBuffer.slice(3),
    });
  }

  // 5) JSON-stable-stringify
  try {
    const json = JSON.parse(asString);
    const stable = JSON.stringify(json);
    if (stable !== asString) {
      variants.push({
        name: "json-stable",
        buffer: Buffer.from(stable, "utf8"),
      });
    }
  } catch (e) {}

  // Remove duplicates
  const out = {};
  variants.forEach((v) => {
    out[v.buffer.toString("base64")] = v;
  });

  return Object.values(out);
}

/**
 * Try HMAC verification across variants.
 */
function verifyAcrossVariants(rawBuffer, header) {
  if (!header || !header.startsWith("HMAC ")) return { ok: false };

  const received = header.replace("HMAC ", "").trim();
  let receivedBuf;
  try {
    receivedBuf = Buffer.from(received, "base64");
  } catch {
    return { ok: false };
  }

  const variants = generateVariants(rawBuffer);

  for (const v of variants) {
    const computed = computeHmac(v.buffer);
    if (safeEqual(computed, receivedBuf)) {
      return { ok: true, variant: v.name };
    }
  }

  return { ok: false };
}

// Teams endpoint
app.post("/teams", (req, res) => {
  const rawBuffer = req.body;
  const header = req.headers["authorization"] || "";

  console.log("RAW LENGTH:", rawBuffer.length);
  console.log("Authorization:", header);

  const result = verifyAcrossVariants(rawBuffer, header);

  if (!result.ok) {
    console.log("❌ Invalid HMAC");
    return res.status(401).send("Invalid HMAC Signature");
  }

  console.log("✔ Valid HMAC Signature via variant:", result.variant);

  // Parse payload
  let payload;
  try {
    payload = JSON.parse(rawBuffer.toString("utf8"));
  } catch {
    payload = { text: rawBuffer.toString("utf8") };
  }

  console.log("Teams text:", payload.text);

  res.json({
    text: "Node.js received your message ✔ (verified)",
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Teams HMAC proxy running on port ${PORT}`)
);

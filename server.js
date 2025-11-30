// server.js
import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

const app = express();

// Get raw bytes (exact bytes) for HMAC verification
app.use(express.raw({ type: "*/*", limit: "4mb" }));

const SHARED_SECRET = process.env.TEAMS_SHARED_SECRET;
if (!SHARED_SECRET) {
  console.error("Missing TEAMS_SHARED_SECRET in environment. Exiting.");
  process.exit(1);
}

app.get("/", (req, res) => {
  res.send("Teams → Node.js webhook is running ✔");
}

/**
 * Compute HMAC-SHA256 buffer from raw buffer using shared secret.
 * Returns Buffer.
 */
function computeHmacBuffer(rawBuffer) {
  return crypto.createHmac("sha256", SHARED_SECRET).update(rawBuffer).digest();
}

/**
 * Constant-time compare buffers (safe).
 */
function safeEqual(bufA, bufB) {
  if (!Buffer.isBuffer(bufA) || !Buffer.isBuffer(bufB)) return false;
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Generate a list of plausible rawBuffer variants to try verification on.
 * Each variant is an object { name, buffer }.
 */
function generateVariants(rawBuffer) {
  const variants = [];

  // 1) exact
  variants.push({ name: "exact", buffer: rawBuffer });

  // Helper: convert buffer -> utf8 string safely
  const asStr = rawBuffer.toString("utf8");

  // 2) trimmed trailing CRLF / CR / LF
  const trimmedStr = asStr.replace(/[\r\n]+$/u, "");
  if (trimmedStr !== asStr) {
    variants.push({ name: "trim-trailing-crlf", buffer: Buffer.from(trimmedStr, "utf8") });
  }

  // 3) normalize CRLF -> LF
  const normalizedLF = asStr.replace(/\r\n/g, "\n");
  if (normalizedLF !== asStr) {
    variants.push({ name: "normalize-crlf->lf", buffer: Buffer.from(normalizedLF, "utf8") });
  }

  // 4) remove UTF-8 BOM if present
  if (asStr.charCodeAt(0) === 0xfeff || asStr.charCodeAt(0) === 0xEF) { 
    // note: check both possibilities; simpler is to test byte sequence
    const noBomBuf = rawBuffer;
    // remove BOM bytes if present (EF BB BF)
    if (rawBuffer.length >= 3 && rawBuffer[0] === 0xEF && rawBuffer[1] === 0xBB && rawBuffer[2] === 0xBF) {
      variants.push({ name: "remove-bom", buffer: rawBuffer.slice(3) });
    }
  } else {
    // Also defensively try removing BOM even if first char test failed (safe)
    if (rawBuffer.length >= 3 && rawBuffer[0] === 0xEF && rawBuffer[1] === 0xBB && rawBuffer[2] === 0xBF) {
      variants.push({ name: "remove-bom", buffer: rawBuffer.slice(3) });
    }
  }

  // 5) re-encode parsed JSON -> stable string (JSON.stringify) then buffer
  try {
    const parsed = JSON.parse(asStr);
    const stable = JSON.stringify(parsed);
    if (stable !== asStr) {
      variants.push({ name: "json-stringified", buffer: Buffer.from(stable, "utf8") });
    }
  } catch (e) {
    // ignore parse error
  }

  // 6) trim trailing space characters
  const trimmedSpace = asStr.replace(/\s+$/u, "");
  if (trimmedSpace !== asStr) {
    variants.push({ name: "trim-trailing-space", buffer: Buffer.from(trimmedSpace, "utf8") });
  }

  // 7) if CRLF present, try CRLF->CR only (rare)
  const crOnly = asStr.replace(/\r\n/g, "\r");
  if (crOnly !== asStr) {
    variants.push({ name: "normalize-crlf->cr", buffer: Buffer.from(crOnly, "utf8") });
  }

  // Remove duplicate buffers (avoid repeated work)
  const unique = [];
  const seen = new Set();
  for (const v of variants) {
    const key = v.buffer.toString("base64");
    if (!seen.has(key)) {
      unique.push(v);
      seen.add(key);
    }
  }
  return unique;
}

/**
 * Try verification across variants; returns object { ok, variantName }.
 */
function verifyAcrossVariants(rawBuffer, header) {
  if (!header || typeof header !== "string") return { ok: false };

  const match = header.match(/^HMAC\s+(.+)$/i);
  if (!match) return { ok: false };

  const receivedBase64 = match[1].trim();
  let receivedBuffer;
  try {
    receivedBuffer = Buffer.from(receivedBase64, "base64");
  } catch (e) {
    return { ok: false };
  }

  const candidates = generateVariants(rawBuffer);

  for (const v of candidates) {
    const computed = computeHmacBuffer(v.buffer);
    if (computed.length === receivedBuffer.length && safeEqual(computed, receivedBuffer)) {
      return { ok: true, variant: v.name };
    }
  }
  return { ok: false };
}

// Main endpoint
app.post("/teams", (req, res) => {
  try {
    const rawBuffer = req.body; // Buffer
    const header = req.headers["authorization"] || "";

    console.log("RAW LENGTH:", rawBuffer.length);
    console.log("Authorization:", header);

    const result = verifyAcrossVariants(rawBuffer, header);

    if (!result.ok) {
      console.warn("❌ Invalid HMAC (no variant matched)");
      // For debugging also show a short preview
      console.log("Preview (first 500 chars):", rawBuffer.toString("utf8").slice(0, 500));
      return res.status(401).send("Invalid HMAC Signature");
    }

    console.log("✔ Valid HMAC Signature. Matched variant:", result.variant);

    // Parse and handle payload
    const rawString = rawBuffer.toString("utf8");
    let payload;
    try {
      payload = JSON.parse(rawString);
    } catch (err) {
      payload = { text: rawString };
    }

    console.log("Teams Payload text preview:", (payload && payload.text) ? payload.text.slice(0,200) : "(no text)");

    // TODO: forward to SFMC / DE insert / etc.

    return res.json({ text: "Node.js received your message ✔ (verified)" });
  } catch (err) {
    console.error("Handler error:", err);
    return res.status(500).send("Server error");
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Teams HMAC proxy running on port ${PORT}`));

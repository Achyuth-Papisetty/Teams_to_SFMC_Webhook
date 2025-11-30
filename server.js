// server.js
import express from "express";
import crypto from "crypto";
import bodyParser from "body-parser";
import dotenv from "dotenv";
dotenv.config();

const app = express();
// read raw body as text (important)
app.use(bodyParser.text({ type: "*/*" }));

const SHARED_SECRET = process.env.TEAMS_SHARED_SECRET; // set in .env

function verifySignature(rawBody, header) {
  if (!header || !header.startsWith("HMAC ")) return false;
  const receivedBase64 = header.substring(5).trim(); // remove "HMAC "
  const hmac = crypto.createHmac("sha256", SHARED_SECRET);
  hmac.update(Buffer.from(rawBody, "utf8"));
  const computedBase64 = hmac.digest("base64");
  return computedBase64 === receivedBase64;
}

app.post("/teams", (req, res) => {
  const raw = req.body; // exact raw string
  const auth = req.headers["authorization"] || "";

  console.log("raw body:", raw);
  console.log("authorization:", auth);

  if (!verifySignature(raw, auth)) {
    console.warn("Invalid HMAC");
    return res.status(401).send("Invalid HMAC");
  }

  // parse JSON now that it's verified
  const payload = JSON.parse(raw);
  console.log("Verified payload:", payload);

  // Simple text reply (Teams will display it)
  return res.json({ text: "Received — thanks!" });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`listening ${port}`));

const crypto = require("node:crypto");

require("dotenv").config();

const SECRETKEY = process.env.JWT_SECRET_KEY;

const signToken = () => {
  const rawHeader = {
    alg: "HS256",
    typ: "JWT",
    kid: "default",
  };

  const rawPayload = {
    sub: "1234567890",
    name: "Yoseph",
    iat: 1516239022,
  };

  const encHeader = Buffer.from(JSON.stringify(rawHeader)).toString(
    "base64url"
  );

  const encPayload = Buffer.from(JSON.stringify(rawPayload)).toString(
    "base64url"
  );

  const signature = crypto
    .createHmac("SHA256", Buffer.from(SECRETKEY, "base64url"))
    .update(`${encHeader}.${encPayload}`)
    .digest("base64url");

  return `${encHeader}.${encPayload}.${signature}`;
};

const verifyToken = (token) => {
  const [header, payload, signature] = token.split(".");
  const compareSignature = require("node:crypto")
    .createHmac("sha256", Buffer.from(SECRETKEY, "base64url"))
    .update(`${header}.${payload}`)
    .digest("base64url");

  if (signature !== compareSignature) throw new Error("signature not valid");

  const decodePayload = Buffer.from(payload, "base64url").toString("utf-8");
  return JSON.parse(decodePayload);
};

const main = () => {
  const token = signToken();
  console.log(token);
  const decodeToken = verifyToken(token);
  console.log(decodeToken);
};

main();

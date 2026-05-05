import crypto from "crypto";

function base64ToBuffer(b64) {
  return Buffer.from(b64, "base64");
}

function signRedsys(paramsB64, orderId, secretB64) {

  const key = base64ToBuffer(secretB64);

  // 🔴 DERIVACIÓN CORRECTA REDSYS (3DES-like)
  const iv = Buffer.alloc(8, 0);

  const cipher = crypto.createCipheriv(
    "des-ede3-cbc",
    key.slice(0, 24),
    iv
  );

  let orderEncrypted = cipher.update(orderId, "utf8");
  orderEncrypted = Buffer.concat([orderEncrypted, cipher.final()]);

  // clave derivada XOR base64 decode
  const derivedKey = orderEncrypted.slice(0, 32);

  const hmac = crypto.createHmac("sha256", derivedKey);
  hmac.update(paramsB64);

  return hmac.digest("base64");
}

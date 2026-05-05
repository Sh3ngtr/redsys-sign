const crypto = require('crypto');

function firmar(params, orderId, secretKey) {
  // 1. Clave TAL CUAL (no base64)
  const key = Buffer.from(secretKey, 'utf8');

  // 2. Cifrar order con 3DES CBC IV=0
  const cipher = crypto.createCipheriv(
    'des-ede3-cbc',
    key,
    Buffer.alloc(8, 0)
  );

  let encrypted = cipher.update(orderId, 'ascii');
  encrypted = Buffer.concat([encrypted, cipher.final()]);

  // 3. Usar primeros 8 bytes como clave derivada
  const divKey = encrypted.subarray(0, 8);

  // 4. HMAC SHA256
  return crypto.createHmac('sha256', divKey)
    .update(params, 'ascii')
    .digest('base64');
}

function firmar(params, orderId, secretKeyB64) {
  // 1. Clave: decodificar desde Base64
  const key = Buffer.from(secretKeyB64, 'base64');

  // 2. Order ID: exactamente 8 bytes con padding de ceros
  const order = Buffer.alloc(8, 0);
  Buffer.from(orderId, 'ascii').copy(order, 0, 0, Math.min(orderId.length, 8));

  // 3. 3DES-CBC IV=0 → divKey
  // Con padding activado: 8 bytes entrada → 16 bytes salida (8 cifrado + 8 padding)
  // Solo necesitamos el primer bloque (los primeros 8 bytes)
  const iv = Buffer.alloc(8, 0);
  const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);
  const encrypted = Buffer.concat([cipher.update(order), cipher.final()]);
  const divKey = encrypted.slice(0, 8);

  // 4. HMAC-SHA256(params, divKey) → Base64
  return crypto.createHmac('sha256', divKey)
    .update(Buffer.from(params, 'ascii'))
    .digest('base64');
}

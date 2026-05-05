function firmar(params, orderId, secretKeyB64) {
  // 1. IMPORTANTE: esta clave del test NO es base64 real
  const keyBuf = Buffer.from(secretKeyB64, 'utf8');

  // 2. Preparar clave 24 bytes
  const key24 = Buffer.alloc(24);
  keyBuf.copy(key24, 0, 0, Math.min(keyBuf.length, 24));
  if (keyBuf.length === 16) keyBuf.copy(key24, 16, 0, 8);

  // 3. ORDER SIN truncar
  const order = Buffer.from(orderId, 'ascii');

  // 4. forge cipher
  const forgeKey  = forge.util.createBuffer(key24.toString('binary'));
  const forgeIv   = forge.util.createBuffer('\x00\x00\x00\x00\x00\x00\x00\x00');
  const forgeData = forge.util.createBuffer(order.toString('binary'));

  const cipher = forge.cipher.createCipher('3DES-CBC', forgeKey);
  cipher.start({ iv: forgeIv });
  cipher.update(forgeData);
  cipher.finish();

  const encrypted = cipher.output.getBytes();

  // 5. primeros 8 bytes
  const divKey = Buffer.from(encrypted, 'binary').subarray(0, 8);

  // 6. HMAC
  return crypto.createHmac('sha256', divKey)
    .update(params, 'ascii')
    .digest('base64');
}

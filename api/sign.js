const crypto = require('crypto');

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  try {
    const body = req.body || {};
    const { params, orderId, secretKeyB64, test } = body;

    if (test === 'redsys') {
      const p = 'eyJEU19NRVJDSEFOVF9BTU9VTlQiOiIxNDUiLCJEU19NRVJDSEFOVF9PUkRFUiI6IjEyMzRhYmNkIiwiRFNfTUVSQ0hBTlRfTUVSQ0hBTlRDT0RFIjoiOTk5MDA4ODgxIiwiRFNfTUVSQ0hBTlRfQ1VSUkVOQ1kiOiI5NzgiLCJEU19NRVJDSEFOVF9UUkFOU0FDVElPTlRZUEUiOiIwIiwiRFNfTUVSQ0hBTlRfVEVSTUlOQUwiOiIwMDEiLCJEU19NRVJDSEFOVF9NRVJDSEFOVFVSTCI6Imh0dHBzOi8vcHJ1ZWJhcy5yZWRzeXMuZXMvdGVzdC1wYWdvLXJlZHN5cy9yZXN1bHQtcGFnby1yZWRzeXMucGhwIiwiRFNfTUVSQ0hBTlRfVVJMT0siOiJodHRwczovL3BydWViYXMucmVkc3lzLmVzL3Rlc3QtcGFnby1yZWRzeXMvcmVzdWx0LXBhZ28tcmVkc3lzLnBocCIsIkRTX01FUkNIQU5UX1VSTEtPIjoiaHR0cHM6Ly9wcnVlYmFzLnJlZHN5cy5lcy90ZXN0LXBhZ28tcmVkc3lzL3Jlc3VsdC1wYWdvLXJlZHN5cy5waHAifQ==';
      const sig = firmar(p, '1234abcd', 'Mk9m98IfEblmPfrpsawt7BmxObt98Lfg');
      const expected = 'xD7Y7xsJTCrCGTfWABPJ59nj5MO2k7M/d+y9B1cKk3c=';
      return res.json({ sig, expected, ok: sig === expected });
    }

    if (!params || !orderId || !secretKeyB64)
      return res.status(400).json({ error: 'Faltan parametros' });

    return res.json({ signature: firmar(params, orderId, secretKeyB64) });

  } catch (err) {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
};

function firmar(params, orderId, secretKeyB64) {
  // La clave llega como Base64 (así la entrega Caja Rural)
  const key = Buffer.from(secretKeyB64, 'base64');

  // Order: 8 bytes exactos con padding de ceros a la derecha
  const order = Buffer.alloc(8, 0);
  const orderAscii = Buffer.from(orderId, 'ascii');
  orderAscii.copy(order, 0, 0, Math.min(orderAscii.length, 8));

  // 3DES-EDE-CBC con IV=0 → divKey = primeros 8 bytes del cifrado
  const iv = Buffer.alloc(8, 0);
  const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);
  const part1 = cipher.update(order);   // devuelve 0 bytes (bloque incompleto)
  const part2 = cipher.final();          // devuelve 16 bytes (8 cifrado + 8 padding PKCS7)
  const divKey = Buffer.concat([part1, part2]).slice(0, 8);

  // HMAC-SHA256(params_en_ascii, divKey) → Base64
  return crypto.createHmac('sha256', divKey)
    .update(params, 'ascii')
    .digest('base64');
}

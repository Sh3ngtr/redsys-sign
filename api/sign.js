const crypto = require('crypto');

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).end();

  try {
    const { params, orderId, secretKeyB64, test } = req.body;

    if (test === 'redsys') {
      // Vector oficial de prueba Redsys
      const p = 'eyJEU19NRVJDSEFOVF9BTU9VTlQiOiIxNDUiLCJEU19NRVJDSEFOVF9PUkRFUiI6IjEyMzRhYmNkIiwiRFNfTUVSQ0hBTlRfTUVSQ0hBTlRDT0RFIjoiOTk5MDA4ODgxIiwiRFNfTUVSQ0hBTlRfQ1VSUkVOQ1kiOiI5NzgiLCJEU19NRVJDSEFOVF9UUkFOU0FDVElPTlRZUEUiOiIwIiwiRFNfTUVSQ0hBTlRfVEVSTUlOQUwiOiIwMDEiLCJEU19NRVJDSEFOVF9NRVJDSEFOVFVSTCI6Imh0dHBzOi8vcHJ1ZWJhcy5yZWRzeXMuZXMvdGVzdC1wYWdvLXJlZHN5cy9yZXN1bHQtcGFnby1yZWRzeXMucGhwIiwiRFNfTUVSQ0hBTlRfVVJMT0siOiJodHRwczovL3BydWViYXMucmVkc3lzLmVzL3Rlc3QtcGFnby1yZWRzeXMvcmVzdWx0LXBhZ28tcmVkc3lzLnBocCIsIkRTX01FUkNIQU5UX1VSTEtPIjoiaHR0cHM6Ly9wcnVlYmFzLnJlZHN5cy5lcy90ZXN0LXBhZ28tcmVkc3lzL3Jlc3VsdC1wYWdvLXJlZHN5cy5waHAifQ==';
      const sig = firmar(p, '1234abcd', 'Mk9m98IfEblmPfrpsawt7BmxObt98Lfg');
      const expected = 'xD7Y7xsJTCrCGTfWABPJ59nj5MO2k7M/d+y9B1cKk3c=';
      return res.json({ sig, expected, ok: sig === expected });
    }

    if (!params || !orderId || !secretKeyB64)
      return res.status(400).json({ error: 'Faltan parámetros' });

    res.json({ signature: firmar(params, orderId, secretKeyB64) });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

function firmar(params, orderId, secretKeyB64) {
  // 1. Clave desde Base64
  const key = Buffer.from(secretKeyB64, 'base64');

  // 2. Order ID: 8 bytes con padding de ceros
  const order = Buffer.alloc(8, 0);
  Buffer.from(orderId, 'ascii').copy(order, 0, 0, Math.min(orderId.length, 8));

  // 3. 3DES-CBC con IV=0 → divKey (los primeros 8 bytes del resultado)
  const iv = Buffer.alloc(8, 0);
  const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);
  cipher.setAutoPadding(false);
  const divKey = Buffer.concat([cipher.update(order), cipher.final()]).slice(0, 8);

  // 4. HMAC-SHA256(params, divKey) → Base64
  return crypto.createHmac('sha256', divKey).update(params, 'ascii').digest('base64');
}

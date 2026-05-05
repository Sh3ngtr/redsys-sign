const forge  = require('node-forge');
const crypto = require('crypto');

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    const { params, orderId, secretKeyB64, test } = req.body || {};

    // 🧪 TEST REDSYS
    if (test === 'redsys') {
      const p = 'eyJEU19NRVJDSEFOVF9BTU9VTlQiOiIxNDUiLCJEU19NRVJDSEFOVF9PUkRFUiI6IjEyMzRhYmNkIiwiRFNfTUVSQ0hBTlRfTUVSQ0hBTlRDT0RFIjoiOTk5MDA4ODgxIiwiRFNfTUVSQ0hBTlRfQ1VSUkVOQ1kiOiI5NzgiLCJEU19NRVJDSEFOVF9UUkFOU0FDVElPTlRZUEUiOiIwIiwiRFNfTUVSQ0hBTlRfVEVSTUlOQUwiOiIwMDEiLCJEU19NRVJDSEFOVF9NRVJDSEFOVFVSTCI6Imh0dHBzOi8vcHJ1ZWJhcy5yZWRzeXMuZXMvdGVzdC1wYWdvLXJlZHN5cy9yZXN1bHQtcGFnby1yZWRzeXMucGhwIiwiRFNfTUVSQ0hBTlRfVVJMT0siOiJodHRwczovL3BydWViYXMucmVkc3lzLmVzL3Rlc3QtcGFnby1yZWRzeXMvcmVzdWx0LXBhZ28tcmVkc3lzLnBocCIsIkRTX01FUkNIQU5UX1VSTEtPIjoiaHR0cHM6Ly9wcnVlYmFzLnJlZHN5cy5lcy90ZXN0LXBhZ28tcmVkc3lzL3Jlc3VsdC1wYWdvLXJlZHN5cy5waHAifQ==';

      const sig = firmar(
        p,
        '1234abcd',
        'Mk9m98IfEblmPfrpsawt7BmxObt98Lfg'
      );

      const expected = 'xD7Y7xsJTCrCGTfWABPJ59nj5MO2k7M/d+y9B1cKk3c=';

      return res.json({ sig, expected, ok: sig === expected });
    }

    if (!params || !orderId || !secretKeyB64) {
      return res.status(400).json({ error: 'Faltan parametros' });
    }

    const signature = firmar(params, orderId, secretKeyB64);
    return res.json({ signature });

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};

function firmar(params, orderId, secretKeyB64) {
  const keyBuf = Buffer.from(secretKeyB64, 'utf8');

  const key24 = Buffer.alloc(24);
  keyBuf.copy(key24, 0, 0, Math.min(keyBuf.length, 24));
  if (keyBuf.length === 16) keyBuf.copy(key24, 16, 0, 8);

  const order = Buffer.from(orderId, 'ascii');

  const forgeKey  = forge.util.createBuffer(key24.toString('binary'));
  const forgeIv   = forge.util.createBuffer('\x00\x00\x00\x00\x00\x00\x00\x00');
  const forgeData = forge.util.createBuffer(order.toString('binary'));

  const cipher = forge.cipher.createCipher('3DES-CBC', forgeKey);
  cipher.start({ iv: forgeIv });
  cipher.update(forgeData);
  cipher.finish();

  const encrypted = cipher.output.getBytes();
  const divKey = Buffer.from(encrypted, 'binary').subarray(0, 8);

  return crypto.createHmac('sha256', divKey)
    .update(params, 'ascii')
    .digest('base64');
}

import crypto from "crypto";

/**
 * Firma una operación Redsys con HMAC_SHA512_V2
 * Documentación: https://pagosonline.redsys.es/desarrolladores-inicio/documentacion-operativa/firmar-una-operacion/
 *
 * Algoritmo:
 * 1. Tomar los primeros 16 chars de la clave secreta (texto plano, NO base64)
 * 2. AES-128-CBC(IV=todos ceros, key=esos 16 bytes, data=orderId) → encrypted
 * 3. divKeyB64 = base64(encrypted)   ← usada como STRING para el HMAC
 * 4. Ds_Signature = base64url( HMAC-SHA512(divKeyB64, paramsB64) )
 */
function signRedsys(paramsB64, orderId, secretKey) {
  // Paso 1: primeros 16 caracteres en UTF-8 (texto plano, NO decodificar base64)
  const key16 = Buffer.from(secretKey.substring(0, 16), "utf8");
  const iv     = Buffer.alloc(16, 0); // IV = 16 bytes a cero

  // Paso 2: AES-128-CBC
  const cipher    = crypto.createCipheriv("aes-128-cbc", key16, iv);
  const encrypted = Buffer.concat([
    cipher.update(orderId, "utf8"),
    cipher.final()
  ]);

  // Paso 3: codificar la clave derivada en base64 (como STRING, no buffer)
  const divKeyB64 = encrypted.toString("base64");

  // Paso 4: HMAC-SHA512 → base64url
  const hmac = crypto.createHmac("sha512", divKeyB64);
  hmac.update(paramsB64, "utf8");
  return hmac.digest("base64url");
}

export default async function handler(req, res) {
  // Manejo CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;

    // Modo test: verifica el vector oficial de Redsys
    if (body.test === "redsys" || body.test === "des") {
      const testSig = signRedsys(
        "eyJEU19NRVJDSEFOVF9BTU9VTlQiOiI5OTkiLCJEU19NRVJDSEFOVF9PUkRFUiI6IjEyMzQ1Njc4OTAiLCJEU19NRVJDSEFOVF9NRVJDSEFOVENPREUiOiI5OTkwMDg4ODEiLCJEU19NRVJDSEFOVF9DVVJSRU5DWSI6Ijk3OCIsIkRTX01FUkNIQU5UX1RSQU5TQUNUSU9OVFlQRSI6IjAiLCJEU19NRVJDSEFOVF9URVJNSU5BTCI6IjEiLCJEU19NRVJDSEFOVF9NRVJDSEFOVFVSTCI6Imh0dHA6XC9cL3d3dy5wcnVlYmEuY29tXC91cmxOb3RpZmljYWNpb24ucGhwIiwiRFNfTUVSQ0hBTlRfVVJMT0siOiJodHRwOlwvXC93d3cucHJ1ZWJhLmNvbVwvdXJsT0sucGhwIiwiRFNfTUVSQ0hBTlRfVVJMS08iOiJodHRwOlwvXC93d3cucHJ1ZWJhLmNvbVwvdXJsS08ucGhwIn0",
        "1234567890",
        "sq7HjrUOBfKmC576ILgskD5srU870gJ7"
      );
      const expected = "Vjo02eSWq249IeZZp3R-ArFnGLhKY0OuzDDlx1BuVtZDC2yhczA7_11uZhsYzLZBCMFAz8u8uzGDX3AErHKmmw";
      return res.status(200).json({
        ok: testSig === expected,
        calculated: testSig,
        expected
      });
    }

    // Uso normal: firmar parámetros reales
    const { params, orderId, secretKey } = body;

    if (!params || !orderId || !secretKey) {
      return res.status(400).json({
        error: "Faltan campos: params, orderId, secretKey"
      });
    }

    const signature = signRedsys(params, orderId, secretKey);

    return res.status(200).json({
      signature,
      signatureVersion: "HMAC_SHA512_V2"
    });

  } catch (err) {
    console.error("Sign error:", err);
    return res.status(500).json({ error: err.message });
  }
}

// Transmissão HTTPS com certificado do cliente (mTLS), exigida pelos
// webservices da ABRASF. Usa o PFX diretamente no agente TLS do Node.

import https from "node:https";
import http from "node:http";
import { URL } from "node:url";
import { parseSoapResponse } from "./abrasi.js";

const DEFAULT_TIMEOUT_MS = 60_000;

/**
 * Envia o envelope SOAP para a URL informada.
 * `pfx` é o buffer PKCS#12; quando ausente, a chamada sai sem certificado
 * (alguns endpoints municipais aceitam só HTTPS simples).
 */
export function transmitSoap(input) {
  const {
    url,
    soap,
    pfx,
    passphrase,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    rejectUnauthorized = true,
    headers = {},
  } = input || {};

  if (!url) return Promise.reject(new Error("URL do webservice ausente."));
  if (!soap) return Promise.reject(new Error("Envelope SOAP ausente."));

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return Promise.reject(new Error("URL do webservice inválida."));
  }

  const secure = parsed.protocol === "https:";
  if (!secure && rejectUnauthorized) {
    return Promise.reject(new Error("A URL informada não é HTTPS."));
  }

  const agent = secure
    ? new https.Agent({
        ...(pfx
          ? { pfx: Buffer.from(pfx), passphrase: String(passphrase ?? "") }
          : {}),
        rejectUnauthorized,
      })
    : new http.Agent();

  return new Promise((resolve, reject) => {
    const request = (secure ? https : http).request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (secure ? 443 : 80),
        path: `${parsed.pathname}${parsed.search}`,
        method: "POST",
        agent,
        headers: {
          "Content-Type": "text/xml; charset=utf-8",
          "Content-Length": Buffer.byteLength(soap),
          Accept: "text/xml",
          ...headers,
        },
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf8");
          const parsedBody = parseSoapResponse(body);
          resolve({
            statusCode: response.statusCode ?? 0,
            body,
            ...parsedBody,
          });
        });
      },
    );

    request.setTimeout(timeoutMs, () => {
      request.destroy(new Error("Tempo esgotado ao falar com o webservice."));
    });
    request.on("error", (error) => {
      const tls = /certificate|SSL|alert|handshake|ECONN|socket|wrong version/i.test(
        error.message,
      );
      reject(
        new Error(
          tls
            ? `Não foi possível falar com o webservice (certificado ou conexão): ${error.message}`
            : error.message,
        ),
      );
    });
    request.write(soap);
    request.end();
  });
}

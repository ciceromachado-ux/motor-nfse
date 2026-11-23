// Ponte de NFS-e do RespiraPsi.
// Recebe o certificado A1 e o XML, assina no padrão ABRASF e transmite
// com mTLS. Nada fica gravado em disco: o certificado chega e vai embora
// junto com a resposta.

import http from "node:http";
import { timingSafeEqual } from "node:crypto";
import { readCertificate } from "./cert.js";
import { signXmlElement } from "./dsign.js";
import { buildSoapEnvelope } from "./abrasi.js";
import { transmitSoap } from "./transmit.js";
import { verifySignedXml } from "./verify.js";

const PORT = Number(process.env.PORT || 8080);
const API_KEY = process.env.BRIDGE_API_KEY || "";
const MAX_BODY_BYTES = 12 * 1024 * 1024;

function json(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

function authorized(req) {
  if (!API_KEY) return true;
  const given = String(req.headers["x-bridge-key"] || "");
  const expected = Buffer.from(API_KEY);
  const actual = Buffer.from(given);
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(expected, actual);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("Corpo da requisição muito grande."));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (!chunks.length) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(new Error("Corpo da requisição não é JSON."));
      }
    });
    req.on("error", reject);
  });
}

function certificateFrom(payload) {
  const pfxBase64 = payload.certificate_pfx_base64;
  if (!pfxBase64) throw new Error("Certificado ausente (certificate_pfx_base64).");
  const pfx = Buffer.from(String(pfxBase64), "base64");
  if (!pfx.length) throw new Error("Certificado vazio.");
  return { pfx, ...readCertificate(pfx, payload.certificate_passphrase) };
}

async function handleSign(payload) {
  const cert = certificateFrom(payload);
  const signed = signXmlElement(payload.xml, {
    targetTag: payload.target_tag,
    privateKeyPem: cert.privateKeyPem,
    certificatePem: cert.certificatePem,
    digestAlgorithm: payload.digest_algorithm,
    signatureAlgorithm: payload.signature_algorithm,
  });
  const check = verifySignedXml(signed, { targetTag: payload.target_tag });
  if (!check.valid) {
    throw new Error(`A assinatura não conferiu: ${check.errors.join(" ")}`);
  }
  return { signed_xml: signed, common_name: cert.commonName, verified: true };
}

async function handleTransmit(payload) {
  const soap =
    payload.soap ||
    buildSoapEnvelope({
      operation: payload.operation,
      innerXml: payload.inner_xml,
      version: payload.version,
      namespace: payload.namespace,
      paramTag: payload.param_tag,
    });

  let pfx = null;
  if (payload.certificate_pfx_base64) {
    pfx = Buffer.from(String(payload.certificate_pfx_base64), "base64");
  }

  const result = await transmitSoap({
    url: payload.url,
    soap,
    pfx,
    passphrase: payload.certificate_passphrase,
    timeoutMs: payload.timeout_ms,
    rejectUnauthorized: payload.reject_unauthorized !== false,
    headers: payload.headers,
  });

  return {
    status_code: result.statusCode,
    has_fault: result.hasFault,
    fault_text: result.faultText,
    payload: result.payload,
    soap_sent: soap,
  };
}

async function handleEmitir(payload) {
  const cert = certificateFrom(payload);
  const signed = signXmlElement(payload.xml, {
    targetTag: payload.target_tag,
    privateKeyPem: cert.privateKeyPem,
    certificatePem: cert.certificatePem,
    digestAlgorithm: payload.digest_algorithm,
    signatureAlgorithm: payload.signature_algorithm,
  });
  const soap = buildSoapEnvelope({
    operation: payload.operation,
    innerXml: signed,
    version: payload.version,
    namespace: payload.namespace,
    paramTag: payload.param_tag,
  });
  const result = await transmitSoap({
    url: payload.url,
    soap,
    pfx: cert.pfx,
    passphrase: payload.certificate_passphrase,
    timeoutMs: payload.timeout_ms,
    rejectUnauthorized: payload.reject_unauthorized !== false,
    headers: payload.headers,
  });
  return {
    signed_xml: signed,
    common_name: cert.commonName,
    verified: verifySignedXml(signed, { targetTag: payload.target_tag }).valid,
    status_code: result.statusCode,
    has_fault: result.hasFault,
    fault_text: result.faultText,
    payload: result.payload,
  };
}

const routes = {
  "POST /sign": handleSign,
  "POST /transmit": handleTransmit,
  "POST /emitir": handleEmitir,
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", "http://localhost");
  const route = `${req.method} ${url.pathname}`;

  if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
    return json(res, 200, { ok: true, service: "respirapsi-fiscal-bridge" });
  }

  if (!routes[route]) return json(res, 404, { error: "Rota desconhecida." });
  if (!authorized(req)) return json(res, 401, { error: "Chave da ponte inválida." });

  try {
    const payload = await readBody(req);
    const result = await routes[route](payload);
    return json(res, 200, { ok: true, ...result });
  } catch (error) {
    const tooBig = /muito grande|não é JSON/.test(error.message);
    return json(res, tooBig ? 400 : 422, { ok: false, error: error.message });
  }
});

server.listen(PORT, () => {
  console.log(`ponte de NFS-e ouvindo na porta ${server.address().port}`);
});


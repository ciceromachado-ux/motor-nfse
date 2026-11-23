// Conferência da própria assinatura antes de enviar à prefeitura.
// Refaz o cálculo que o webservice vai fazer: canonicaliza o SignedInfo,
// confere o SignatureValue com a chave pública do certificado e confere o
// DigestValue do conteúdo sem a assinatura. Assim um XML que seria recusado
// é pego aqui, com o motivo, em vez de virar rejeição anônima lá fora.

import { DOMParser } from "@xmldom/xmldom";
import crypto from "node:crypto";
import cryptoPkg from "xml-crypto";
import xpathPkg from "xpath";

const { C14nCanonicalization } = cryptoPkg;
const { select } = xpathPkg;

const HASHES = {
  "http://www.w3.org/2000/09/xmldsig#sha1": "sha1",
  "http://www.w3.org/2001/04/xmlenc#sha256": "sha256",
};

function pick(node, tag) {
  if (!node) return null;
  const found = select(`*[local-name()="${tag}"]`, node);
  return found && found[0] ? found[0] : null;
}

function textOf(node) {
  return node && node.textContent ? String(node.textContent).trim() : null;
}

function publicKeyFromPem(certificatePem) {
  return new crypto.X509Certificate(certificatePem).publicKey;
}

/**
 * Namespaces herdados dos antecessores, do mesmo jeito que a ABRASF precisa:
 * sem isso o C14N de um pedaço do documento perde declarações e o cálculo
 * não bate com o de quem assinou.
 */
function collectAncestorNamespaces(node, out) {
  const list = out || [];
  const parent = node.parentNode;
  if (!parent) return list;
  const attrs = parent.attributes || [];
  for (let i = 0; i < attrs.length; i++) {
    const attr = attrs[i];
    if (attr && attr.nodeName && /^xmlns:?/.test(attr.nodeName)) {
      list.push({
        prefix: attr.nodeName.replace(/^xmlns:?/, ""),
        namespaceURI: attr.nodeValue,
      });
    }
  }
  return collectAncestorNamespaces(parent, list);
}

/**
 * Prefixo que o próprio nó carrega: uma declaração xmlns dele, ou o prefixo
 * do nome do elemento. É o que a canonicalização já resolve sozinha.
 */
function ownPrefixOf(node) {
  const attrs = node.attributes || [];
  for (let k = 0; k < attrs.length; k++) {
    if (/^xmlns:?/.test(attrs[k].nodeName)) {
      return attrs[k].nodeName.replace(/^xmlns:?/, "");
    }
  }
  return node.prefix || "";
}

function ancestorNamespacesFor(node) {
  const seen = new Map();
  for (const entry of collectAncestorNamespaces(node)) {
    if (!seen.has(entry.prefix)) seen.set(entry.prefix, entry);
  }
  // O prefixo que o nó já resolve sozinho fica de fora; os demais entram para
  // que o C14N do pedaço reproduza exatamente o que quem assinou enxergou.
  const own = ownPrefixOf(node);
  return [...seen.values()].filter((entry) => entry.prefix !== own);
}

function certificateFromKeyInfo(signature) {
  const b64 = textOf(pick(pick(signature, "KeyInfo"), "X509Data") || signature, "X509Certificate");
  if (!b64) return null;
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}

/**
 * Confere a assinatura do elemento `targetTag`.
 * Devolve { valid, errors } — nunca lança para conteúdo recusado.
 */
export function verifySignedXml(xml, options = {}) {
  const targetTag = options.targetTag || "InfDeclaracaoPrestacaoServico";
  const errors = [];

  if (!xml || typeof xml !== "string") {
    return { valid: false, errors: ["XML ausente."] };
  }

  const doc = new DOMParser().parseFromString(xml, "text/xml");
  if (!doc || !doc.documentElement) {
    return { valid: false, errors: ["O XML informado não é válido."] };
  }

  const target = select(`//*[local-name()="${targetTag}"]`, doc)[0];
  if (!target) {
    return { valid: false, errors: [`Elemento "${targetTag}" não encontrado.`] };
  }

  const signature = pick(target, "Signature");
  if (!signature) {
    return { valid: false, errors: ["O XML não tem assinatura."] };
  }

  const signedInfo = pick(signature, "SignedInfo");
  const signatureValue = textOf(pick(signature, "SignatureValue"));
  if (!signedInfo || !signatureValue) {
    return { valid: false, errors: ["Assinatura incompleta (SignedInfo ou SignatureValue)."] };
  }

  const digestMethod = textOf(
    pick(pick(signedInfo, "Reference"), "DigestMethod"),
  );
  const digestValue = textOf(pick(pick(signedInfo, "Reference"), "DigestValue"));
  if (!digestValue) {
    return { valid: false, errors: ["Assinatura sem DigestValue."] };
  }

  const certificatePem = options.certificatePem || certificateFromKeyInfo(signature);
  if (!certificatePem) {
    return { valid: false, errors: ["Nenhum certificado para conferir a assinatura."] };
  }

  let publicKey;
  try {
    publicKey = publicKeyFromPem(certificatePem);
  } catch (error) {
    return { valid: false, errors: [`Certificado ilegível: ${error.message}`] };
  }

  const canonicalizer = new C14nCanonicalization();

  // 1) SignatureValue sobre o SignedInfo canonicalizado.
  try {
    const canonSignedInfo = canonicalizer.process(signedInfo, {
      ancestorNamespaces: ancestorNamespacesFor(signedInfo),
    });
    const verify = crypto.createVerify("RSA-SHA1");
    verify.update(canonSignedInfo, "utf8");
    if (!verify.verify(publicKey, Buffer.from(signatureValue, "base64"))) {
      errors.push("O SignatureValue não corresponde à chave do certificado.");
    }
  } catch (error) {
    errors.push(`Não foi possível conferir o SignatureValue: ${error.message}`);
  }

  // 2) DigestValue do conteúdo sem a assinatura.
  try {
    let sigs;
    while ((sigs = select('//*[local-name()="Signature"]', doc)).length) {
      for (const s of sigs) s.parentNode.removeChild(s);
    }
    const clean = select(`//*[local-name()="${targetTag}"]`, doc)[0];
    const canon = canonicalizer.process(clean, {
      ancestorNamespaces: ancestorNamespacesFor(clean),
    });
    const hash = crypto
      .createHash(HASHES[digestMethod] || "sha1")
      .update(canon, "utf8")
      .digest("base64");
    if (hash !== digestValue) {
      errors.push("O DigestValue não corresponde ao conteúdo: o XML foi alterado depois de assinado.");
    }
  } catch (error) {
    errors.push(`Não foi possível conferir o DigestValue: ${error.message}`);
  }

  return { valid: errors.length === 0, errors };
}

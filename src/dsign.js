// Assinatura XML-DSig no padrão da ABRASF 2.04.
// O alvo é o elemento informado (por padrão InfDeclaracaoPrestacaoServico);
// a biblioteca grava <Reference URI="#Id..."> a partir do atributo Id do alvo
// e insere o bloco Signature dentro do próprio elemento.

import { DOMParser } from "@xmldom/xmldom";
import cryptoPkg from "xml-crypto";
import xpathPkg from "xpath";

const { SignedXml } = cryptoPkg;
const { select } = xpathPkg;

const C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
const RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/** Mantém só caracteres válidos em nome de elemento XML. */
function sanitizeTag(tag) {
  return String(tag || "").replace(/[^A-Za-z0-9_:.-]/g, "");
}

/**
 * Assina o elemento `targetTag` do XML informado.
 * Retorna o XML completo com o bloco Signature embutido no próprio elemento.
 */
export function signXmlElement(xml, options) {
  const {
    targetTag = "InfDeclaracaoPrestacaoServico",
    privateKeyPem,
    certificatePem,
    digestAlgorithm = SHA1,
    signatureAlgorithm = RSA_SHA1,
  } = options || {};

  if (!xml || typeof xml !== "string") throw new Error("XML ausente.");
  if (!privateKeyPem) throw new Error("Chave particular ausente.");
  if (!certificatePem) throw new Error("Certificado ausente.");

  const tag = sanitizeTag(targetTag);
  if (!tag) throw new Error("Nome do elemento a assinar inválido.");

  const doc = new DOMParser().parseFromString(xml, "text/xml");
  if (!doc || !doc.documentElement) throw new Error("O XML informado não é válido.");

  const xpathExpr = `//*[local-name()="${tag}"]`;
  const nodes = select(xpathExpr, doc);
  if (!nodes || nodes.length === 0) {
    throw new Error(`Elemento "${tag}" não encontrado no XML.`);
  }

  // O construtor recebe (idMode, options): sem o null no início as
  // opções são ignoradas e a canonicalização sai do padrão errado.
  const signed = new SignedXml(null, {
    privateKey: privateKeyPem,
    signatureAlgorithm,
    idAttribute: "Id",
    // A ABRASF espera canonicalização C14N também no SignedInfo.
    canonicalizationAlgorithm: C14N,
  });

  // xml-crypto 3 recebe os argumentos na ordem: xpath, transforms, digest.
  signed.addReference(xpathExpr, [ENVELOPED, C14N], digestAlgorithm);
  signed.signingKey = privateKeyPem;
  signed.signingCert = certificatePem;

  // Sem isto a biblioteca não escreve o KeyInfo, e sem o certificado embutido
  // a prefeitura não tem como conferir quem assinou.
  signed.keyInfoProvider = {
    getKeyInfo: (cert, prefix) => {
      const p = prefix ? `${prefix}:` : "";
      const body = String(cert || "")
        .replace(/-----[^-]+-----/g, "")
        .replace(/\s+/g, "");
      return (
        `<${p}X509Data><${p}X509Certificate>${body}</${p}X509Certificate></${p}X509Data>`
      );
    },
  };

  // O primeiro argumento é a string XML; a assinatura entra dentro do alvo.
  signed.computeSignature(xml, {
    location: { action: "append", reference: xpathExpr },
    canonicalizationAlgorithm: C14N,
    canonicalizationAlgorithmExcludeComments: false,
    prefix: "ds",
  });

  return signed.getSignedXml();
}

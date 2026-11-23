// Leitura do certificado e-CNPJ A1 (PKCS#12 / PFX).
// O Node não abre PKCS#12 direto, então a chave e o certificado saem do
// node-forge, que enxerga os bags do arquivo. A transmissão TLS usa o PFX
// cru no agente do Node (isso sim é suportado).

import forge from "node-forge";

function toForgeBinary(pfx) {
  const bytes = pfx instanceof Uint8Array ? pfx : new Uint8Array(pfx);
  return forge.util.binary.raw.encode(bytes);
}

function openP12(pfx, passphrase) {
  const asn1 = forge.asn1.fromDer(toForgeBinary(pfx));
  // integrityUsed=false: alguns e-CNPJ vêm com MAC que não bate com a senha;
  // a senha ainda é exigida para abrir a chave particular.
  return forge.pkcs12.pkcs12FromAsn1(asn1, false, String(passphrase ?? ""));
}

/** Chave particular em PEM extraída do PFX. */
export function privateKeyPemFromPfx(pfx, passphrase) {
  const p12 = openP12(pfx, passphrase);
  const shrouded =
    p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[
      forge.pki.oids.pkcs8ShroudedKeyBag
    ] || [];
  let key = shrouded.find((entry) => entry.key)?.key;
  if (!key) {
    const plain =
      p12.getBags({ bagType: forge.pki.oids.keyBag })[forge.pki.oids.keyBag] || [];
    key = plain.find((entry) => entry.key)?.key;
  }
  if (!key) throw new Error("O arquivo não contém uma chave particular.");
  return forge.pki.privateKeyToPem(key);
}

/** Certificado X.509 em PEM extraído do PFX. */
export function certificatePemFromPfx(pfx, passphrase) {
  const p12 = openP12(pfx, passphrase);
  const bags = p12.getBags({ bagType: forge.pki.oids.certBag });
  const list = bags[forge.pki.oids.certBag] || [];
  const cert = list.find((entry) => entry.cert)?.cert;
  if (!cert) throw new Error("O arquivo não contém um certificado X.509.");
  return forge.pki.certificateToPem(cert);
}

/** Nome comum (CN) do titular do certificado. */
export function commonNameFromCertificatePem(certificatePem) {
  const cert = forge.pki.certificateFromPem(certificatePem);
  const attrs = cert.subject?.attributes || [];
  const cn = attrs.find((a) => a.shortName === "CN" || a.type === "2.5.4.3");
  return cn?.value || null;
}

/**
 * Lê o PFX e devolve o que a assinatura e a transmissão precisam.
 * Falha com mensagem legível quando a senha não bate ou o arquivo está corrompido.
 */
export function readCertificate(pfx, passphrase) {
  let privateKeyPem;
  try {
    privateKeyPem = privateKeyPemFromPfx(pfx, passphrase);
  } catch (error) {
    throw new Error(
      `Não foi possível abrir a chave do certificado. Verifique a senha do e-CNPJ. (${error.message})`,
    );
  }
  let certificatePem;
  try {
    certificatePem = certificatePemFromPfx(pfx, passphrase);
  } catch (error) {
    throw new Error(
      `Não foi possível ler o certificado do arquivo. (${error.message})`,
    );
  }
  return {
    privateKeyPem,
    certificatePem,
    commonName: commonNameFromCertificatePem(certificatePem),
  };
}

// Envelope SOAP e leitura de respostas no padrão ABRASF 2.04.
// Os nomes de operação, namespace e parâmetro variam entre prefeituras,
// então tudo é configurável por chamada — a ponte não embute municipalidade.

export const ABRASF_NS = "http://www.abrasf.org.br/ABRASF/arquivos/nfse.xsd";
export const SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/";

export function escapeXml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/**
 * Monta o envelope SOAP de uma operação ABRASF.
 * `innerXml` é o XML já assinado, enviado como texto escapado dentro do parâmetro.
 */
export function buildSoapEnvelope(input) {
  const {
    operation,
    innerXml,
    version = "2.04",
    namespace = ABRASF_NS,
    paramTag = "xmlLoteRps",
  } = input || {};

  if (!operation) throw new Error("Operação SOAP ausente.");
  if (innerXml === undefined || innerXml === null) {
    throw new Error("Conteúdo do lote ausente.");
  }

  return (
    `<soapenv:Envelope xmlns:soapenv="${SOAP_NS}" xmlns:ns="${namespace}">` +
    `<soapenv:Header/>` +
    `<soapenv:Body>` +
    `<ns:${operation} v="${version}">` +
    `<ns:${paramTag}>${escapeXml(innerXml)}</ns:${paramTag}>` +
    `</ns:${operation}>` +
    `</soapenv:Body>` +
    `</soapenv:Envelope>`
  );
}

/**
 * Extrai o corpo útil da resposta: o conteúdo de <soap:Body> sem o invólucro,
 * e o texto de <soap:Fault> quando a prefeitura devolve erro.
 */
export function parseSoapResponse(body) {
  const text = String(body ?? "");
  const fault = text.match(/<[^>]*Fault[^>]*>([\s\S]*?)<\/[^>]*Fault>/i);
  const bodyMatch = text.match(/<[^>]*Body[^>]*>([\s\S]*?)<\/[^>]*Body>/i);
  return {
    hasFault: Boolean(fault),
    faultText: fault
      ? fault[1].replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim()
      : null,
    payload: bodyMatch ? bodyMatch[1].trim() : text.trim(),
  };
}

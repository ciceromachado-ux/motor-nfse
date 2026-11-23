# Motor de NFS-e do RespiraPsi

Ponte que assina e transmite notas de serviço no padrão ABRASF 2.04 usando o
certificado e-CNPJ A1 do profissional. Ela faz o que o backend do app não
consegue fazer sozinho: abrir a conexão HTTPS **com certificado do cliente**
(mTLS) e falar direto com o webservice da prefeitura.

O que ela sabe fazer:

| Rota | O que faz |
| --- | --- |
| `GET /health` | diz que está de pé |
| `POST /sign` | assina o XML e confere a própria assinatura antes de devolver |
| `POST /transmit` | envia um envelope SOAP já pronto, com o certificado |
| `POST /emitir` | assina, confere, monta o envelope e transmite — tudo numa chamada |

Nada é gravado em disco: o certificado chega codificado em base64, é usado e
vai embora junto com a resposta.

## Segurança

* Toda rota que faz algo exige o cabeçalho `x-bridge-key` com o valor de
  `BRIDGE_API_KEY`. Sem isso, a ponte responde `401`.
* Se `BRIDGE_API_KEY` não estiver definido, a ponte abre sem chave — por isso a
  variável é obrigatória em produção.
* A URL do webservice é sempre informada por quem chama; a ponte não embute
  nenhuma prefeitura.
* Antes de devolver ou transmitir, a assinatura é conferida de novo. Se o XML
  não conferir, a chamada falha com o motivo em vez de virar rejeição anônima.

## Variáveis

| Nome | Obrigatória | Para quê |
| --- | --- | --- |
| `PORT` | não (padrão 8080) | o Railway define sozinho |
| `BRIDGE_API_KEY` | sim em produção | chave que o app envia em `x-bridge-key` |

## Rodar local

```bash
npm install
npm test          # 18 verificações: certificado, assinatura, mTLS e a ponte
BRIDGE_API_KEY=dev npm start
```

## Colocar no ar (GitHub + Railway)

1. Subir o código para um repositório no GitHub (arraste a pasta inteira em
   *Add file → Upload files*). O `node_modules` não vai junto: o `.gitignore`
   cuida disso.
2. No Railway, ligar esse repositório ao serviço.
3. Em **Variables**, criar `BRIDGE_API_KEY` com um valor longo e aleatório.
4. Em **Settings → Networking**, gerar o endereço público.
5. O endereço que aparecer (`https://algo.up.railway.app`) é o que o app vai
   chamar.

## Como o app usa

O app chama `POST /emitir` com:

```json
{
  "xml": "<Rps>...</Rps>",
  "certificate_pfx_base64": "...",
  "certificate_passphrase": "...",
  "operation": "RecepcionarLoteRps",
  "url": "https://webservice.da.prefeitura/nfse",
  "param_tag": "xmlLoteRps"
}
```

A ponte devolve o XML assinado, o status HTTP, se houve `Fault` e o corpo da
resposta da prefeitura.

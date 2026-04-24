# SSLyze OPC UA — Análise de Certificados X.509 em Servidores OPC UA

> Adaptação da ferramenta [SSLyze](https://github.com/nabla-c0d3/sslyze) para extração e análise de certificados digitais X.509 em servidores que operam sob o protocolo **OPC UA**, em substituição à camada TLS convencional.

Desenvolvido no âmbito do **VIRTUS / LIEC — UFCG** (Universidade Federal de Campina Grande), Abril de 2022.

---

## Sumário

- [Visão Geral](#visão-geral)
- [Motivação](#motivação)
- [Arquitetura das Modificações](#arquitetura-das-modificações)
- [Pré-requisitos](#pré-requisitos)
- [Instalação e Configuração](#instalação-e-configuração)
- [Uso](#uso)
- [Resultados Esperados](#resultados-esperados)
- [Validação](#validação)
- [Limitações Conhecidas](#limitações-conhecidas)
- [Referências](#referências)

---

## Visão Geral

Este projeto adapta o **SSLyze 6.3.1** — ferramenta de análise de servidores TLS/SSL — para inspecionar certificados X.509 em servidores **OPC UA** (Open Platform Communications Unified Architecture). A comunicação TLS é substituída por conexões TCP simples combinadas ao serviço `GetEndpoints` do protocolo OPC UA, via biblioteca `asyncua`.

```
SSLyze Original          →    SSLyze OPC UA (este repositório)
──────────────────────────────────────────────────────────────
Conexão TLS (nassl)      →    Conexão TCP simples (socket)
Certificado via TLS      →    Certificado via GetEndpoints (asyncua)
Análise de suítes TLS    →    Análise de certificados X.509 OPC UA
```

---

## Motivação

Ferramentas clássicas de análise de segurança, como o SSLyze, não suportam nativamente o protocolo OPC UA — amplamente utilizado em ambientes de automação industrial (Indústria 4.0). Ao executar o SSLyze padrão contra um servidor OPC UA, o scanner falha com a mensagem:

```
=> ERROR: TLS probing failed: could not find a TLS version and cipher suite
   supported by the server; discarding scan.
```

Este projeto resolve essa limitação, permitindo que a lógica de análise de certificados do SSLyze seja reaproveitada para contextos industriais baseados em OPC UA.

---

## Arquitetura das Modificações

Dois arquivos do código-fonte do SSLyze foram alterados:

### `sslyze/server_connectivity.py`

A função `check_connectivity_to_server()` foi substituída por uma verificação de conectividade via **socket TCP simples**, testando apenas se a porta do servidor está acessível:

```python
def check_connectivity_to_server(
    server_location: ServerNetworkLocation,
    network_configuration: ServerNetworkConfiguration
) -> ServerTlsProbingResult:
    import socket
    try:
        sock = socket.create_connection(
            (server_location.hostname, server_location.port),
            timeout=5,
        )
        sock.close()
    except OSError as e:
        raise ConnectionToServerFailed(
            server_location=server_location,
            network_configuration=network_configuration,
            error_message=f"OPC UA connection failed: {e}",
        )
    return ServerTlsProbingResult(
        highest_tls_version_supported=TlsVersionEnum.TLS_1_2,
        cipher_suite_supported="OPC-UA",
        client_auth_requirement=ClientAuthRequirementEnum.DISABLED,
        supports_ecdh_key_exchange=False,
    )
```

### `sslyze/plugins/certificate_info/_get_cert_chain.py`

A função `get_certificate_chain()` foi reescrita para obter o certificado diretamente dos **endpoints OPC UA** usando `asyncua`, em vez de uma conexão nassl/TLS:

```python
async def _get_opcua_certificate(hostname: str, port: int):
    url = f"opc.tcp://{hostname}:{port}"
    client = Client(url=url, timeout=5)
    try:
        endpoints = await client.connect_and_get_server_endpoints()
    except Exception as e:
        raise ConnectionError(f"Falha ao obter endpoints OPC UA: {e}") from e

    for ep in endpoints:
        cert_der = bytes(ep.ServerCertificate)
        if cert_der and len(cert_der) > 0:
            return x509.load_der_x509_certificate(cert_der, default_backend())

    raise ValueError("Nenhum certificado encontrado nos endpoints do servidor OPC UA.")
```

---

## Pré-requisitos

- **Python 3.12** (versões mais recentes apresentam incompatibilidades com `asyncua`)
- **Git**
- **winget** (Windows) ou equivalente para instalação do Python
- Servidor OPC UA em execução (ex.: [Prosys OPC UA Simulation Server](https://prosysopc.com/products/opc-ua-simulation-server/))

---

## Instalação e Configuração

### 1. Clone o repositório

```bash
git clone https://github.com/allanss1lva/sslyze-opcua
cd sslyze-opcua
```

### 2. Instale o Python 3.12

```bash
winget install Python.Python.3.12
```

### 3. Crie e ative o ambiente virtual

```bash
py -3.12 -m venv venv
venv\Scripts\activate.bat
```

### 4. Instale as dependências

```bash
pip install --upgrade pip setuptools wheel
pip install -e .
pip install asyncua
```

---

## Uso

Com o servidor OPC UA em execução, execute:

```bash
sslyze --certinfo <HOSTNAME_OU_IP>:<PORTA>
```

**Exemplo:**

```bash
sslyze --certinfo Virtus-PC0283:53530
```

> Substitua `Virtus-PC0283:53530` pelo endereço e porta do seu servidor OPC UA (visível na aba **Status** do Prosys ou equivalente).

---

## Resultados Esperados

Uma execução bem-sucedida retorna informações do certificado X.509 do servidor, por exemplo:

```
SCAN RESULTS FOR VIRTUS-PC0283:53530
─────────────────────────────────────────────────────

* Certificates Information:
    Hostname sent for SNI:              Virtus-PC0283
    Number of cert chains detected:     1 (RSAPublicKey)

    Certificate Chain #1 (RSAPublicKey, SNI enabled)
        SHA1 Fingerprint:       ee2a927719d926982109424c8fef88ead59d5d06
        Common Name:            SimulationServer@Virtus-PC0283
        Issuer:                 SimulationServer@Virtus-PC0283
        Serial Number:          1773689176746
        Not Before:             2026-03-16
        Not After:              2036-03-13
        Public Key Algorithm:   RSAPublicKey
        Signature Algorithm:    sha256
        Key Size:               2048
        SubjAltName - DNS Names: ['Virtus-PC0283']

SCANS COMPLETED IN 0.300622 S
```

---

## Validação

A correção dos dados extraídos pode ser verificada comparando o **número de série** retornado pelo SSLyze com o exibido na aba **Certificates** do Prosys (ou equivalente). No exemplo acima:

| Fonte      | Número de Série (hex) | Número de Série (decimal) |
|------------|-----------------------|---------------------------|
| SSLyze     | `019cf81d02aa`        | `1773689176746`           |
| Prosys     | `019cf81d02aa`        | `1773689176746`           |

Os valores coincidem, confirmando a extração correta do certificado.

---

## Limitações Conhecidas

- O certificado extraído é **auto-assinado** (Self Signed), portanto não será validado pelas lojas de certificados do sistema operacional (Android, Apple, Java, Mozilla, Windows). Isso é esperado em ambientes OPC UA industriais.
- Extensões OCSP Must-Staple e Certificate Transparency **não são suportadas** por servidores OPC UA.
- O scanner retorna `TLS_1_2` e `OPC-UA` como valores fictícios de compatibilidade apenas para satisfazer a interface interna do SSLyze — esses valores não refletem uma negociação TLS real.
- Testado apenas no Windows. Adaptações podem ser necessárias para Linux/macOS.

---

## Referências

- [SSLyze — repositório original](https://github.com/nabla-c0d3/sslyze)
- [asyncua — Python OPC UA library](https://github.com/FreeOpcUa/opcua-asyncio)
- [Prosys OPC UA Simulation Server](https://prosysopc.com/products/opc-ua-simulation-server/)
- VIRTUS / LIEC — UFCG, *Explorando SSLyze: Etapa 1 a 8*, Campina Grande, Abril de 2022.

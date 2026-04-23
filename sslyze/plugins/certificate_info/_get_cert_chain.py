from pathlib import Path
from typing import List, Optional, Tuple
import asyncio
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from asyncua import Client
from sslyze.server_connectivity import ServerConnectivityInfo, TlsVersionEnum

ArgumentsToGetCertificateChain = Tuple[
    ServerConnectivityInfo, Optional[Path], Optional[TlsVersionEnum], Optional[str], bool
]


async def _get_opcua_certificate(hostname: str, port: int):
    url = f"opc.tcp://{hostname}:{port}"
    client = Client(url=url, timeout=5)
    
    try:
        endpoints = await client.connect_and_get_server_endpoints()
    except Exception as e:
        raise ConnectionError(f"Falha ao obter endpoints OPC UA: {e}") from e

    for ep in endpoints:
        cert_der = bytes(ep.ServerCertificate)  # garante conversão correta do tipo
        if cert_der and len(cert_der) > 0:
            return x509.load_der_x509_certificate(cert_der, default_backend())
    
    raise ValueError("Nenhum certificado encontrado nos endpoints do servidor OPC UA.")


def get_certificate_chain(
    server_info: ServerConnectivityInfo,
    custom_ca_file: Optional[Path],
    tls_version: Optional[TlsVersionEnum],
    openssl_cipher_string: Optional[str],
    should_enable_sni: bool,
) -> Tuple[List[str], None, Optional[Path], bool]:

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        cert = loop.run_until_complete(
            _get_opcua_certificate(
                hostname=server_info.server_location.hostname,
                port=server_info.server_location.port,
            )
        )
    finally:
        loop.close()

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return [cert_pem], None, custom_ca_file, should_enable_sni
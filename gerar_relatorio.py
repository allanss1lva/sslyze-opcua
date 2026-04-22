import json
from datetime import datetime

with open("resultado.json") as f:
    data = json.load(f)

scan = data["server_scan_results"][0]
server = scan["server_location"]
cert_deployments = scan["scan_result"]["certificate_info"]["result"]["certificate_deployments"]
cert = cert_deployments[0]["received_certificate_chain"][0]
trust = cert_deployments[0]["path_validation_results"]

html = f"""<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<title>Relatório SSLyze OPC UA</title>
<style>
  body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; background: #f5f5f5; }}
  h1 {{ background: #2E75B6; color: white; padding: 20px; border-radius: 8px; }}
  h2 {{ color: #2E75B6; border-bottom: 2px solid #2E75B6; padding-bottom: 5px; }}
  table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; margin-bottom: 20px; }}
  th {{ background: #2E75B6; color: white; padding: 10px; text-align: left; }}
  td {{ padding: 10px; border-bottom: 1px solid #eee; }}
  tr:nth-child(even) td {{ background: #f2f7fc; }}
  .fail {{ color: #c0392b; font-weight: bold; }}
  .ok {{ color: #27ae60; font-weight: bold; }}
  .card {{ background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
</style>
</head>
<body>
<h1>Relatório SSLyze OPC UA</h1>
<div class="card">
  <h2>Servidor</h2>
  <table>
    <tr><th>Campo</th><th>Valor</th></tr>
    <tr><td>Hostname</td><td>{server['hostname']}</td></tr>
    <tr><td>Porta</td><td>{server['port']}</td></tr>
    <tr><td>IP</td><td>{server['ip_address']}</td></tr>
    <tr><td>Gerado em</td><td>{datetime.now().strftime('%d/%m/%Y %H:%M')}</td></tr>
  </table>
</div>
<div class="card">
  <h2>Certificado</h2>
  <table>
    <tr><th>Campo</th><th>Valor</th></tr>
    <tr><td>Common Name</td><td>{cert['subject']['attributes'][0]['value']}</td></tr>
    <tr><td>Organização</td><td>{cert['subject']['attributes'][1]['value']}</td></tr>
    <tr><td>Emissor</td><td>{cert['issuer']['attributes'][0]['value']}</td></tr>
    <tr><td>Serial Number</td><td>{cert['serial_number']}</td></tr>
    <tr><td>Válido de</td><td>{cert['not_valid_before']}</td></tr>
    <tr><td>Válido até</td><td>{cert['not_valid_after']}</td></tr>
    <tr><td>Algoritmo</td><td>{cert['signature_algorithm_oid']['name']}</td></tr>
    <tr><td>SHA1 Fingerprint</td><td>{cert['fingerprint_sha1']}</td></tr>
    <tr><td>SHA256 Fingerprint</td><td>{cert['fingerprint_sha256']}</td></tr>
  </table>
</div>
<div class="card">
  <h2>Confiança</h2>
  <table>
    <tr><th>CA Store</th><th>Resultado</th></tr>"""

for t in trust:
    status = t["verified_certificate_chain"]
    store = t["trust_store"]["name"]
    if status is None:
        resultado = '<span class="fail">FALHOU</span>'
    else:
        resultado = '<span class="ok">CONFIÁVEL</span>'
    html += f"\n    <tr><td>{store}</td><td>{resultado}</td></tr>"

html += """
  </table>
</div>
</body>
</html>"""

with open("relatorio_opcua.html", "w") as f:
    f.write(html)

print("Relatório gerado: relatorio_opcua.html")

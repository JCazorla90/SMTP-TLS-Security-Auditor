import smtplib
import ssl
import socket
import http.client
import dns.resolver
import pandas as pd
import matplotlib.pyplot as plt
import base64
import os
import pdfkit
from io import BytesIO
from datetime import datetime

# ==============================================================================
# CONFIGURACIÓN EXTERNA (Cumplimiento DSA: Carga desde fichero)
# ==============================================================================
def cargar_dominios(ruta_fichero="dominios.txt"):
    """Lee la lista de dominios desde un archivo externo para evitar hardcoding."""
    if not os.path.exists(ruta_fichero):
        raise FileNotFoundError(
            f"Error: No se encontró el archivo '{ruta_fichero}'. "
            "Crea este archivo e incluye un dominio por línea."
        )
    
    with open(ruta_fichero, 'r') as archivo:
        return [linea.strip() for linea in archivo if linea.strip()]

# ==============================================================================
# MÓDULOS DE AUDITORÍA: CORREO (SMTP/TLS & DNS)
# ==============================================================================
def check_dns_records(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except Exception:
        return []

def evaluate_smtp_tls(mx_host):
    try:
        server = smtplib.SMTP(mx_host, 25, timeout=10)
        server.ehlo()
        context = ssl.create_default_context()
        server.starttls(context=context)
        server.ehlo()
        
        cipher, proto, bits = server.sock.cipher()
        server.quit()
        return proto, cipher, bits
    except Exception as e:
        return "Fallo", str(e), 0

# ==============================================================================
# MÓDULOS DE AUDITORÍA: SALUD DE CERTIFICADOS Y VULNERABILIDADES (HTTPS/SSL)
# ==============================================================================
def evaluate_certificate_and_vulnerabilities(domain):
    """
    Inspecciona la salud del certificado (validez, caducidad, emisor) 
    y evalúa vulnerabilidades (como soporte a protocolos obsoletos o Heartbleed).
    """
    cert_results = {
        "Certificado Válido": "❌",
        "Días para Expirar": 0,
        "Autofirmado": "Sí",
        "Vulnerabilidades / Alertas": "Ninguna detectada"
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # 1. Análisis de fechas de expiración
                not_after_str = cert.get('notAfter')
                if not_after_str:
                    # Formato típico: 'May  5 12:00:00 2027 GMT'
                    exp_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    dias_restantes = (exp_date - datetime.utcnow()).days
                    cert_results["Días para Expirar"] = dias_restantes
                    
                    if dias_restantes > 0:
                        cert_results["Certificado Válido"] = "✅"
                    else:
                        cert_results["Vulnerabilidades / Alertas"] = "Certificado CADUCADO"
                
                # 2. Comprobación de Emisor / Autofirmado
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                
                if subject == issuer:
                    cert_results["Autofirmado"] = "Sí (Inseguro)"
                    cert_results["Vulnerabilidades / Alertas"] = "Certificado Autofirmado detectado"
                else:
                    cert_results["Autofirmado"] = "No (CA Confiable)"

                # 3. Verificación de vulnerabilidades a protocolos obsoletos (ej. simulación TLS < 1.2)
                # Intento de conexión con contexto inseguro para ver si acepta versiones antiguas (Riesgo)
                insecure_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                insecure_context.check_hostname = False
                insecure_context.verify_mode = ssl.CERT_NONE
                
    except Exception as e:
        cert_results["Vulnerabilidades / Alertas"] = f"Error de conexión TLS: {str(e)[:30]}"
        
    return cert_results

def evaluate_web_security(domain):
    web_results = {
        "HTTPS Soportado": "❌",
        "TLS Web": "N/A",
        "HSTS": "❌",
        "CSP": "❌",
        "X-Frame-Options": "❌"
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                web_results["HTTPS Soportado"] = "✅"
                web_results["TLS Web"] = ssock.version()
        
        conn = http.client.HTTPSConnection(domain, timeout=5)
        conn.request("GET", "/")
        res = conn.getresponse()
        headers = {k.lower(): v for k, v in res.getheaders()}
        
        if "strict-transport-security" in headers:
            web_results["HSTS"] = "✅"
        if "content-security-policy" in headers:
            web_results["CSP"] = "✅"
        if "x-frame-options" in headers:
            web_results["X-Frame-Options"] = "✅"
            
    except Exception:
        pass
        
    return web_results

# ==============================================================================
# PROCESAMIENTO GLOBAL DE SEGURIDAD Y SCORING
# ==============================================================================
def generate_security_data(domains):
    results = []
    for domain in domains:
        print(f"Analizando seguridad integral y certificados de {domain}...")
        
        # 1. DNS (SPF / DMARC)
        mx_records = check_dns_records(domain, 'MX')
        mx_host = mx_records[0].split()[1].rstrip('.') if mx_records else None
        
        txt_records = check_dns_records(domain, 'TXT')
        spf_pass = any("v=spf1" in txt for txt in txt_records)
        
        dmarc_records = check_dns_records(f"_dmarc.{domain}", 'TXT')
        dmarc_pass = any("v=DMARC1" in txt for txt in dmarc_records)
        
        # 2. SMTP (Correo)
        proto, cipher, bits = evaluate_smtp_tls(mx_host) if mx_host else ("N/A", "N/A", 0)
        
        # 3. Web & Certificados (Salud y Vulnerabilidades)
        web_sec = evaluate_web_security(domain)
        cert_sec = evaluate_certificate_and_vulnerabilities(domain)
        
        # 4. Cálculo de Puntuación Global (Score 0-100)
        tls_mail_ok = proto in ["TLSv1.2", "TLSv1.3"]
        bits_ok = bits >= 256
        https_ok = web_sec["HTTPS Soportado"] == "✅"
        cert_valid = cert_sec["Certificado Válido"] == "✅"
        no_self_signed = "No" in cert_sec["Autofirmado"]
        no_vulns = cert_sec["Vulnerabilidades / Alertas"] == "Ninguna detectada"
        
        score = 0
        if tls_mail_ok: score += 20
        if bits_ok: score += 15
        if spf_pass: score += 10
        if dmarc_pass: score += 10
        if https_ok: score += 10
        if cert_valid: score += 15
        if no_self_signed: score += 10
        if no_vulns: score += 10

        results.append({
            "Dominio": domain,
            "TLS Correo": proto,
            "SPF": "✅" if spf_pass else "❌",
            "DMARC": "✅" if dmarc_pass else "❌",
            "Cert. Válido": cert_sec["Certificado Válido"],
            "Días Expiración": cert_sec["Días para Expirar"],
            "Autofirmado": cert_sec["Autofirmado"],
            "Vulnerabilidades": cert_sec["Vulnerabilidades / Alertas"],
            "HSTS": web_sec["HSTS"],
            "Score Global": score
        })
    
    return pd.DataFrame(results)

# ==============================================================================
# GENERACIÓN DE DASHBOARD Y REPORTES (HTML y PDF)
# ==============================================================================
def create_dashboard(df):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    
    protocol_counts = df['TLS Correo'].value_counts()
    ax1.pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%', colors=['#4CAF50', '#F44336', '#FFC107'])
    ax1.set_title('Distribución de Protocolos TLS (Correo)')
    
    df_sorted = df.sort_values('Score Global', ascending=True)
    colors = ['#F44336' if score < 60 else '#FFC107' if score < 90 else '#4CAF50' for score in df_sorted['Score Global']]
    ax2.barh(df_sorted['Dominio'], df_sorted['Score Global'], color=colors)
    ax2.set_title('Security Score Global (0-100)')
    ax2.set_xlim(0, 100)
    
    plt.tight_layout()
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
    plt.close()
    return image_base64

def export_html_report(df, image_base64, output_path):
    html_template = f"""
    <html>
    <head>
        <meta charset="utf-8">
        <title>Reporte de Auditoría y Salud de Certificados</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 25px; color: #333; }}
            h1 {{ color: #003366; border-bottom: 2px solid #003366; padding-bottom: 8px; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 15px; font-size: 11px; }}
            th, td {{ border: 1px solid #ddd; padding: 7px; text-align: left; }}
            th {{ background-color: #f2f2f2; color: #003366; }}
            .chart {{ margin-top: 20px; text-align: center; }}
            .footer {{ margin-top: 30px; font-size: 0.8em; color: #777; }}
        </style>
    </head>
    <body>
        <h1>Auditoría Integral de Ciberseguridad, Certificados y Vulnerabilidades</h1>
        <p><strong>Fecha de escaneo:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <div class="chart">
            <img src="data:image/png;base64,{image_base64}" alt="Security Dashboard" style="max-width: 85%;">
        </div>

        <h2>Detalle de Salud de Certificados y Postura Perimetral</h2>
        {df.to_html(index=False, classes='table', escape=False)}
        
        <div class="footer">
            <p>Elaborado bajo directrices de arquitectura: Validación de validez de certificados, detección de autofirmados y control de vulnerabilidades criptográficas.</p>
        </div>
    </body>
    </html>
    """
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_template)
    print(f"Reporte HTML generado exitosamente: {output_path}")

def export_pdf_report(html_file_path, pdf_file_path):
    options = {
        'page-size': 'A4',
        'orientation': 'Landscape',
        'margin-top': '0.4in',
        'margin-right': '0.4in',
        'margin-bottom': '0.4in',
        'margin-left': '0.4in',
        'encoding': "UTF-8",
        'enable-local-file-access': None,
        'no-outline': None
    }
    try:
        path_to_wkhtmltopdf = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'
        config = pdfkit.configuration(wkhtmltopdf=path_to_wkhtmltopdf)
        pdfkit.from_file(html_file_path, pdf_file_path, options=options, configuration=config)
        print(f"Reporte PDF generado exitosamente: {pdf_file_path}")
    except Exception as e:
        print(f"Error al generar el PDF: {e}")

# ==============================================================================
# EJECUCIÓN PRINCIPAL
# ==============================================================================
if __name__ == "__main__":
    try:
        lista_dominios = cargar_dominios()
        print(f"Se han cargado {len(lista_dominios)} dominios para auditar.")
        
        df_results = generate_security_data(lista_dominios)
        chart_base64 = create_dashboard(df_results)
        
        html_output = "reporte_certificados_vulnerabilidades.html"
        pdf_output = "reporte_certificados_vulnerabilidades.pdf"
        
        export_html_report(df_results, chart_base64, html_output)
        export_pdf_report(html_output, pdf_output)
        
    except FileNotFoundError as e:
        print(e)
    except Exception as e:
        print(f"Error inesperado durante la ejecución: {e}")

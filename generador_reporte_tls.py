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
# 1. CONFIGURACIÓN EXTERNA (Carga de dominios desde fichero)
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
# 2. MÓDULOS DE AUDITORÍA: CORREO ELECTRÓNICO Y DNS (APARTADO 1)
# ==============================================================================
def check_dns_records(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except Exception:
        return []

def evaluate_smtp_tls(mx_host):
    """Evalúa la conexión STARTTLS y extrae la suite criptográfica del servidor de correo."""
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
# 3. MÓDULOS DE AUDITORÍA: NAVEGACIÓN WEB, CERTIFICADOS Y CABECERAS (APARTADO 2)
# ==============================================================================
def evaluate_certificate_health(domain):
    """Inspecciona la salud del certificado (validez, caducidad, emisor y autofirmados)."""
    cert_results = {
        "Cert. Válido": "❌",
        "Días Expiración": 0,
        "Autofirmado": "Sí",
        "Alertas Certificado": "Ninguna"
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Fechas de expiración
                not_after_str = cert.get('notAfter')
                if not_after_str:
                    exp_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    dias_restantes = (exp_date - datetime.utcnow()).days
                    cert_results["Días Expiración"] = dias_restantes
                    if dias_restantes > 0:
                        cert_results["Cert. Válido"] = "✅"
                    else:
                        cert_results["Alertas Certificado"] = "CADUCADO"
                
                # Emisor / Autofirmado
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                if subject == issuer:
                    cert_results["Autofirmado"] = "Sí (Inseguro)"
                    cert_results["Alertas Certificado"] = "Autofirmado detectado"
                else:
                    cert_results["Autofirmado"] = "No (CA Confiable)"
    except Exception as e:
        cert_results["Alertas Certificado"] = f"Error TLS: {str(e)[:25]}"
        
    return cert_results

def evaluate_web_security_headers(domain):
    """Evalúa HTTPS y cabeceras de seguridad perimetral (HSTS, CSP, X-Frame, X-Content)."""
    web_results = {
        "HTTPS Web": "❌",
        "TLS Web": "N/A",
        "HSTS": "❌",
        "CSP": "❌",
        "X-Frame": "❌",
        "X-Content": "❌"
    }
    try:
        # 1. Comprobar HTTPS
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                web_results["HTTPS Web"] = "✅"
                web_results["TLS Web"] = ssock.version()
        
        # 2. Comprobar Security Headers
        conn = http.client.HTTPSConnection(domain, timeout=5)
        conn.request("GET", "/")
        res = conn.getresponse()
        headers = {k.lower(): v for k, v in res.getheaders()}
        
        if "strict-transport-security" in headers: web_results["HSTS"] = "✅"
        if "content-security-policy" in headers: web_results["CSP"] = "✅"
        if "x-frame-options" in headers: web_results["X-Frame"] = "✅"
        if "x-content-type-options" in headers: web_results["X-Content"] = "✅"
    except Exception:
        pass
        
    return web_results

# ==============================================================================
# 4. PROCESAMIENTO INTEGRAL Y CÁLCULO DE SCORE GLOBAL
# ==============================================================================
def generate_security_data(domains):
    results = []
    for domain in domains:
        print(f"Auditando dominios de correo y web para: {domain}...")
        
        # --- APARTADO 1: CORREO Y DNS ---
        mx_records = check_dns_records(domain, 'MX')
        mx_host = mx_records[0].split()[1].rstrip('.') if mx_records else None
        
        txt_records = check_dns_records(domain, 'TXT')
        spf_pass = any("v=spf1" in txt for txt in txt_records)
        
        dmarc_records = check_dns_records(f"_dmarc.{domain}", 'TXT')
        dmarc_pass = any("v=DMARC1" in txt for txt in dmarc_records)
        
        proto, cipher, bits = evaluate_smtp_tls(mx_host) if mx_host else ("N/A", "N/A", 0)
        
        # --- APARTADO 2: NAVEGACIÓN WEB, CERTIFICADOS Y CABECERAS ---
        cert_sec = evaluate_certificate_health(domain)
        web_sec = evaluate_web_security_headers(domain)
        
        # Ponderación de Scoring Global (0-100)
        score = 0
        if proto in ["TLSv1.2", "TLSv1.3"]: score += 20
        if bits >= 256: score += 10
        if spf_pass: score += 10
        if dmarc_pass: score += 10
        if web_sec["HTTPS Web"] == "✅": score += 10
        if cert_sec["Cert. Válido"] == "✅": score += 15
        if "No" in cert_sec["Autofirmado"]: score += 10
        if web_sec["HSTS"] == "✅": score += 5
        if web_sec["CSP"] == "✅": score += 5
        if web_sec["X-Frame"] == "✅": score += 5

        results.append({
            "Dominio": domain,
            # Bloque Correo
            "MX Principal": mx_host if mx_host else "No encontrado",
            "TLS Correo": proto,
            "Fuerza Bits": bits,
            "SPF": "✅" if spf_pass else "❌",
            "DMARC": "✅" if dmarc_pass else "❌",
            # Bloque Web y Certificados
            "HTTPS Web": web_sec["HTTPS Web"],
            "Cert. Válido": cert_sec["Cert. Válido"],
            "Días Exp.": cert_sec["Días Expiración"],
            "Autofirmado": cert_sec["Autofirmado"],
            "HSTS": web_sec["HSTS"],
            "CSP": web_sec["CSP"],
            "Score Global": score
        })
    
    return pd.DataFrame(results)

# ==============================================================================
# 5. GENERACIÓN DE DASHBOARD Y REPORTES (HTML y PDF)
# ==============================================================================
def create_dashboard(df):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    
    protocol_counts = df['TLS Correo'].value_counts()
    ax1.pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%', colors=['#4CAF50', '#F44336', '#FFC107'])
    ax1.set_title('Distribución de Protocolos TLS (Correo)')
    
    df_sorted = df.sort_values('Score Global', ascending=True)
    colors = ['#F44336' if s < 60 else '#FFC107' if s < 90 else '#4CAF50' for s in df_sorted['Score Global']]
    ax2.barh(df_sorted['Dominio'], df_sorted['Score Global'], color=colors)
    ax2.set_title('Security Score Global (Correo + Web) [0-100]')
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
        <title>Reporte Integral de Ciberseguridad (Correo y Navegación Web)</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 25px; color: #333; }}
            h1 {{ color: #003366; border-bottom: 2px solid #003366; padding-bottom: 8px; }}
            h2 {{ color: #004080; margin-top: 25px; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 10px; font-size: 10px; }}
            th, td {{ border: 1px solid #ddd; padding: 6px; text-align: left; }}
            th {{ background-color: #f2f2f2; color: #003366; }}
            .chart {{ margin-top: 20px; text-align: center; }}
            .footer {{ margin-top: 30px; font-size: 0.8em; color: #777; }}
        </style>
    </head>
    <body>
        <h1>Informe de Auditoría Integral de Ciberseguridad</h1>
        <p><strong>Fecha de escaneo:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <div class="chart">
            <img src="data:image/png;base64,{image_base64}" alt="Security Dashboard" style="max-width: 80%;">
        </div>

        <h2>Resumen Consolidado de Dominios (Correo y Navegación Web)</h2>
        {df.to_html(index=False, classes='table', escape=False)}
        
        <div class="footer">
            <p>Informe estructurado en apartados diferenciados para Infraestructura de Correo (SMTP/TLS, SPF, DMARC) y Navegación Web (HTTPS, Certificados y Security Headers).</p>
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
# 6. EJECUCIÓN PRINCIPAL
# ==============================================================================
if __name__ == "__main__":
    try:
        lista_dominios = cargar_dominios()
        print(f"Se han cargado {len(lista_dominios)} dominios para auditoría integral.")
        
        df_results = generate_security_data(lista_dominios)
        chart_base64 = create_dashboard(df_results)
        
        html_output = "reporte_integral_correo_web.html"
        pdf_output = "reporte_integral_correo_web.pdf"
        
        export_html_report(df_results, chart_base64, html_output)
        export_pdf_report(html_output, pdf_output)
        
    except FileNotFoundError as e:
        print(e)
    except Exception as e:
        print(f"Error inesperado durante la ejecución: {e}")

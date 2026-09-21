import smtplib
import ssl
import dns.resolver
import pandas as pd
import matplotlib.pyplot as plt
import base64
import os
import pdfkit
from io import BytesIO
from datetime import datetime

# ==============================================================================
# CONFIGURACIÓN EXTERNA (Cumplimiento DSA corporativo)
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
# AUDITORÍA CIBERSEGURIDAD SMTP/TLS Y DNS
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

def generate_security_data(domains):
    results = []
    for domain in domains:
        print(f"Analizando {domain}...")
        
        mx_records = check_dns_records(domain, 'MX')
        mx_host = mx_records[0].split()[1].rstrip('.') if mx_records else None
        
        txt_records = check_dns_records(domain, 'TXT')
        spf_pass = any("v=spf1" in txt for txt in txt_records)
        
        dmarc_records = check_dns_records(f"_dmarc.{domain}", 'TXT')
        dmarc_pass = any("v=DMARC1" in txt for txt in dmarc_records)
        
        proto, cipher, bits = evaluate_smtp_tls(mx_host) if mx_host else ("N/A", "N/A", 0)
        
        tls_compliant = proto in ["TLSv1.2", "TLSv1.3"]
        bits_compliant = bits >= 256
        
        score = 0
        if tls_compliant: score += 40
        if bits_compliant: score += 20
        if spf_pass: score += 20
        if dmarc_pass: score += 20

        results.append({
            "Dominio": domain,
            "MX Principal": mx_host,
            "Protocolo TLS": proto,
            "Cipher Suite": cipher,
            "Fuerza (Bits)": bits,
            "SPF": "✅" if spf_pass else "❌",
            "DMARC": "✅" if dmarc_pass else "❌",
            "Score": score
        })
    
    return pd.DataFrame(results)

# ==============================================================================
# GENERACIÓN DE REPORTES (HTML y PDF)
# ==============================================================================
def create_dashboard(df):
    """Genera gráficos en base64."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    
    protocol_counts = df['Protocolo TLS'].value_counts()
    ax1.pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%', colors=['#4CAF50', '#F44336', '#FFC107'])
    ax1.set_title('Distribución de Protocolos TLS Negociados')
    
    df_sorted = df.sort_values('Score', ascending=True)
    colors = ['#F44336' if score < 60 else '#FFC107' if score < 100 else '#4CAF50' for score in df_sorted['Score']]
    ax2.barh(df_sorted['Dominio'], df_sorted['Score'], color=colors)
    ax2.set_title('Security Score por Dominio (0-100)')
    ax2.set_xlim(0, 100)
    
    plt.tight_layout()
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
    plt.close()
    return image_base64

def export_html_report(df, image_base64, output_path):
    """Genera un reporte HTML consolidado."""
    html_template = f"""
    <html>
    <head>
        <meta charset="utf-8">
        <title>Reporte de Ciberseguridad de Correo (SMTP/TLS)</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
            h1 {{ color: #003366; border-bottom: 2px solid #003366; padding-bottom: 10px; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 20px; font-size: 14px; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            th {{ background-color: #f2f2f2; color: #003366; }}
            .chart {{ margin-top: 40px; text-align: center; }}
            .footer {{ margin-top: 50px; font-size: 0.8em; color: #777; }}
        </style>
    </head>
    <body>
        <h1>Auditoría de Seguridad de Dominios</h1>
        <p><strong>Fecha de escaneo:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <div class="chart">
            <img src="data:image/png;base64,{image_base64}" alt="Security Dashboard" style="max-width: 100%;">
        </div>

        <h2>Detalle de Cumplimiento Técnico</h2>
        {df.to_html(index=False, classes='table', escape=False)}
        
        <div class="footer">
            <p>Elaborado bajo normativa de Arquitectura corporativa: Validación de TLS 1.2/1.3 y cipher suites robustas (AES-256).</p>
        </div>
    </body>
    </html>
    """
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_template)
    print(f"Reporte HTML generado exitosamente: {output_path}")

def export_pdf_report(html_file_path, pdf_file_path):
    """Convierte el archivo HTML generado en un documento PDF."""
    options = {
        'page-size': 'A4',
        'margin-top': '0.75in',
        'margin-right': '0.5in',
        'margin-bottom': '0.75in',
        'margin-left': '0.5in',
        'encoding': "UTF-8",
        'enable-local-file-access': None,
        'no-outline': None
    }
    
    try:
        pdfkit.from_file(html_file_path, pdf_file_path, options=options)
        print(f"Reporte PDF generado exitosamente: {pdf_file_path}")
    except Exception as e:
        print(f"Error al generar el PDF. Verifica que wkhtmltopdf esté instalado y en tu PATH. Error técnico: {e}")

# ==============================================================================
# EJECUCIÓN PRINCIPAL
# ==============================================================================
if __name__ == "__main__":
    try:
        lista_dominios = cargar_dominios()
        print(f"Se han cargado {len(lista_dominios)} dominios para auditar.")
        
        df_results = generate_security_data(lista_dominios)
        chart_base64 = create_dashboard(df_results)
        
        html_output = "reporte_seguridad_smtp.html"
        pdf_output = "reporte_seguridad_smtp.pdf"
        
        export_html_report(df_results, chart_base64, html_output)
        export_pdf_report(html_output, pdf_output)
        
    except FileNotFoundError as e:
        print(e)
    except Exception as e:
        print(f"Error inesperado durante la ejecución: {e}")

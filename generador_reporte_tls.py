import smtplib
import ssl
import dns.resolver
import pandas as pd
import matplotlib.pyplot as plt
import base64
import os
from io import BytesIO
from datetime import datetime

# ==============================================================================
# CONFIGURACIÓN: Carga dinámica para evitar hardcodeo (Cumplimiento Arquitectura)
# ==============================================================================
def cargar_dominios(ruta_fichero="dominios.txt"):
    """
    Lee la lista de dominios desde un archivo externo.
    Cumple con la normativa que prohíbe configuraciones estáticas en el código.
    """
    if not os.path.exists(ruta_fichero):
        raise FileNotFoundError(
            f"Error: No se encontró el archivo '{ruta_fichero}'. "
            "Crea este archivo e incluye un dominio por línea."
        )
    
    with open(ruta_fichero, 'r') as archivo:
        # Extrae líneas ignorando espacios en blanco y líneas vacías
        return [linea.strip() for linea in archivo if linea.strip()]

# ==============================================================================
# MÓDULOS DE AUDITORÍA CIBERSEGURIDAD
# ==============================================================================
def check_dns_records(domain, record_type):
    """Consulta registros DNS específicos (MX, TXT para SPF/DMARC)"""
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except Exception:
        return []

def evaluate_smtp_tls(mx_host):
    """Evalúa la conexión STARTTLS y extrae la suite criptográfica"""
    try:
        server = smtplib.SMTP(mx_host, 25, timeout=10)
        server.ehlo()
        # Contexto estricto: requiere CA de confianza y deshabilita protocolos obsoletos
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
        
        # 1. Análisis DNS (Protección contra Spoofing)
        mx_records = check_dns_records(domain, 'MX')
        mx_host = mx_records[0].split()[1].rstrip('.') if mx_records else None
        
        txt_records = check_dns_records(domain, 'TXT')
        spf_pass = any("v=spf1" in txt for txt in txt_records)
        
        dmarc_records = check_dns_records(f"_dmarc.{domain}", 'TXT')
        dmarc_pass = any("v=DMARC1" in txt for txt in dmarc_records)
        
        # 2. Análisis Criptográfico SMTP
        proto, cipher, bits = evaluate_smtp_tls(mx_host) if mx_host else ("N/A", "N/A", 0)
        
        # 3. Evaluación de Cumplimiento (Scoring Arquitectura Corporativa)
        # Cumple si: TLS 1.2/1.3 + >= 256 bits (AES-256) + SPF + DMARC
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
# GENERACIÓN DE REPORTES (DASHBOARD)
# ==============================================================================
def create_dashboard(df):
    """Genera gráficos en base64 para embeber en HTML"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    
    # Gráfico 1: Distribución de Protocolos TLS
    protocol_counts = df['Protocolo TLS'].value_counts()
    ax1.pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%', colors=['#4CAF50', '#F44336', '#FFC107'])
    ax1.set_title('Distribución de Protocolos TLS Negociados')
    
    # Gráfico 2: Puntuación de Seguridad Media (Score)
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

def export_html_report(df, image_base64):
    """Genera un reporte HTML consolidado"""
    html_template = f"""
    <html>
    <head>
        <title>Reporte de Ciberseguridad de Correo (SMTP/TLS)</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
            h1 {{ color: #003366; border-bottom: 2px solid #003366; padding-bottom: 10px; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
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
            <img src="data:image/png;base64,{image_base64}" alt="Security Dashboard">
        </div>

        <h2>Detalle de Cumplimiento Técnico</h2>
        {df.to_html(index=False, classes='table', escape=False)}
        
        <div class="footer">
            <p>Elaborado bajo normativa de Arquitectura corporativa: Validación de TLS 1.2/1.3 y cipher suites robustas (AES-256).</p>
        </div>
    </body>
    </html>
    """
    with open("reporte_seguridad_smtp.html", "w", encoding="utf-8") as f:
        f.write(html_template)
    print("Reporte generado exitosamente: reporte_seguridad_smtp.html")

if __name__ == "__main__":
    try:
        # El script ahora lee los dominios desde el archivo de texto
        lista_dominios = cargar_dominios()
        print(f"Se han cargado {len(lista_dominios)} dominios para auditar.")
        
        df_results = generate_security_data(lista_dominios)
        chart_base64 = create_dashboard(df_results)
        export_html_report(df_results, chart_base64)
        
    except FileNotFoundError as e:
        print(e)
    except Exception as e:
        print(f"Error inesperado durante la ejecución: {e}")

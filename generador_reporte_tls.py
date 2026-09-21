import smtplib
import ssl
import socket
import http.client
import dns.resolver
import pandas as pd
import matplotlib.pyplot as plt
import os
from datetime import datetime
from fpdf import FPDF

# ==============================================================================
# 1. CONFIGURACIÓN EXTERNA (Carga de dominios desde fichero)
# ==============================================================================
def cargar_dominios(ruta_fichero="dominios.txt"):
    """Lee la lista de dominios desde un archivo externo."""
    if not os.path.exists(ruta_fichero):
        raise FileNotFoundError(
            f"Error: No se encontró el archivo '{ruta_fichero}'. "
            "Crea este archivo e incluye un dominio por línea."
        )
    
    with open(ruta_fichero, 'r') as archivo:
        return [linea.strip() for linea in archivo if linea.strip()]

# ==============================================================================
# 2. MÓDULOS DE AUDITORÍA: CORREO Y DNS (SPF, DKIM, DMARC, MTA-STS, TLS-RPT)
# ==============================================================================
def check_dns_records(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except Exception:
        return []

def evaluate_email_protections(domain):
    email_sec = {
        "SPF": "No",
        "DKIM": "No",
        "DMARC": "No",
        "MTA-STS": "No",
        "TLS-RPT": "No"
    }
    try:
        txt_records = check_dns_records(domain, 'TXT')
        if any("v=spf1" in txt for txt in txt_records):
            email_sec["SPF"] = "Sí"
            
        dmarc_records = check_dns_records(f"_dmarc.{domain}", 'TXT')
        if any("v=DMARC1" in txt for txt in dmarc_records):
            email_sec["DMARC"] = "Sí"
            
        dkim_records = check_dns_records(f"_domainkey.{domain}", 'TXT')
        if dkim_records or any("k=rsa" in txt for txt in txt_records):
            email_sec["DKIM"] = "Sí"
        else:
            email_sec["DKIM"] = "Verif."
            
        mtasts_records = check_dns_records(f"_mta-sts.{domain}", 'TXT')
        if any("v=STSv1" in txt for txt in mtasts_records):
            email_sec["MTA-STS"] = "Sí"
            
        tlsrpt_records = check_dns_records(f"_smtp._tls.{domain}", 'TXT')
        if any("v=TLSRPTv1" in txt for txt in tlsrpt_records):
            email_sec["TLS-RPT"] = "Sí"
    except Exception:
        pass
        
    return email_sec

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
# 3. MÓDULOS DE AUDITORÍA: NAVEGACIÓN WEB, CERTIFICADOS Y CSP
# ==============================================================================
def evaluate_certificate_health(domain):
    cert_results = {
        "Cert Válido": "No",
        "Días Exp": 0,
        "Autofirmado": "Sí",
        "Estado": "OK"
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after_str = cert.get('notAfter')
                if not_after_str:
                    exp_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    dias_restantes = (exp_date - datetime.utcnow()).days
                    cert_results["Días Exp"] = dias_restantes
                    if dias_restantes > 0:
                        cert_results["Cert Válido"] = "Sí"
                    else:
                        cert_results["Estado"] = "CADUCADO"
                
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                if subject == issuer:
                    cert_results["Autofirmado"] = "Sí"
                else:
                    cert_results["Autofirmado"] = "No"
    except Exception:
        pass
        
    return cert_results

def evaluate_web_security_and_csp(domain):
    web_results = {
        "HTTPS": "No",
        "CSP": "No",
        "HSTS": "No"
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                web_results["HTTPS"] = "Sí"
        
        conn = http.client.HTTPSConnection(domain, timeout=5)
        conn.request("GET", "/")
        res = conn.getresponse()
        headers = {k.lower(): v for k, v in res.getheaders()}
        
        if "content-security-policy" in headers:
            web_results["CSP"] = "Sí"
        if "strict-transport-security" in headers:
            web_results["HSTS"] = "Sí"
    except Exception:
        pass
        
    return web_results

# ==============================================================================
# 4. PROCESAMIENTO INTEGRAL Y CÁLCULO DE SCORE GLOBAL
# ==============================================================================
def generate_security_data(domains):
    results = []
    for domain in domains:
        print(f"Analizando: {domain}...")
        
        mx_records = check_dns_records(domain, 'MX')
        mx_host = mx_records[0].split()[1].rstrip('.') if mx_records else None
        proto, cipher, bits = evaluate_smtp_tls(mx_host) if mx_host else ("N/A", "N/A", 0)
        email_sec = evaluate_email_protections(domain)
        
        cert_sec = evaluate_certificate_health(domain)
        web_sec = evaluate_web_security_and_csp(domain)
        
        score = 0
        if proto in ["TLSv1.2", "TLSv1.3"]: score += 15
        if email_sec["SPF"] == "Sí": score += 10
        if email_sec["DKIM"] == "Sí": score += 10
        if email_sec["DMARC"] == "Sí": score += 15
        if email_sec["MTA-STS"] == "Sí": score += 5
        if email_sec["TLS-RPT"] == "Sí": score += 5
        if web_sec["HTTPS"] == "Sí": score += 10
        if cert_sec["Cert Válido"] == "Sí": score += 10
        if cert_sec["Autofirmado"] == "No": score += 10
        if web_sec["CSP"] == "Sí": score += 5
        if web_sec["HSTS"] == "Sí": score += 5

        results.append({
            "Dominio": domain,
            "MX Principal": mx_host if mx_host else "No encontrado",
            "Protocolo TLS": proto,
            "Cipher Suite": cipher,
            "Fuerza (Bits)": bits,
            "SPF": email_sec["SPF"],
            "DKIM": email_sec["DKIM"],
            "DMARC": email_sec["DMARC"],
            "MTA-STS": email_sec["MTA-STS"],
            "TLS-RPT": email_sec["TLS-RPT"],
            "HTTPS": web_sec["HTTPS"],
            "Cert Válido": cert_sec["Cert Válido"],
            "Días Exp": str(cert_sec["Días Exp"]),
            "Autofirmado": cert_sec["Autofirmado"],
            "CSP": web_sec["CSP"],
            "HSTS": web_sec["HSTS"],
            "Score": score
        })
    
    return pd.DataFrame(results)

# ==============================================================================
# 5. GENERACIÓN DE GRÁFICO Y REPORTE PDF PROFESIONAL
# ==============================================================================
def create_dashboard_image(df):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 3.6))
    
    protocol_counts = df['Protocolo TLS'].value_counts()
    ax1.pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%', colors=['#003366', '#4CAF50', '#FFC107'])
    ax1.set_title('Protocolos TLS (Correo)', fontsize=10, fontweight='bold', color='#003366')
    
    df_sorted = df.sort_values('Score', ascending=True)
    colors = ['#F44336' if s < 60 else '#FFC107' if s < 90 else '#4CAF50' for s in df_sorted['Score']]
    ax2.barh(df_sorted['Dominio'], df_sorted['Score'], color=colors)
    ax2.set_title('Security Score Global (0-100)', fontsize=10, fontweight='bold', color='#003366')
    ax2.set_xlim(0, 100)
    ax2.tick_params(axis='y', labelsize=8)
    
    plt.tight_layout()
    chart_path = "temp_chart.png"
    plt.savefig(chart_path, format='png', dpi=200)
    plt.close()
    return chart_path

def export_pdf_report(df, chart_path, pdf_path):
    pdf = FPDF(orientation='L', unit='mm', format='A4')
    pdf.set_auto_page_break(auto=True, margin=10)
    pdf.add_page()
    
    # --- CABECERA EJECUTIVA ---
    pdf.set_font("Arial", 'B', 15)
    pdf.set_text_color(0, 51, 102) # Azul corporativo
    pdf.cell(0, 7, "INFORME DE AUDITORÍA INTEGRAL DE CIBERSEGURIDAD", ln=True, align='C')
    
    pdf.set_font("Arial", '', 8)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 5, f"Fecha de ejecución: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Estado perimetral y normativo", ln=True, align='C')
    pdf.ln(2)
    
    # --- DASHBOARD GRÁFICO ---
    if os.path.exists(chart_path):
        pdf.image(chart_path, x=58, y=22, w=160)
        pdf.ln(54)
        
    # --- TÍTULO DE SECCIÓN ---
    pdf.set_font("Arial", 'B', 9)
    pdf.set_text_color(0, 51, 102)
    pdf.cell(0, 5, "Detalle Consolidado: [1] Protecciones de Correo y DNS  |  [2] Navegación Web, Certificados y CSP", ln=True)
    pdf.ln(1)
    
    # --- TABLA DE DATOS MAQUETADA ---
    columns = list(df.columns)
    # Anchos óptimos distribuidos para los 277 mm útiles de A4 Landscape
    col_widths = [26, 32, 16, 26, 14, 10, 10, 12, 14, 14, 12, 16, 12, 16, 12, 12, 11]
    
    # Cabecera de la tabla
    pdf.set_font("Arial", 'B', 6.5)
    pdf.set_fill_color(0, 51, 102) # Fondo Azul Marino
    pdf.set_text_color(255, 255, 255) # Texto Blanco
    
    for i, col in enumerate(columns):
        pdf.cell(col_widths[i], 6, col, border=1, fill=True, align='C')
    pdf.ln()
    
    # Filas de datos con Zebra Striping (colores alternos)
    pdf.set_font("Arial", '', 6)
    pdf.set_text_color(50, 50, 50)
    
    fill = False
    for _, row in df.iterrows():
        if fill:
            pdf.set_fill_color(245, 247, 250) # Gris muy suave
        else:
            pdf.set_fill_color(255, 255, 255) # Blanco
            
        for i, col in enumerate(columns):
            # Centrar textos cortos y alinear dominios a la izquierda si es necesario
            align = 'L' if i == 0 else 'C'
            pdf.cell(col_widths[i], 5, str(row[col]), border=1, fill=True, align=align)
        pdf.ln()
        fill = not fill
        
    pdf.output(pdf_path)
    print(f"Reporte PDF generado exitosamente: {pdf_path}")
    
    if os.path.exists(chart_path):
        os.remove(chart_path)

# ==============================================================================
# 6. EJECUCIÓN PRINCIPAL
# ==============================================================================
if __name__ == "__main__":
    try:
        lista_dominios = cargar_dominios()
        print(f"Se han cargado {len(lista_dominios)} dominios para auditoría.")
        
        df_results = generate_security_data(lista_dominios)
        chart_path = create_dashboard_image(df_results)
        
        pdf_output = "reporte_seguridad_integral.pdf"
        export_pdf_report(df_results, chart_path, pdf_output)
        
    except FileNotFoundError as e:
        print(e)
    except Exception as e:
        print(f"Error inesperado durante la ejecución: {e}")

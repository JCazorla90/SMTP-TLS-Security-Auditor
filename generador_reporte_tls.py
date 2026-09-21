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
    """
    Evalúa los mecanismos de protección de correo:
    - SPF: Servidores IP autorizados para enviar correo.
    - DKIM: Firma digital criptográfica de autenticidad.
    - DMARC: Políticas de alineación y reporte.
    - MTA-STS y TLS-RPT: Seguridad estricta y reporte de fallos en tránsito.
    """
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
            email_sec["DKIM"] = "Verificar"
            
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
    """Evalúa la conexión STARTTLS y extrae protocolo, cipher suite y bits."""
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
    """Inspecciona la salud del certificado (validez, caducidad y autofirmados)."""
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
                    cert_results["Estado"] = "Autofirmado"
                else:
                    cert_results["Autofirmado"] = "No"
    except Exception:
        cert_results["Estado"] = "Error Conexión"
        
    return cert_results

def evaluate_web_security_and_csp(domain):
    """Evalúa HTTPS, HSTS y aísla Content Security Policy (CSP)."""
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
        print(f"Procesando auditoría integral para: {domain}...")
        
        # Bloque Correo
        mx_records = check_dns_records(domain, 'MX')
        mx_host = mx_records[0].split()[1].rstrip('.') if mx_records else None
        proto, cipher, bits = evaluate_smtp_tls(mx_host) if mx_host else ("N/A", "N/A", 0)
        email_sec = evaluate_email_protections(domain)
        
        # Bloque Web y Certificados
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
# 5. GENERACIÓN DE GRÁFICO Y REPORTE PDF NATIVO
# ==============================================================================
def create_dashboard_image(df):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4))
    
    protocol_counts = df['Protocolo TLS'].value_counts()
    ax1.pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%', colors=['#4CAF50', '#F44336', '#FFC107'])
    ax1.set_title('Protocolos TLS (Correo)')
    
    df_sorted = df.sort_values('Score', ascending=True)
    colors = ['#F44336' if s < 60 else '#FFC107' if s < 90 else '#4CAF50' for s in df_sorted['Score']]
    ax2.barh(df_sorted['Dominio'], df_sorted['Score'], color=colors)
    ax2.set_title('Security Score Global (0-100)')
    ax2.set_xlim(0, 100)
    
    plt.tight_layout()
    chart_path = "temp_chart.png"
    plt.savefig(chart_path, format='png', dpi=150)
    plt.close()
    return chart_path

def export_pdf_report(df, chart_path, pdf_path):
    pdf = FPDF(orientation='L', unit='mm', format='A4')
    pdf.add_page()
    
    # Cabecera
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 8, "Informe de Auditoria Integral de Ciberseguridad", ln=True, align='C')
    pdf.set_font("Arial", '', 9)
    pdf.cell(0, 5, f"Fecha de escaneo: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
    pdf.ln(2)
    
    # Gráfico Dashboard
    if os.path.exists(chart_path):
        pdf.image(chart_path, x=65, y=20, w=150)
        pdf.ln(58)
        
    # Título Tabla
    pdf.set_font("Arial", 'B', 9)
    pdf.cell(0, 5, "Resumen Consolidado: [1] Protecciones Correo (SPF, DKIM, DMARC, MTA-STS, TLS-RPT) | [2] Web, Certificados y CSP", ln=True)
    pdf.set_font("Arial", 'B', 6)
    
    columns = list(df.columns)
    # Anchos óptimos para formato horizontal A4 (~277 mm útiles para 17 columnas)
    col_widths = [26, 32, 16, 28, 14, 10, 10, 12, 14, 14, 12, 16, 12, 16, 12, 12, 11]
    
    for i, col in enumerate(columns):
        pdf.cell(col_widths[i], 6, col, border=1, align='C')
    pdf.ln()
    
    pdf.set_font("Arial", '', 6)
    for _, row in df.iterrows():
        for i, col in enumerate(columns):
            pdf.cell(col_widths[i], 5, str(row[col]), border=1, align='C')
        pdf.ln()
        
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

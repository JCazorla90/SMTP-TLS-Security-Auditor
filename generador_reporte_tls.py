import smtplib
import ssl
import socket
import http.client
import dns.resolver
import pandas as pd
import matplotlib.pyplot as plt
import os
import sys
import time
import threading
import base64
import requests
from datetime import datetime
from fpdf import FPDF

# ==============================================================================
# CONFIGURACIÓN DE APIS Y EXTERNOS (Opcional)
# ==============================================================================
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "") # Configura tu API Key si dispones de ella

estado_actual = ["Inicializando motor de inteligencia perimetral..."]

def animar_progreso_tecnico(stop_event):
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\r\033[96m{frames[i % len(frames)]}\033[0m \033[1m[ESTADO]\033[0m {estado_actual[0]}                  ")
        sys.stdout.flush()
        time.sleep(0.08)
        i += 1
    sys.stdout.write("\r" + " " * 120 + "\r")
    sys.stdout.flush()

# ==============================================================================
# CARGA DE DOMINIOS, LISTAS BLANCAS Y NEGRAS
# ==============================================================================
def cargar_fichero(ruta):
    if not os.path.exists(ruta):
        return []
    with open(ruta, 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def cargar_configuracion():
    estado_actual[0] = "Cargando dominios y políticas de listas (White/Blacklist)..."
    dominios = cargar_fichero("dominios.txt")
    if not dominios:
        raise FileNotFoundError("Error: No se encontró el archivo 'dominios.txt' o está vacío.")
    
    whitelists = set(cargar_fichero("whitelist.txt"))
    blacklists = set(cargar_fichero("blacklist.txt"))
    return dominios, whitelists, blacklists

# ==============================================================================
# MÓDULOS DE INTELIGENCIA Y REPUTACIÓN (DNSBL & SHODAN)
# ==============================================================================
def check_dnsbl(ip):
    """Verifica si una IP está en listas negras globales de correo (Ej. Spamhaus)."""
    if not ip or ip == "No encontrado":
        return "Clean"
    try:
        rev_ip = ".".join(reversed(ip.split(".")))
        query = f"{rev_ip}.zen.spamhaus.org"
        dns.resolver.resolve(query, 'A')
        return "Listado en Blacklist (Spamhaus)"
    except Exception:
        return "Clean"

def query_shodan(ip):
    """Consulta Shodan API para detectar servicios expuestos y vulnerabilidades."""
    if not SHODAN_API_KEY or not ip or ip == "No encontrado":
        return {"ports": [], "vulnerabilities": []}
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            data = res.json()
            return {
                "ports": data.get("ports", []),
                "vulnerabilities": list(data.get("vulns", []))
            }
    except Exception:
        pass
    return {"ports": [], "vulnerabilities": []}

# ==============================================================================
# MÓDULOS DE AUDITORÍA TÉCNICA (DNS, SMTP, SSL, WEB)
# ==============================================================================
def check_dns_records(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except Exception:
        return []

def evaluate_email_protections(domain):
    estado_actual[0] = f"[{domain}] Evaluando postura de correo (SPF, DKIM, DMARC)..."
    sec = {"SPF": "No", "DKIM": "No", "DMARC": "No", "MTA-STS": "No", "TLS-RPT": "No"}
    try:
        txt_records = check_dns_records(domain, 'TXT')
        if any("v=spf1" in txt for txt in txt_records): sec["SPF"] = "Sí"
        
        dmarc_records = check_dns_records(f"_dmarc.{domain}", 'TXT')
        if any("v=DMARC1" in txt for txt in dmarc_records): sec["DMARC"] = "Sí"
            
        dkim_records = check_dns_records(f"_domainkey.{domain}", 'TXT')
        sec["DKIM"] = "Sí" if dkim_records or any("k=rsa" in txt for txt in txt_records) else "Verif."
            
        mtasts_records = check_dns_records(f"_mta-sts.{domain}", 'TXT')
        if any("v=STSv1" in txt for txt in mtasts_records): sec["MTA-STS"] = "Sí"
            
        tlsrpt_records = check_dns_records(f"_smtp._tls.{domain}", 'TXT')
        if any("v=TLSRPTv1" in txt for txt in tlsrpt_records): sec["TLS-RPT"] = "Sí"
    except Exception:
        pass
    return sec

def evaluate_smtp_tls(mx_host, domain):
    estado_actual[0] = f"[{domain}] Ejecutando handshake STARTTLS en MX ({mx_host})..."
    try:
        server = smtplib.SMTP(mx_host, 25, timeout=8)
        server.ehlo()
        context = ssl.create_default_context()
        server.starttls(context=context)
        server.ehlo()
        cipher, proto, bits = server.sock.cipher()
        server.quit()
        return proto, cipher, bits
    except Exception as e:
        return "Fallo", str(e), 0

def evaluate_certificate_health(domain):
    estado_actual[0] = f"[{domain}] Inspeccionando validez de certificado SSL..."
    res = {"Cert Válido": "No", "Días Exp": 0, "Autofirmado": "Sí"}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get('notAfter')
                if not_after:
                    exp_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    dias = (exp_date - datetime.utcnow()).days
                    res["Días Exp"] = dias
                    res["Cert Válido"] = "Sí" if dias > 0 else "No"
                
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                res["Autofirmado"] = "Sí" if subject == issuer else "No"
    except Exception:
        pass
    return res

def evaluate_web_security(domain):
    estado_actual[0] = f"[{domain}] Analizando HTTPS, HSTS y CSP..."
    web = {"HTTPS": "No", "CSP": "No", "HSTS": "No"}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                web["HTTPS"] = "Sí"
        
        conn = http.client.HTTPSConnection(domain, timeout=5)
        conn.request("GET", "/")
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        if "content-security-policy" in headers: web["CSP"] = "Sí"
        if "strict-transport-security" in headers: web["HSTS"] = "Sí"
    except Exception:
        pass
    return web

# ==============================================================================
# PROCESAMIENTO GLOBAL Y CÁLCULO DE SCORE
# ==============================================================================
def generate_security_data(domains, whitelists, blacklists):
    results = []
    for domain in domains:
        estado_actual[0] = f"Analizando activo perimetral: {domain}"
        
        # Resolución IP y MX
        mx_records = check_dns_records(domain, 'MX')
        mx_host = mx_records[0].split()[1].rstrip('.') if mx_records else None
        mx_ip = socket.gethostbyname(mx_host) if mx_host else "No encontrado"
        
        # Verificaciones de inteligencia
        dnsbl_status = check_dnsbl(mx_ip)
        shodan_data = query_shodan(mx_ip)
        
        # Evaluaciones técnicas
        proto, cipher, bits = evaluate_smtp_tls(mx_host, domain) if mx_host else ("N/A", "N/A", 0)
        email_sec = evaluate_email_protections(domain)
        cert_sec = evaluate_certificate_health(domain)
        web_sec = evaluate_web_security(domain)
        
        # Cálculo de Score Ponderado (0-100)
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
        
        # Penalizaciones por reputación
        if domain in blacklists or dnsbl_status != "Clean": score = max(0, score - 30)
        if domain in whitelists: score = min(100, score + 10)

        results.append({
            "Dominio": domain,
            "IP MX": mx_ip,
            "Reputación": "Blacklisted" if (domain in blacklists or dnsbl_status != "Clean") else "Trusted",
            "Protocolo TLS": proto,
            "Bits": bits,
            "SPF": email_sec["SPF"],
            "DKIM": email_sec["DKIM"],
            "DMARC": email_sec["DMARC"],
            "MTA-STS": email_sec["MTA-STS"],
            "HTTPS": web_sec["HTTPS"],
            "Cert Válido": cert_sec["Cert Válido"],
            "Días Exp": str(cert_sec["Días Exp"]),
            "CSP": web_sec["CSP"],
            "HSTS": web_sec["HSTS"],
            "Score": score
        })
    return pd.DataFrame(results)

# ==============================================================================
# GENERACIÓN DE REPORTES PROFESIONALES (PDF & HTML)
# ==============================================================================
class PDFReporteCorporativo(FPDF):
    def header(self):
        self.set_fill_color(15, 32, 67) # Azul marino corporativo
        self.rect(0, 0, 297, 12, 'F')
        self.set_font('Arial', 'B', 8)
        self.set_text_color(255, 255, 255)
        self.cell(0, 6, "  REPSOL ENTERPRISE SECURITY POSTURE & THREAT INTELLIGENCE", border=0, align='L')
        self.ln(12)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 7)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f"Página {self.page_no()} | Clasificación: Información Confidencial", 0, 0, 'C')

def create_dashboard_image(df):
    estado_actual[0] = "Renderizando dashboard analítico..."
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 3.6))
    
    rep_counts = df['Reputación'].value_counts()
    ax1.pie(rep_counts, labels=rep_counts.index, autopct='%1.1f%%', colors=['#4CAF50', '#F44336'])
    ax1.set_title('Estado de Reputación / Listas', fontsize=10, fontweight='bold', color='#0F2043')
    
    df_sorted = df.sort_values('Score', ascending=True)
    colors = ['#F44336' if s < 60 else '#FFC107' if s < 90 else '#0F2043' for s in df_sorted['Score']]
    ax2.barh(df_sorted['Dominio'], df_sorted['Score'], color=colors)
    ax2.set_title('Security Score Global (0-100)', fontsize=10, fontweight='bold', color='#0F2043')
    ax2.set_xlim(0, 100)
    ax2.tick_params(axis='y', labelsize=8)
    
    plt.tight_layout()
    chart_path = "temp_chart.png"
    plt.savefig(chart_path, format='png', dpi=200)
    plt.close()
    return chart_path

def export_pdf_report(df, chart_path, pdf_path):
    pdf = PDFReporteCorporativo(orientation='L', unit='mm', format='A4')
    pdf.set_auto_page_break(auto=True, margin=10)
    pdf.add_page()
    
    pdf.set_font("Arial", 'B', 15)
    pdf.set_text_color(15, 32, 67)
    pdf.cell(0, 7, "INFORME DE SOLUCIÓN DE ARQUITECTURA Y SEGURIDAD PERIMETRAL", ln=True, align='L')
    
    pdf.set_font("Arial", '', 8)
    pdf.set_text_color(100, 100, 100)
    promedio_score = int(df['Score'].mean()) if not df.empty else 0
    pdf.cell(0, 5, f"Fecha de emisión: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  Score Promedio: {promedio_score}/100", ln=True, align='L')
    pdf.ln(2)
    
    if os.path.exists(chart_path):
        pdf.image(chart_path, x=58, y=25, w=160)
        pdf.ln(54)
        
    pdf.set_font("Arial", 'B', 9)
    pdf.set_text_color(15, 32, 67)
    pdf.cell(0, 5, "Matriz Consolidada de Riesgos: [1] Reputación & DNSBL  |  [2] Criptografía TLS  |  [3] Controles Web", ln=True)
    pdf.ln(1)
    
    columns = list(df.columns)
    col_widths = [28, 26, 22, 22, 12, 10, 10, 12, 14, 14, 14, 14, 12, 12, 17]
    
    pdf.set_font("Arial", 'B', 6.5)
    pdf.set_fill_color(15, 32, 67)
    pdf.set_text_color(255, 255, 255)
    
    for i, col in enumerate(columns):
        pdf.cell(col_widths[i], 6, col, border=1, fill=True, align='C')
    pdf.ln()
    
    pdf.set_font("Arial", '', 6)
    pdf.set_text_color(50, 50, 50)
    
    fill = False
    for _, row in df.iterrows():
        pdf.set_fill_color(240, 243, 248) if fill else pdf.set_fill_color(255, 255, 255)
        for i, col in enumerate(columns):
            align = 'L' if i == 0 else 'C'
            pdf.cell(col_widths[i], 5, str(row[col]), border=1, fill=True, align=align)
        pdf.ln()
        fill = not fill

    # Glosario
    pdf.ln(4)
    pdf.set_font("Arial", 'B', 9)
    pdf.set_text_color(15, 32, 67)
    pdf.cell(0, 5, "Glosario Técnico y Criterios de Evaluación", ln=True)
    pdf.ln(1)
    
    glosario = [
        ("Reputación", "Evaluación cruzada con listas negras (DNSBL) y políticas internas de whitelisting/blacklisting."),
        ("SPF / DKIM / DMARC", "Controles estrictos anti-spoofing y autenticación de origen para correo electrónico corporativo."),
        ("HSTS / CSP", "Cabeceras perimetrales obligatorias de seguridad web para mitigación de ataques de transporte e inyección (XSS).")
    ]
    for termino, desc in glosario:
        pdf.set_font("Arial", 'B', 6.5)
        pdf.set_text_color(15, 32, 67)
        pdf.write(4, f"- {termino}: ")
        pdf.set_font("Arial", '', 6.5)
        pdf.set_text_color(80, 80, 80)
        pdf.write(4, f"{desc}\n")
        
    pdf.output(pdf_path)

def export_html_report(df, chart_path, html_path):
    image_base64 = ""
    if os.path.exists(chart_path):
        with open(chart_path, "rb") as f:
            image_base64 = base64.b64encode(f.read()).decode('utf-8')
            
    html_content = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Informe Ejecutivo de Seguridad y Activos</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 30px; background-color: #f4f6f9; color: #333; }}
            .container {{ background: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }}
            h1 {{ color: #0F2043; border-bottom: 3px solid #0F2043; padding-bottom: 10px; }}
            .metadata {{ font-size: 14px; color: #666; margin-bottom: 20px; }}
            .chart {{ text-align: center; margin: 20px 0; }}
            .chart img {{ max-width: 100%; border: 1px solid #ddd; border-radius: 6px; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 20px; font-size: 12px; }}
            th, td {{ border: 1px solid #dcdcdc; padding: 8px; text-align: center; }}
            th {{ background-color: #0F2043; color: white; }}
            tr:nth-child(even) {{ background-color: #f8fafc; }}
            td:first-child {{ text-align: left; font-weight: bold; }}
            .glosario {{ margin-top: 30px; background: #f8fafc; padding: 20px; border-left: 4px solid #0F2043; border-radius: 4px; }}
            .footer {{ margin-top: 30px; text-align: center; font-size: 12px; color: #888; border-top: 1px solid #ddd; padding-top: 10px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>INFORME DE SOLUCIÓN DE ARQUITECTURA Y SEGURIDAD</h1>
            <div class="metadata">
                <strong>Fecha de emisión:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | <strong>Score Global Promedio:</strong> {int(df['Score'].mean())}/100
            </div>
            <div class="chart">
                <img src="data:image/png;base64,{image_base64}" alt="Dashboard Analítico">
            </div>
            <h2>Matriz Consolidada de Seguridad Perimetral</h2>
            {df.to_html(index=False, classes='table', escape=False)}
            <div class="glosario">
                <h3>Glosario Técnico y Criterios</h3>
                <p><strong>- Reputación:</strong> Validación cruzada con listas negras (DNSBL) y políticas de confianza corporativa.</p>
                <p><strong>- Controles Perimetrales:</strong> Auditoría automatizada de estándares TLS, SPF, DKIM, DMARC y cabeceras de navegación web.</p>
            </div>
            <div class="footer">
                <p>Uso Interno Exclusivo - Arquitectura y Seguridad Corporativa</p>
            </div>
        </div>
    </body>
    </html>
    """
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

# ==============================================================================
# EJECUCIÓN PRINCIPAL
# ==============================================================================
if __name__ == "__main__":
    try:
        stop_animation = threading.Event()
        hilo = threading.Thread(target=animar_progreso_tecnico, args=(stop_animation,))
        hilo.start()
        
        dominios, whitelists, blacklists = cargar_configuracion()
        df_results = generate_security_data(dominios, whitelists, blacklists)
        chart_path = create_dashboard_image(df_results)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_out = f"reporte_seguridad_{timestamp}.pdf"
        html_out = f"reporte_seguridad_{timestamp}.html"
        
        export_pdf_report(df_results, chart_path, pdf_out)
        export_html_report(df_results, chart_path, html_out)
        
        stop_animation.set()
        hilo.join()
        
        if os.path.exists(chart_path): os.remove(chart_path)
        
        print(f"informe listo puedes verlo en {os.path.abspath(pdf_out)} y {os.path.abspath(html_out)}")
        
    except Exception as e:
        if 'stop_animation' in locals(): stop_animation.set()
        print(f"\n[ERROR] {e}")

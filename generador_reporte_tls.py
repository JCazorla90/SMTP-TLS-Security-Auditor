import smtplib
import ssl
import socket
import http.client
import dns.resolver
import pandas as pd
import matplotlib.pyplot as plt
import os
import sys
import base64
import requests
from datetime import datetime
from fpdf import FPDF

# ==============================================================================
# CONFIGURACIÓN DE APIS Y LISTAS NEGRAS LOCALES
# ==============================================================================
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

def cargar_fichero(ruta):
    if not os.path.exists(ruta):
        return []
    with open(ruta, 'r', encoding='utf-8') as f:
        return [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]

def cargar_configuracion():
    print("[-] Cargando dominios base desde 'dominios.txt'...")
    dominios_base = cargar_fichero("dominios.txt")
    if not dominios_base:
        raise FileNotFoundError("Error: No se encontró el archivo 'dominios.txt' o está vacío.")
    
    activos_con_origen = {}
    for dom in dominios_base:
        activos_con_origen[dom] = "Base (Manual)"
        
    # 1. Descubrimiento OSINT vía crt.sh (Certificate Transparency)
    for dom in dominios_base:
        print(f"[*] [OSINT] Consultando subdominios en crt.sh para: {dom}...")
        try:
            url = f"https://crt.sh/?q=%.{dom}&output=json"
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                data = res.json()
                contador = 0
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub and '*' not in sub and sub not in activos_con_origen:
                            activos_con_origen[sub] = "crt.sh (OSINT)"
                            contador += 1
                print(f"    -> Encontrados {contador} subdominios nuevos.")
        except Exception as e:
            print(f"    -> Aviso: Error al conectar con crt.sh ({e}).")

    whitelists = set(cargar_fichero("whitelist.txt"))
    blacklists_fichero = set(cargar_fichero("blacklist_dominios.txt"))
    blacklists = whitelists.union(blacklists_fichero)
    
    return activos_con_origen, whitelists, blacklists

# ==============================================================================
# MÓDULO DE ESCANEO DE VULNERABILIDADES Y PUERTOS (Estilo Nessus / OpenVAS)
# ==============================================================================
def escanear_puertos_criticos(domain):
    """
    Simula un escaneo de vulnerabilidades e infraestructura comprobando 
    la exposición de puertos críticos y servicios potencialmente riesgosos.
    """
    puertos_a_escanear = {
        21: "FTP (Inseguro/Expuesto)",
        22: "SSH (Administración Remota)",
        80: "HTTP (Texto Plano)",
        443: "HTTPS (Seguro)",
        3306: "MySQL (Base de Datos Expuesta)",
        3389: "RDP (Escritorio Remoto Expuesto)",
        8080: "HTTP-Proxy / Alternativo"
    }
    
    puertos_abiertos = []
    riesgo_detectado = "Bajo"
    
    for puerto, descripcion in puertos_a_escanear.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                resultado = s.connect_ex((domain, puerto))
                if resultado == 0:
                    puertos_abiertos.append(str(puerto))
                    # Si hay puertos altamente sensibles expuestos, elevamos el riesgo
                    if puerto in [21, 3306, 3389]:
                        riesgo_detectado = "Crítico / Alto"
                    elif puerto == 80 and riesgo_detectado != "Crítico / Alto":
                        riesgo_detectado = "Medio"
        except Exception:
            pass
            
    return puertos_abiertos, riesgo_detectado

# ==============================================================================
# MÓDULOS DE REPUTACIÓN Y ANÁLISIS Criptográfico
# ==============================================================================
def check_dnsbl(ip):
    if not ip or ip == "No encontrado":
        return "Clean"
    try:
        rev_ip = ".".join(reversed(ip.split(".")))
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        resolver.resolve(f"{rev_ip}.zen.spamhaus.org", 'A')
        return "Listado en Spamhaus"
    except Exception:
        return "Clean"

def check_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY or not ip or ip == "No encontrado":
        return "Clean"
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        headers = {'Accept': 'json', 'Key': ABUSEIPDB_API_KEY}
        response = requests.get(url, headers=headers, params=params, timeout=4)
        if response.status_code == 200:
            score = response.json().get('data', {}).get('abuseConfidenceScore', 0)
            if score > 25:
                return f"Maliciosa ({score}%)"
    except Exception:
        pass
    return "Clean"

def auditar_protocolos_tls(domain, port=443):
    soporte = {"TLS 1.2": "No", "TLS 1.3": "No"}
    try:
        ctx12 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx12.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx12.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx12.check_hostname = False
        ctx12.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, port), timeout=3) as sock:
            with ctx12.wrap_socket(sock, server_hostname=domain) as ssock:
                soporte["TLS 1.2"] = f"Sí ({ssock.cipher()[0][:12]})"
    except Exception:
        pass

    try:
        ctx13 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx13.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx13.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx13.check_hostname = False
        ctx13.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, port), timeout=3) as sock:
            with ctx13.wrap_socket(sock, server_hostname=domain) as ssock:
                soporte["TLS 1.3"] = f"Sí ({ssock.cipher()[0][:12]})"
    except Exception:
        pass
    return soporte

def check_dns_records(domain, record_type):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        return [str(r) for r in resolver.resolve(domain, record_type)]
    except Exception:
        return []

def evaluate_email_protections(domain):
    sec = {"SPF": "No", "DMARC": "No"}
    try:
        txt = check_dns_records(domain, 'TXT')
        if any("v=spf1" in t for t in txt): sec["SPF"] = "Sí"
        dmarc = check_dns_records(f"_dmarc.{domain}", 'TXT')
        if any("v=DMARC1" in t for t in dmarc): sec["DMARC"] = "Sí"
    except Exception:
        pass
    return sec

def evaluate_certificate_health(domain):
    res = {"Cert Válido": "No", "Días Exp": 0}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get('notAfter')
                if not_after:
                    dias = (datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z') - datetime.utcnow()).days
                    res["Días Exp"] = dias
                    res["Cert Válido"] = "Sí" if dias > 0 else "No"
    except Exception:
        pass
    return res

def generate_security_data(activos_con_origen, whitelists, blacklists):
    results = []
    activos_lista = list(activos_con_origen.items())[:20]
    
    for domain, origen in activos_lista:
        print(f"[-] Analizando activo [{origen}]: {domain}...")
        
        # 1. Escaneo de Vulnerabilidades y Puertos (Estilo Nessus/OpenVAS)
        puertos_abiertos, nivel_riesgo_puertos = escanear_puertos_criticos(domain)
        
        # Resolución IP
        try:
            ip_activo = socket.gethostbyname(domain)
        except Exception:
            ip_activo = "No encontrado"
            
        # Reputación y Listas Negras
        en_lista_negra = domain in blacklists
        dnsbl_status = check_dnsbl(ip_activo)
        abuse_status = check_abuseipdb(ip_activo)
        
        reputacion = "Trusted"
        if en_lista_negra or dnsbl_status != "Clean" or "Maliciosa" in abuse_status:
            reputacion = "Blacklisted / Riesgo"

        tls_soporte = auditar_protocolos_tls(domain)
        email_sec = evaluate_email_protections(domain)
        cert_sec = evaluate_certificate_health(domain)
        
        # Cálculo de Puntuación (Security Score) con penalizaciones por vulnerabilidades/puertos abiertos
        score = 100
        if "Sí" not in tls_soporte["TLS 1.2"] and "Sí" not in tls_soporte["TLS 1.3"]: score -= 20
        if email_sec["SPF"] == "No": score -= 10
        if email_sec["DMARC"] == "No": score -= 15
        if cert_sec["Cert Válido"] == "No": score -= 25
        if nivel_riesgo_puertos == "Crítico / Alto": score -= 35
        elif nivel_riesgo_puertos == "Medio": score -= 15
        if reputacion != "Trusted": score -= 40
        
        score = max(0, min(100, score))

        results.append({
            "Dominio / Activo": domain,
            "Origen": origen,
            "IP": ip_activo,
            "Reputación": reputacion,
            "Puertos Abiertos": ", ".join(puertos_abiertos) if puertos_abiertos else "Ninguno",
            "Riesgo Infra": nivel_riesgo_puertos,
            "TLS 1.2/1.3": f"{tls_soporte['TLS 1.2']}/{tls_soporte['TLS 1.3']}",
            "SPF": email_sec["SPF"],
            "DMARC": email_sec["DMARC"],
            "Cert Válido": cert_sec["Cert Válido"],
            "Días Exp": str(cert_sec["Días Exp"]),
            "Score": score
        })
    return pd.DataFrame(results)

# ==============================================================================
# EXPORTADORES A PDF Y HTML CORPORATIVOS
# ==============================================================================
class PDFReporteCorporativo(FPDF):
    def header(self):
        self.set_fill_color(15, 32, 67)
        self.rect(0, 0, 297, 12, 'F')
        self.set_font('Arial', 'B', 8)
        self.set_text_color(255, 255, 255)
        self.cell(0, 6, "  CYBERSECURITY POSTURE ASSESSMENT & VULNERABILITY SCANNER", border=0, align='L')
        self.ln(12)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 7)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f"Página {self.page_no()} | Clasificación: Información Confidencial", 0, 0, 'C')

def create_dashboard_image(df):
    print("[-] Renderizando dashboard analítico...")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 3.6))
    
    risk_counts = df['Riesgo Infra'].value_counts()
    ax1.pie(risk_counts, labels=risk_counts.index, autopct='%1.1f%%', colors=['#4CAF50', '#FFC107', '#F44336'])
    ax1.set_title('Nivel de Riesgo de Infraestructura', fontsize=10, fontweight='bold', color='#0F2043')
    
    df_sorted = df.sort_values('Score', ascending=True)
    colors = ['#F44336' if s < 60 else '#FFC107' if s < 90 else '#0F2043' for s in df_sorted['Score']]
    ax2.barh(df_sorted['Dominio / Activo'], df_sorted['Score'], color=colors)
    ax2.set_title('Security Score Global (0-100)', fontsize=10, fontweight='bold', color='#0F2043')
    ax2.set_xlim(0, 100)
    ax2.tick_params(axis='y', labelsize=7)
    
    plt.tight_layout()
    chart_path = "temp_chart.png"
    plt.savefig(chart_path, format='png', dpi=200)
    plt.close()
    return chart_path

def export_pdf_report(df, chart_path, pdf_path):
    print(f"[-] Compilando documento PDF en '{pdf_path}'...")
    pdf = PDFReporteCorporativo(orientation='L', unit='mm', format='A4')
    pdf.set_auto_page_break(auto=True, margin=10)
    pdf.add_page()
    
    pdf.set_font("Arial", 'B', 14)
    pdf.set_text_color(15, 32, 67)
    pdf.cell(0, 7, "INFORME DE VULNERABILIDADES, OSINT Y SEGURIDAD PERIMETRAL", ln=True, align='L')
    
    pdf.set_font("Arial", '', 8)
    pdf.set_text_color(100, 100, 100)
    promedio = int(df['Score'].mean()) if not df.empty else 0
    pdf.cell(0, 5, f"Emisión: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  Score Promedio: {promedio}/100  |  Activos analizados: {len(df)}", ln=True, align='L')
    pdf.ln(2)
    
    if os.path.exists(chart_path):
        pdf.image(chart_path, x=58, y=24, w=160)
        pdf.ln(54)
        
    pdf.set_font("Arial", 'B', 9)
    pdf.set_text_color(15, 32, 67)
    pdf.cell(0, 5, "Matriz de Exposición de Puertos, Vulnerabilidades y Criptografía", ln=True)
    pdf.ln(1)
    
    columns = list(df.columns)
    col_widths = [36, 24, 24, 28, 30, 22, 24, 14, 14, 16, 14, 15]
    
    pdf.set_font("Arial", 'B', 6)
    pdf.set_fill_color(15, 32, 67)
    pdf.set_text_color(255, 255, 255)
    
    for i, col in enumerate(columns):
        pdf.cell(col_widths[i], 6, col, border=1, fill=True, align='C')
    pdf.ln()
    
    pdf.set_font("Arial", '', 5.5)
    pdf.set_text_color(50, 50, 50)
    
    fill = False
    for _, row in df.iterrows():
        pdf.set_fill_color(240, 243, 248) if fill else pdf.set_fill_color(255, 255, 255)
        for i, col in enumerate(columns):
            align = 'L' if i == 0 else 'C'
            pdf.cell(col_widths[i], 5, str(row[col]), border=1, fill=True, align=align)
        pdf.ln()
        fill = not fill

    # Glosario Técnico
    pdf.ln(4)
    pdf.set_font("Arial", 'B', 9)
    pdf.set_text_color(15, 32, 67)
    pdf.cell(0, 5, "Glosario de Controles de Vulnerabilidades e Inteligencia", ln=True)
    pdf.ln(1)
    
    glosario = [
        ("Escáner de Puertos (Nessus/OpenVAS style)", "Detección automatizada de puertos críticos expuestos a Internet (FTP, SSH, MySQL, RDP)."),
        ("crt.sh OSINT", "Descubrimiento de subdominios corporativos mediante Certificate Transparency."),
        ("Listas Negras / DNSBL", "Verificación de reputación de IP contra bases de datos de spam, fraude y abuso.")
    ]
    for term, desc in glosario:
        pdf.set_font("Arial", 'B', 6.5)
        pdf.set_text_color(15, 32, 67)
        pdf.write(4, f"- {term}: ")
        pdf.set_font("Arial", '', 6.5)
        pdf.set_text_color(80, 80, 80)
        pdf.write(4, f"{desc}\n")
        
    pdf.output(pdf_path)

def export_html_report(df, chart_path, html_path):
    print(f"[-] Compilando documento HTML en '{html_path}'...")
    image_base64 = ""
    if os.path.exists(chart_path):
        with open(chart_path, "rb") as f:
            image_base64 = base64.b64encode(f.read()).decode('utf-8')
            
    html_content = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>Informe Integral de Vulnerabilidades y Seguridad</title>
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
            <h1>INFORME INTEGRAL DE VULNERABILIDADES, OSINT Y SEGURIDAD</h1>
            <div class="metadata">
                <strong>Fecha de emisión:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | <strong>Score Promedio:</strong> {int(df['Score'].mean())}/100
            </div>
            <div class="chart">
                <img src="data:image/png;base64,{image_base64}" alt="Dashboard Analítico">
            </div>
            <h2>Matriz Consolidada de Riesgos y Puertos Expuestos</h2>
            {df.to_html(index=False, classes='table', escape=False)}
            <div class="glosario">
                <h3>Glosario de Controles de Seguridad e Inteligencia Integrados</h3>
                <p><strong>- Escáner de Puertos:</strong> Detección de exposición de servicios críticos (Nessus/OpenVAS style).</p>
                <p><strong>- crt.sh OSINT:</strong> Descubrimiento automático de subdominios corporativos.</p>
                <p><strong>- Listas Negras (Blacklists / DNSBL):</strong> Verificación de reputación de IP contra abuso y spam.</p>
            </div>
            <div class="footer">
                <p>Información Confidencial - Uso Interno Exclusivo</p>
            </div>
        </div>
    </body>
    </html>
    """
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

# ==============================================================================
# EJECUCIÓN PRINCIPAL LOCAL
# ==============================================================================
if __name__ == "__main__":
    try:
        activos_con_origen, whitelists, blacklists = cargar_configuracion()
        df_results = generate_security_data(activos_con_origen, whitelists, blacklists)
        chart_path = create_dashboard_image(df_results)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_out = f"reporte_seguridad_{timestamp}.pdf"
        html_out = f"reporte_seguridad_{timestamp}.html"
        
        export_pdf_report(df_results, chart_path, pdf_out)
        export_html_report(df_results, chart_path, html_out)
        
        if os.path.exists(chart_path): 
            os.remove(chart_path)
        
        print(f"\n✔ ¡Informe listo! Puedes verlo en:\n- PDF: {os.path.abspath(pdf_out)}\n- HTML: {os.path.abspath(html_out)}")
        
    except Exception as e:
        print(f"\n[ERROR] {e}")

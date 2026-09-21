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
from datetime import datetime
from fpdf import FPDF

# ==============================================================================
# 1. ESTADO COMPARTIDO Y ANIMACIÓN TÉCNICA EN TIEMPO REAL
# ==============================================================================
estado_actual = ["Inicializando herramienta de auditoría perimetral..."]

def animar_progreso_tecnico(stop_event):
    """Muestra en la terminal la acción técnica exacta que el script está ejecutando."""
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\r\033[96m{frames[i % len(frames)]}\033[0m \033[1m[ESTADO]\033[0m {estado_actual[0]}                  ")
        sys.stdout.flush()
        time.sleep(0.08)
        i += 1
    sys.stdout.write(f"\r\033[92m✔ ¡Proceso finalizado correctamente!                                                          \033[0m\n")

# ==============================================================================
# 2. CONFIGURACIÓN EXTERNA (Carga de dominios desde fichero)
# ==============================================================================
def cargar_dominios(ruta_fichero="dominios.txt"):
    estado_actual[0] = f"Leyendo la lista de dominios desde '{ruta_fichero}'..."
    time.sleep(0.3)
    if not os.path.exists(ruta_fichero):
        raise FileNotFoundError(
            f"Error: No se encontró el archivo '{ruta_fichero}'. "
            "Crea este archivo e incluye un dominio por línea."
        )
    
    with open(ruta_fichero, 'r') as archivo:
        dominios = [linea.strip() for linea in archivo if linea.strip()]
    estado_actual[0] = f"Se han cargado {len(dominios)} dominios para análisis."
    return dominios

# ==============================================================================
# 3. MÓDULOS DE AUDITORÍA: CORREO Y DNS (SPF, DKIM, DMARC, MTA-STS, TLS-RPT)
# ==============================================================================
def check_dns_records(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except Exception:
        return []

def evaluate_email_protections(domain):
    estado_actual[0] = f"[{domain}] Consultando registros DNS (SPF, DKIM, DMARC)..."
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

# ==============================================================================
# 4. MÓDULOS DE AUDITORÍA: NAVEGACIÓN WEB, CERTIFICADOS Y CSP
# ==============================================================================
def evaluate_certificate_health(domain):
    estado_actual[0] = f"[{domain}] Inspeccionando salud y validez de certificado SSL..."
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
    estado_actual[0] = f"[{domain}] Analizando HTTPS, cabeceras HSTS y política CSP..."
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
# 5. PROCESAMIENTO INTEGRAL Y CÁLCULO DE SCORE GLOBAL
# ==============================================================================
def generate_security_data(domains):
    results = []
    for domain in domains:
        estado_actual[0] = f"Iniciando escaneo perimetral para el dominio: {domain}"
        
        mx_records = check_dns_records(domain, 'MX')
        mx_host = mx_records[0].split()[1].rstrip('.') if mx_records else None
        
        if mx_host:
            proto, cipher, bits = evaluate_smtp_tls(mx_host, domain)
        else:
            proto, cipher, bits = ("N/A", "Sin registro MX", 0)
            
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
# 6. CLASE PDF PERSONALIZADA CON ESTILO EJECUTIVO (BITSIGHT STYLE)
# ==============================================================================
class PDFReporteEjecutivo(FPDF):
    def header(self):
        # Cabecera corporativa superior
        self.set_fill_color(15, 32, 67) # Azul marino oscuro
        self.rect(0, 0, 297, 12, 'F')
        self.set_font('Arial', 'B', 8)
        self.set_text_color(255, 255, 255)
        self.cell(0, 6, "  CYBERSECURITY POSTURE ASSESSMENT & ASSET INTELLIGENCE", border=0, align='L')
        self.ln(12)

    def footer(self):
        # Pie de página formal
        self.set_y(-15)
        self.set_font('Arial', 'I', 7)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f"Página {self.page_no()} | Confidencial - Uso Interno Exclusivo", 0, 0, 'C')

def create_dashboard_image(df):
    estado_actual[0] = "Renderizando gráfico estadístico (Dashboard)..."
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 3.6))
    
    protocol_counts = df['Protocolo TLS'].value_counts()
    ax1.pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%', colors=['#0F2043', '#4CAF50', '#FFC107'])
    ax1.set_title('Protocolos TLS (Correo)', fontsize=10, fontweight='bold', color='#0F2043')
    
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
    estado_actual[0] = f"Compilando informe ejecutivo y generando PDF ('{pdf_path}')..."
    pdf = PDFReporteEjecutivo(orientation='L', unit='mm', format='A4')
    pdf.set_auto_page_break(auto=True, margin=10)
    pdf.add_page()
    
    # --- BLOQUE DE PORTADA / TÍTULO EJECUTIVO ---
    pdf.set_font("Arial", 'B', 16)
    pdf.set_text_color(15, 32, 67)
    pdf.cell(0, 8, "INFORME DE AUDITORÍA PERIMETRAL DE ACTIVOS", ln=True, align='L')
    
    pdf.set_font("Arial", '', 8)
    pdf.set_text_color(100, 100, 100)
    promedio_score = int(df['Score'].mean()) if not df.empty else 0
    pdf.cell(0, 5, f"Fecha de emisión: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  Score Promedio Global: {promedio_score}/100", ln=True, align='L')
    pdf.ln(3)
    
    # --- DASHBOARD GRÁFICO ---
    if os.path.exists(chart_path):
        pdf.image(chart_path, x=58, y=28, w=160)
        pdf.ln(56)
        
    # --- TÍTULO DE SECCIÓN ---
    pdf.set_font("Arial", 'B', 9)
    pdf.set_text_color(15, 32, 67)
    pdf.cell(0, 5, "Detalle Consolidado: [1] Protecciones de Correo y DNS  |  [2] Navegación Web, Certificados y CSP", ln=True)
    pdf.ln(1)
    
    # --- TABLA DE DATOS MAQUETADA ---
    columns = list(df.columns)
    col_widths = [26, 32, 16, 26, 14, 10, 10, 12, 14, 14, 12, 16, 12, 16, 12, 12, 11]
    
    # Cabecera de tabla
    pdf.set_font("Arial", 'B', 6.5)
    pdf.set_fill_color(15, 32, 67)
    pdf.set_text_color(255, 255, 255)
    
    for i, col in enumerate(columns):
        pdf.cell(col_widths[i], 6, col, border=1, fill=True, align='C')
    pdf.ln()
    
    # Filas con Zebra Striping
    pdf.set_font("Arial", '', 6)
    pdf.set_text_color(50, 50, 50)
    
    fill = False
    for _, row in df.iterrows():
        if fill:
            pdf.set_fill_color(240, 243, 248)
        else:
            pdf.set_fill_color(255, 255, 255)
            
        for i, col in enumerate(columns):
            align = 'L' if i == 0 else 'C'
            pdf.cell(col_widths[i], 5, str(row[col]), border=1, fill=True, align=align)
        pdf.ln()
        fill = not fill

    # --- GLOSARIO TÉCNICO ---
    pdf.ln(4)
    pdf.set_font("Arial", 'B', 9)
    pdf.set_text_color(15, 32, 67)
    pdf.cell(0, 5, "Glosario Técnico de Términos Evaluados", ln=True)
    
    glosario_items = [
        ("SPF", "Sender Policy Framework: Registro DNS TXT que define qué servidores IP están autorizados a enviar correo en nombre del dominio."),
        ("DKIM", "DomainKeys Identified Mail: Firma digital criptográfica que verifica la autenticidad del mensaje y garantiza que no ha sido alterado."),
        ("DMARC", "Domain-based Message Authentication: Protocolo de políticas que indica cómo manejar correos que fallan en SPF o DKIM."),
        ("MTA-STS", "Mail Transfer Agent Strict Transport Security: Asegura el cifrado estricto obligatorio en las transmisiones SMTP."),
        ("TLS-RPT", "TLS Reporting: Mecanismo para recibir informes de fallos y errores de entrega en las conexiones TLS de correo."),
        ("CSP", "Content Security Policy: Cabecera HTTP que mitiga ataques de inyección de código como XSS restringiendo recursos confiables."),
        ("HSTS", "HTTP Strict Transport Security: Directiva web que fuerza al navegador a comunicarse exclusivamente mediante HTTPS.")
    ]
    
    pdf.set_font("Arial", 'B', 6.5)
    for termino, descripcion in glosario_items:
        pdf.set_text_color(15, 32, 67)
        pdf.cell(18, 4, f"- {termino}:", border=0, align='L')
        pdf.set_font("Arial", '', 6.5)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(250, 4, descripcion, ln=True, align='L')
        pdf.set_font("Arial", 'B', 6.5)
        
    pdf.output(pdf_path)
    
    if os.path.exists(chart_path):
        os.remove(chart_path)

# ==============================================================================
# 7. EJECUCIÓN PRINCIPAL CON ANIMACIÓN TÉCNICA
# ==============================================================================
if __name__ == "__main__":
    try:
        stop_animation = threading.Event()
        hilo_animacion = threading.Thread(target=animar_progreso_tecnico, args=(stop_animation,))
        hilo_animacion.start()
        
        lista_dominios = cargar_dominios()
        df_results = generate_security_data(lista_dominios)
        chart_path = create_dashboard_image(df_results)
        
        pdf_output = "reporte_seguridad_integral.pdf"
        export_pdf_report(df_results, chart_path, pdf_output)
        
        stop_animation.set()
        hilo_animacion.join()
        
        print(f"\n✔ ¡Informe PDF de calidad ejecutiva generado con éxito: {pdf_output}!")
        
    except FileNotFoundError as e:
        stop_animation.set()
        hilo_animacion.join()
        print(f"\n[ERROR] {e}")
    except Exception as e:
        stop_animation.set()
        hilo_animacion.join()
        print(f"\n[ERROR] Error inesperado durante la ejecución: {e}")

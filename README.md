# 🛡️ SMTP / TLS & Web Security Auditor

Una herramienta automatizada en Python para auditoría de ciberseguridad perimetral y de dominios de correo. Este script evalúa la postura criptográfica de servidores SMTP, los registros DNS de protección anti-spoofing, la navegación web segura (HTTPS), las cabeceras defensivas y la salud de los certificados digitales, generando un informe ejecutivo unificado en PDF con gráficos integrados.

## 🚀 Características Principales

*   **Inspección SMTP y Cifrado:** Se conecta a los registros MX por el puerto 25 mediante `STARTTLS`, extrayendo el protocolo negociado (TLS v1.2, TLS v1.3), la *Cipher Suite* y la longitud de bits de cifrado.
*   **Protecciones Avanzadas de Correo (DNS):**
    *   **SPF** (*Sender Policy Framework*): Valida los servidores IP autorizados.
    *   **DKIM** (*DomainKeys Identified Mail*): Comprueba la infraestructura de firma criptográfica de claves.
    *   **DMARC** (*Domain-based Message Authentication, Reporting, and Conformance*): Verifica las políticas de alineación y reporte.
    *   **MTA-STS** (*Mail Transfer Agent Strict Transport Security*): Comprueba el forzado de cifrado estricto en tránsito.
    *   **TLS-RPT** (*TLS Reporting*): Valida la recepción de informes de errores en entregas TLS.
*   **Seguridad Web y Cabeceras Defensivas:**
    *   **HTTPS & HSTS**: Comprueba la conectividad segura perimetral y el forzado de transporte.
    *   **CSP** (*Content Security Policy*): Aísla y valida de forma independiente la mitigación frente a inyecciones de código (XSS).
*   **Salud de Certificados SSL/TLS:** Analiza la validez del certificado, calcula los **días restantes de expiración** y detecta certificados autofirmados o inseguros.
*   **Reporte PDF Nativo y Dashboard Visual:** Utiliza `matplotlib` para generar un panel gráfico de distribución y `fpdf2` para compilar un documento PDF ejecutivo en formato horizontal (*Landscape*) sin requerir dependencias externas del sistema operativo (como wkhtmltopdf).
*   **Configuración Dinámica:** Carga los dominios de forma externa desde un archivo `dominios.txt`, cumpliendo estrictamente con los estándares de parametrización de arquitectura.

## 📋 Requisitos Previos

La herramienta requiere Python 3.7 o superior. Puedes instalar las librerías necesarias ejecutando el siguiente comando:

```bash
pip install dnspython pandas matplotlib fpdf2
```

## ⚙️ Usage

1. Clone the repository:
   ```bash
   git clone <your-repository-url>
   cd <your-repository-directory>
   ```

2. ECreate a dominios.txt file in the root directory and add the domains you want to audit (one per line):
   ```
   bmw.com
   marca.com
   hobbyconsolas.com
   eltiempo.com
   ```

3. Run the script:
   ```bash
   python generador_reporte_tls.py
   ```

4. **View the Results:** Open the generated `reporte_seguridad_smtp.html` or `reporte_seguridad_smtp.pdf` file in any modern web browser to view the security score distribution and detailed compliance table.



## 📄 License

Copyright (c) 2026 José Cazorla Gijón

This software is provided "as is", without warranty of any kind. If you use, modify, or distribute any part of this code, you must include a clear attribution explicitly naming José Cazorla Gijón as the original author.

# 🛡️ SMTP / TLS & Web Security Auditor

Una herramienta automatizada en Python para auditoría de ciberseguridad perimetral y de dominios de correo. Este script evalúa la postura criptográfica de servidores SMTP, los registros DNS de protección anti-spoofing, la navegación web segura (HTTPS), las cabeceras defensivas y la salud de los certificados digitales, generando un informe ejecutivo unificado en PDF con gráficos integrados y marca de tiempo.

## 🚀 Características Principales

*   **Inspección SMTP y Cifrado:** Se conecta a los registros MX por el puerto 25 mediante `STARTTLS`, extrayendo el protocolo negociado (TLS v1.2, TLS v1.3), la *Cipher Suite* y la longitud de bits de cifrado.
*   **Protecciones Avanzadas de Correo (DNS):**
    *   **SPF** (*Sender Policy Framework*): Valida los servidores IP autorizados.
    *   **DKIM** (*DomainKeys Identified Mail*): Comprueba la infraestructura de firma criptográfica de claves en `_domainkey`.
    *   **DMARC** (*Domain-based Message Authentication, Reporting, and Conformance*): Verifica las políticas de alineación y reporte en `_dmarc`.
    *   **MTA-STS** (*Mail Transfer Agent Strict Transport Security*): Comprueba el forzado de cifrado estricto en tránsito.
    *   **TLS-RPT** (*TLS Reporting*): Valida la recepción de informes de errores en entregas TLS.
*   **Seguridad Web y Cabeceras Defensivas:**
    *   **HTTPS & HSTS**: Comprueba la conectividad segura perimetral y el forzado de transporte.
    *   **CSP** (*Content Security Policy*): Aísla y valida de forma independiente la mitigación frente a inyecciones de código (XSS).
*   **Salud de Certificados SSL/TLS:** Analiza la validez del certificado, calcula los **días restantes de expiración** y detecta certificados autofirmados o inseguros.
*   **Reporte PDF Nativo y Dashboard Visual:** Utiliza `matplotlib` para generar un panel gráfico de distribución y `fpdf2` para compilar un documento PDF ejecutivo en formato horizontal (*Landscape*) con glosario técnico integrado, sin requerir dependencias externas del sistema operativo (como wkhtmltopdf).
*   **Configuración Dinámica:** Carga los dominios de forma externa desde un archivo `dominios.txt`, cumpliendo estrictamente con los estándares de parametrización de arquitectura.

---

## 🔍 ¿Qué hace el script por debajo para comprobar todo?

Para realizar la auditoría de forma completamente automatizada y con librerías nativas de Python, el motor interno ejecuta los siguientes procedimientos técnicos:

1. **Resolución y Análisis DNS (`dnspython`):**
   - Consulta los registros **MX** del dominio para identificar el servidor de correo principal encargado de la entrega.
   - Realiza consultas de registros **TXT** para validar la existencia de directivas **SPF**, así como la infraestructura base de claves **DKIM** (`_domainkey`), **MTA-STS** (`_mta-sts`) y **TLS-RPT** (`_smtp._tls`).
   - Consulta de forma específica el subdominio `_dmarc.<dominio>` para comprobar la implementación de políticas **DMARC**.

2. **Auditoría de Protocolos y Cifrado SMTP (`smtplib` & `ssl`):**
   - Establece una conexión de red con el servidor de correo MX descubierto a través del puerto estándar **25**.
   - Ejecuta comandos de salutación (`EHLO`) e inicia un canal seguro mediante el comando **STARTTLS** utilizando contextos SSL seguros por defecto.
   - Extrae directamente del socket de la conexión la suite criptográfica exacta (*Cipher Suite*), el protocolo negociado (ej. `TLSv1.3`) y la fuerza del cifrado en bits.

3. **Inspección de Certificados Digitales y Conectividad Web (`socket` & `ssl`):**
   - Abre un socket TCP hacia el puerto **443** del dominio y envuelve la conexión con un contexto TLS seguro.
   - Extrae el certificado X.509 del servidor para leer la fecha de expiración (`notAfter`), calculando de forma matemática los **días restantes de validez**.
   - Compara el emisor (*Issuer*) y el sujeto (*Subject*) del certificado para detectar de manera automática si se trata de un certificado **autofirmado** o emitido por una Autoridad de Certificación (CA) confiable.

4. **Análisis de Cabeceras Defensivas y Políticas Web (`http.client`):**
   - Realiza una petición HTTP/HTTPS mediante `http.client` para inspeccionar las cabeceras de respuesta del servidor web.
   - Evalúa la presencia de la cabecera **Strict-Transport-Security (HSTS)** para verificar el forzado de conexiones cifradas.
   - Aísla y analiza la cabecera **Content-Security-Policy (CSP)** para validar las restricciones contra ataques de ejecución de scripts y XSS.

5. **Puntuación Global (Security Score) y Compilación del Informe:**
   - Asigna pesos ponderados a cada vector de seguridad evaluado, calculando una nota global de **0 a 100** por dominio.
   - Utiliza `matplotlib` para generar un gráfico estadístico en memoria (distribución de protocolos y barras de puntuación).
   - Utiliza `fpdf2` para estructurar un documento PDF apaisado (*Landscape*) con cabeceras ejecutivas, tablas con celdas alternas (*zebra striping*), desglose completo de columnas y un **Glosario Técnico** final. El fichero se nombra dinámicamente con una marca de tiempo (`YYYYMMDD_HHMMSS`) para evitar sobrescrituras.

---

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

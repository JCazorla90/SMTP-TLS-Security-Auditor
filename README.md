# 🛡️ SMTP / TLS & Web Security Auditor

Una herramienta automatizada de nivel empresarial en Python para auditoría de ciberseguridad perimetral, reputación de dominios y postura criptográfica. Este script evalúa servidores SMTP, registros DNS anti-spoofing, seguridad web (HTTPS, HSTS, CSP), salud de certificados SSL/TLS, cruce con **listas negras globales (DNSBL)** y opcionalmente **Shodan API**, generando un informe ejecutivo unificado y dual en formatos **PDF y HTML** con gráficos corporativos integrados.

## 🚀 Características Principales

*   **Inteligencia de Amenazas y Reputación (DNSBL & Shodan):** 
    *   Verifica automáticamente si las direcciones IP de los servidores de correo (MX) se encuentran en listas negras globales de spam/malware (ej. *Spamhaus*).
    *   Soporte opcional para consulta en tiempo real de puertos abiertos y vulnerabilidades mediante la API de Shodan.
    *   Gestión de políticas locales mediante archivos de texto `whitelist.txt` y `blacklist.txt`.
*   **Inspección SMTP y Cifrado:** Conexión a registros MX por el puerto 25 mediante `STARTTLS`, extrayendo el protocolo negociado (TLS v1.2, TLS v1.3), la *Cipher Suite* y la longitud de bits de cifrado.
*   **Protecciones Avanzadas de Correo (DNS):**
    *   **SPF** (*Sender Policy Framework*): Validación de servidores IP autorizados.
    *   **DKIM** (*DomainKeys Identified Mail*): Verificación de infraestructura de firma criptográfica en `_domainkey`.
    *   **DMARC** (*Domain-based Message Authentication, Reporting, and Conformance*): Comprobación de políticas y alineación en `_dmarc`.
    *   **MTA-STS** (*Mail Transfer Agent Strict Transport Security*): Verificación del cifrado estricto en tránsito.
    *   **TLS-RPT** (*TLS Reporting*): Validación de reportes de errores TLS.
*   **Seguridad Web y Cabeceras Defensivas:**
    *   **HTTPS & HSTS**: Comprobación de conectividad segura y forzado de transporte.
    *   **CSP** (*Content Security Policy*): Mitigación y aislamiento frente a inyecciones de código (XSS).
*   **Salud de Certificados SSL/TLS:** Análisis de validez, cálculo matemático de **días restantes de expiración** y detección de certificados autofirmados.
*   **Reporte Dual (PDF & HTML) y Dashboard Visual:** Utiliza `matplotlib` para generar un panel gráfico analítico, `fpdf2` para compilar un documento ejecutivo apaisado (*Landscape*) y HTML estructurado con codificación base64, incluyendo glosario técnico corporativo.
*   **Control de Versiones y Marcas de Tiempo:** Cada ejecución genera ficheros únicos con timestamp (`YYYYMMDD_HHMMSS`) para evitar sobrescrituras accidentales.

---

## 🔍 ¿Qué hace el script por debajo para comprobar todo?

Para realizar la auditoría de forma completamente automatizada, el motor interno ejecuta los siguientes procedimientos técnicos:

1. **Resolución DNS y Listas de Confianza (`dnspython`):**
   - Consulta registros **MX** y traduce la IP del servidor de correo principal.
   - Lee y procesa las políticas locales configuradas en `whitelist.txt` y `blacklist.txt` para ajustar ponderaciones de riesgo.
   - Realiza consultas inversas contra bases de datos **DNSBL** (ej. `zen.spamhaus.org`) para verificar si la IP perimetral figura en listados de reputación negativa.

2. **Consulta Opcional de Superficie de Ataque (`Shodan API`):**
   - Si se configura la clave de entorno `SHODAN_API_KEY`, consulta la plataforma para identificar servicios expuestos y CVEs asociados a los activos auditados.

3. **Auditoría de Protocolos y Cifrado SMTP (`smtplib` & `ssl`):**
   - Establece una conexión socket hacia el puerto **25** del servidor MX.
   - Ejecuta comandos de salutación (`EHLO`) y asegura el canal mediante **STARTTLS**.
   - Extrae la suite criptográfica exacta (*Cipher Suite*), el protocolo y la fuerza del cifrado en bits desde el socket activo.

4. **Inspección de Certificados y Conectividad Web (`socket`, `ssl` & `http.client`):**
   - Abre un canal TCP cifrado por el puerto **443**, extrayendo el certificado X.509 para calcular los días hasta su expiración (`notAfter`) y detectar si es autofirmado.
   - Realiza peticiones HTTP/HTTPS para auditar la presencia de cabeceras de seguridad críticas como **HSTS** y **CSP**.

5. **Puntuación Global (Security Score) y Exportación Dual:**
   - Calcula una nota ponderada de **0 a 100** aplicando penalizaciones por reputación o bonificaciones por listas blancas.
   - Renderiza un dashboard gráfico en memoria con `matplotlib`.
   - Compila simultáneamente un informe ejecutivo en **PDF** (vía `fpdf2`) y un informe interactivo en **HTML**, añadiendo un desglose completo y un glosario técnico formal.

---

## 📋 Requisitos Previos

La herramienta requiere Python 3.7 o superior. Instala las dependencias necesarias ejecutando:

```bash
pip install dnspython pandas matplotlib fpdf2 requests
```

## ⚙️ Usage

1. Clona o sitúate en el directorio del proyecto:
   ```bash
   git clone <your-repository-url>
   cd <your-repository-directory>
   ```

2. Crea un archivo de texto plano llamado dominios.txt en la misma carpeta e introduce los dominios a auditar (uno por línea):
   ```
   bmw.com
   marca.com
   hobbyconsolas.com
   eltiempo.com
   ```
(Opcional) Crea archivos whitelist.txt y blacklist.txt para aplicar tus propias reglas de confianza o exclusión.

3. Ejecuta el script de auditoría:
   ```bash
   python generador_reporte_tls.py
   ```

4. **View the Results:** Al finalizar la ejecución silenciosa en consola, se mostrarán las rutas absolutas de los ficheros generados listos para su revisión:
5. ```
   informe listo puedes verlo en C:\...\reporte_seguridad_20260921_153000.pdf y C:\...\reporte_seguridad_20260921_153000.html



## 📄 License

Copyright (c) 2026 José Cazorla Gijón

This software is provided "as is", without warranty of any kind. If you use, modify, or distribute any part of this code, you must include a clear attribution explicitly naming José Cazorla Gijón as the original author.

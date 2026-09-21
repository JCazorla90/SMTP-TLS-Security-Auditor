# 🛡️ SMTP / TLS Security Auditor

A Python-based, automated security auditing tool for email domains. This script evaluates the cryptographic posture of SMTP servers and their anti-spoofing DNS configurations, generating a self-contained, visual HTML dashboard similar to commercial solutions like BitSight.

## 🚀 Features

*   **SMTP Handshake Inspection:** Connects to MX records via port 25 and initiates a `STARTTLS` handshake to determine the negotiated protocol (TLS v1.2, TLS v1.3), cipher suite, and key length.
*   **DNS Security Validation:** Queries and validates the presence of anti-spoofing policies (`SPF` and `DMARC`) via TXT records.
*   **Corporate Standard Compliance:** Built to audit against strict enterprise architecture standards:
    *   Enforces **TLS v1.2** or **TLS v1.3**.
    *   Validates cryptographic strength (e.g., **AES-256 bits**).
    *   Ensures asymmetric key lengths are **>= 2048 bits**.
*   **Self-Contained HTML Reporting:** Generates an automated dashboard (`reporte_seguridad_smtp.html`) with embedded base64 charts (matplotlib) and compliance scores.

## 📋 Prerequisites

The tool requires Python 3.7+ and the following libraries. You can install them using `pip`:

```bash
pip install dnspython pandas matplotlib jinja2
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

4. **View the Results:** Open the generated `reporte_seguridad_smtp.html` file in any modern web browser to view the security score distribution and detailed compliance table.



## 📄 License

Copyright (c) 2026 José Cazorla Gijón

This software is provided "as is", without warranty of any kind. If you use, modify, or distribute any part of this code, you must include a clear attribution explicitly naming José Cazorla Gijón as the original author.

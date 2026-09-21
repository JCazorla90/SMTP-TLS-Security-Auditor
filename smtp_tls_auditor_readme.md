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

2. Edit the `DOMAINS` list in `generador_reporte_tls.py` to include the domains you want to audit:
   ```python
   DOMAINS = [
       "chase.com", "jpmorgan.com", "repsol.com", "bear.com"
   ]
   ```

3. Run the script:
   ```bash
   python generador_reporte_tls.py
   ```

4. **View the Results:** Open the generated `reporte_seguridad_smtp.html` file in any modern web browser to view the security score distribution and detailed compliance table.

## 🏗️ Architecture & Security Guidelines (Compliance)

If you plan to extend this tool to integrate with third-party APIs (e.g., SecurityTrails, VirusTotal, BitSight), please adhere to the following architectural guidelines:

*   **Secret Management:** ⛔ **NEVER** hardcode API keys, passwords, or credentials in the source code. All secrets must be dynamically retrieved at runtime using a secure vault solution such as **Azure Key Vault**.
*   **Version Control:** All code and configuration files must be strictly versioned using Git in **Azure DevOps Repos**.
*   **Cryptographic Standards:** Ensure any future network requests made by this tool strictly use TLS 1.2+ with robust cipher suites.

## 📄 License

[Specify your license here, e.g., MIT, GPL, or Internal Corporate Use Only]
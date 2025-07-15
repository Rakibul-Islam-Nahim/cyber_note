# 1. Injection Attacks 💉

## 1.1 SQL Injection(SQLi) :

Inject malicious SQL queries to access, modify, or delete database data.

## 1.2 Command Injection :

Execute arbitrary system-level commands on the server.

## 1.3 LDAP Injection :

Manipulate LDAP queries to bypass authentication or access data.

## 1.4 XML External Entity (XXE) :

Exploit XML parsers to disclose internal files or SSRF attacks.

---

---

---

# 2. Authentication and Authorization Issues 🔐

## 2.1 Broken Authentication :

Exploit weak login mechanisms to gain unauthorized access (e.g., password brute-force, logic flaws).

## 2.2 Broken Access Control :

Access resources or actions without proper permissions (e.g., IDOR, privilege escalation).

## 2.3 Account Takeover (ATO) :

Gain control over another user’s account using insecure flows or token manipulation.

---

---

---

# 3. Cross-Site Scripting (XSS) 🛠️

## 3.1 Reflected XSS :

Payload is reflected and executed immediately via URL or form.

## 3.2 Stored XSS :

Malicious script is saved on the server and triggered for every user.

## 3.3 DOM-Based XSS :

Client-side JS processes untrusted input and executes it dynamically.

---

---

---

# 4. Information Disclosure 📚

## 4.1 Sensitive Data Exposure :

Access to PII, passwords, tokens, or internal system info due to poor handling.

## 4.2 Server Error Messages :

Server leaks technology stacks, database errors, or internal paths in error responses.

## 4.3 Source Code Disclosure :

Accidental leaks of .git, backup files, or source files on the server.

---

---

---

# 5. File Upload Vulnerabilities 📤

## 5.1 Unrestricted File Upload :

Upload dangerous files (e.g., web shells) due to poor validation

## 5.2 Content-Type Bypass :

Upload files by spoofing MIME types or extensions (e.g., image.php.jpg).

---

---

---

# 6. Security Misconfigurations 👨‍🔧

## 6.1 Default Credentials :

Web apps still use default admin/admin or known vendor credentials.

## 6.2 Directory Listing Enabled :

Exposes directory contents that may contain sensitive or unused files.

## 6.3 Open Admin Panels :

Admin interfaces accessible without authentication or rate limiting.

---

---

---

# 7. Vulnerable Components 📦

## 7.1 Outdated Libraries/Plugins :

Known vulnerabilities in old versions of software, CMS plugins, JS libraries.

## 7.2 CVE Exploitation :

Use public exploits against unpatched components.

---

---

---

# 8. Business Logic Vulnerabilities 📈

## 8.1 Logic Flaws :

Break application flow to bypass steps (e.g., checkout without payment).

## 8.2 Price Manipulation :

Change item prices client-side before purchase.

## 8.3 Coupon Abuse :

Reuse or stack discount codes due to poor validation.

---

---

---

# 9. Cross-Site Request Forgery (CSRF) 🌐

## 9.1 CSRF on Critical Actions :

Trick users into performing actions without consent by abusing session cookies.

---

---

---

# 10. Server-Side Request Forgery (SSRF) 🌍

## 10.1 SSRF to Internal Systems :

Force server to fetch internal URLs (e.g., metadata endpoints, localhost).

---

---

---

# 11. Token-Related Vulnerabilities 🔑

## 11.1 Insecure JWT Handling :

Weakly signed or non-expiring tokens used for authentication.

## 11.2 Token Reuse or Prediction :

Access or guess valid session or API tokens.

---

---

---

# 12. Client-Side Attacks 📡

## 12.1 Clickjacking :

Trick users into clicking hidden elements using transparent iframes.

## 12.2 CORS Misconfigurations :

Improper CORS policies allow cross-origin data leaks or access.

---

---

---

# 13. Local and Remote File Inclusion 📁

## 13.1 Local File Inclusion (LFI) :

Read local server files using directory traversal (e.g., ../../etc/passwd).

## 13.2 Remote File Inclusion (RFI) :

Load external malicious scripts into the application.

---

---

---

# 14. Rate Limiting & DoS ⏱️

## 14.1 Lack of Rate Limiting :

Brute-force login, password reset, or OTP endpoints without being blocked.

## 14.2 Resource Exhaustion :

Crash or slow down the app by sending huge payloads or excessive requests.

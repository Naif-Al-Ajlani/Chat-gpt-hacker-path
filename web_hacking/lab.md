# Lab Exercises: Web Application Hacking

These exercises are designed to give you practical experience in identifying and understanding common web application vulnerabilities.

**VERY IMPORTANT SAFETY AND ETHICS NOTE:**
*   **ONLY perform these exercises on platforms explicitly designed for legal security testing, or on applications you have developed yourself and deployed in an isolated environment.**
*   **NEVER test these techniques on websites or applications you do not have explicit, written permission to test.** Unauthorized web scanning and exploitation is illegal and unethical.
*   Recommended platforms for safe practice:
    *   **OWASP Juice Shop:** [owasp.org/www-project-juice-shop/](https://owasp.org/www-project-juice-shop/) (Can be run locally via Docker or on free tiers of some cloud providers).
    *   **Damn Vulnerable Web Application (DVWA):** [dvwa.co.uk/](http://dvwa.co.uk/) (Can be run locally).
    *   **PortSwigger Web Security Academy:** [portswigger.net/web-security](https://portswigger.net/web-security) (Online labs).

For the exercises below, assume you are using a platform like OWASP Juice Shop or DVWA.

## Lab 1: Exploring Developer Tools & Understanding Requests

**Objective:** To become familiar with browser developer tools and how web applications communicate.

**Tasks:**
1.  Open your chosen vulnerable web application (e.g., Juice Shop) in a browser (Firefox or Chrome recommended).
2.  Open your browser's Developer Tools (usually by pressing F12 or right-clicking and selecting "Inspect" or "Inspect Element").
3.  Navigate to the "Network" tab.
4.  Browse through various pages of the web application (e.g., login page, product pages, search functions).
5.  Observe the requests being made in the Network tab:
    *   What types of HTTP methods are used (GET, POST, etc.)?
    *   Select a few requests. Examine the Headers (Request Headers like `User-Agent`, `Cookie`, `Referer`; Response Headers like `Content-Type`, `Set-Cookie`).
    *   Examine the "Payload" or "Request Body" for POST requests (e.g., when you submit a login form).
    *   Examine the "Response" tab for some requests. What kind of data is returned (HTML, JSON, etc.)?
6.  *Deliverable:* Write a short paragraph describing what kind of information you can gather by observing network traffic through developer tools and why this might be useful for an ethical hacker.

## Lab 2: Basic SQL Injection (SQLi) Detection & Exploitation

**Objective:** To understand how a simple SQL injection vulnerability can be identified and exploited.

**Target:** Find a search field or a product ID in a URL on your vulnerable application that might be susceptible to SQLi. (Juice Shop has many!)

**Tasks:**
1.  **Identify Potential Injection Point:** Look for input fields or URL parameters that seem to interact with a database (e.g., `product.php?id=1`, search fields).
2.  **Basic Injection Test (Error-Based):**
    *   Try entering a single quote (`'`) into the field or at the end of the URL parameter. Does the page error out or behave differently? This can indicate SQLi.
    *   Try a basic true condition like `' OR '1'='1`. If it's a login, does this bypass it? If it's a product search, does it show all products?
3.  **(If using Juice Shop or similar that guides you) Try to solve a specific SQLi challenge on the platform.** For example:
    *   Log in as a different user using SQLi.
    *   View hidden product details.
4.  *Deliverable:* Describe the input field/parameter you tested. What input did you use? What was the application's response that indicated a potential SQLi vulnerability? (No need to extract full databases, just observe the behavior).

## Lab 3: Basic Cross-Site Scripting (XSS) Detection

**Objective:** To understand how Reflected and Stored XSS vulnerabilities can be identified.

**Target:** Find input fields like comment boxes, search fields, or profile settings on your vulnerable application.

**Tasks:**
1.  **Reflected XSS Test:**
    *   Find a search field or a URL parameter whose value is displayed on the page.
    *   Try injecting a simple HTML tag, e.g., `<b>test</b>`. Does "test" appear bold on the page?
    *   Try injecting a simple script, e.g., `<script>alert('XSS Test')</script>`. Does an alert box pop up?
2.  **Stored XSS Test:**
    *   Find a comment field, a profile description, or any field where your input is stored and displayed back to you or other users.
    *   Try injecting the same HTML and script payloads as above.
    *   Log out and log back in, or view the page as another user (if possible on the platform). Does the script still execute or the HTML render?
3.  *Deliverable:* Describe the field(s) you tested. Which payloads did you use? Did you successfully trigger an alert or render HTML? Was it Reflected or Stored XSS?

## Lab 4: Exploring for Insecure Direct Object References (IDOR)

**Objective:** To understand how IDOR vulnerabilities can allow unauthorized access to data.

**Target:** Look for URL parameters or form fields that seem to reference specific objects by an ID (e.g., `view_profile.php?user_id=100`, `download_file.php?file_id=3`).

**Tasks:**
1.  Identify a URL or request that uses an ID to fetch data.
2.  If you are logged in as user A with `user_id=100`, try changing the `user_id` to `101` (assuming another user exists). Can you view user B's profile?
3.  If there's a function to download your own invoice like `download.php?invoice_id=500`, try changing `invoice_id` to `499` or `501`. Can you access invoices that don't belong to you?
4.  *Deliverable:* Describe the IDOR scenario you tested. What parameter did you change, and what was the outcome?

**Disclaimer:** These labs are for educational purposes on designated safe platforms. Unauthorized attempts to find or exploit vulnerabilities on systems you do not have permission for are illegal and unethical.

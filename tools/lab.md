# Lab Exercises: Ethical Hacking Tools

These exercises will help you get familiar with the basic commands and functionalities of common ethical hacking tools.

**VERY IMPORTANT SAFETY AND ETHICS NOTE:**
*   **ONLY perform these exercises on systems you explicitly own and have permission to test, or on platforms explicitly designed for legal security testing.**
*   **Using these tools on networks or systems without permission is illegal and unethical.**
*   Recommended targets for practice:
    *   `scanme.nmap.org` (for Nmap)
    *   Metasploitable2 (a deliberately vulnerable VM you can run locally)
    *   OWASP Juice Shop or DVWA (for Burp Suite)
    *   Your own Wi-Fi network (for Aircrack-ng, with caution and understanding of local regulations)
    *   Example hash files you create yourself (for John the Ripper / Hashcat)

## Lab 1: Advanced Nmap Scans

**Objective:** To explore more advanced Nmap scanning techniques.
**Target:** `scanme.nmap.org`

**Tasks:**
1.  **OS Detection:**
    *   Command: `nmap -O scanme.nmap.org` (May require `sudo`)
    *   What OS does Nmap believe `scanme.nmap.org` is running?
2.  **Nmap Scripting Engine (NSE) - Default Scripts:**
    *   Command: `nmap -sC scanme.nmap.org`
    *   What additional information do the default scripts provide about the open ports and services?
3.  **Specific NSE Script - `http-title`:**
    *   Command: `nmap --script http-title -p 80 scanme.nmap.org`
    *   What is the title of the web page running on port 80?
4.  **Outputting Results to a File:**
    *   Command: `nmap -A -oN nmap_scanme_results.txt scanme.nmap.org`
    *   Verify that the scan results are saved in the file `nmap_scanme_results.txt`. Why is saving scan results useful?
5.  *Deliverable:* For each command, briefly describe its purpose and summarize the key findings.

## Lab 2: Exploring Metasploit Framework (Conceptual & Safe Target)

**Objective:** To understand the basic workflow of using Metasploit.
**Target:** Use Metasploitable2 VM for actual exploitation practice if you have it set up. Otherwise, this lab is conceptual using `msfconsole`'s search and show commands.

**Tasks:**
1.  **Launch `msfconsole`:**
    *   Command: `msfconsole`
2.  **Search for a vulnerability/module:**
    *   Imagine you want to find exploits for "vsftpd 2.3.4".
    *   Command: `search vsftpd`
    *   Note one of the exploit module paths found (e.g., `exploit/unix/ftp/vsftpd_234_backdoor`).
3.  **Select an Exploit and View Options:**
    *   Command: `use <module_path_from_above>`
    *   Command: `show options`
    *   What are the required options for this exploit (e.g., `RHOSTS`)?
4.  **View Payloads:**
    *   Command: `show payloads`
    *   List one compatible payload for this exploit.
5.  **(Conceptual/Metasploitable2 Only) Set Options and Exploit:**
    *   If you have Metasploitable2, set `RHOSTS` to its IP address and try `exploit`.
    *   **Do not run `exploit` against any other target.**
6.  *Deliverable:* Describe the steps you took in `msfconsole`. What module and payload did you look at? What options were required?

## Lab 3: Basic Web Traffic Interception with Burp Suite Community Edition

**Objective:** To learn how to intercept and view HTTP requests using Burp Suite.
**Target:** OWASP Juice Shop or DVWA (HTTP versions if possible, or understand you'll need to install Burp's CA cert for HTTPS).

**Tasks:**
1.  **Configure Browser Proxy:**
    *   Open Burp Suite. Go to the "Proxy" tab, then the "Options" sub-tab. Note the proxy listener address (default `127.0.0.1:8080`).
    *   Configure your web browser to use this as an HTTP proxy.
2.  **Enable Intercept:**
    *   In Burp Suite's "Proxy" tab, "Intercept" sub-tab, ensure "Intercept is on".
3.  **Browse Target Application:**
    *   Try to visit a page on your target vulnerable web application.
    *   Observe the request captured in Burp Suite.
4.  **View Request Details:**
    *   Examine the raw request, headers, and any parameters.
5.  **Forward or Drop the Request:**
    *   Use the "Forward" button to send the request to the server.
    *   Use the "Drop" button to prevent the request from being sent.
    *   Forward requests until the page loads in your browser.
6.  *Deliverable:* Describe the process of intercepting an HTTP request with Burp Suite. What information could you see in the intercepted request?

## Lab 4: Wi-Fi Reconnaissance with Aircrack-ng Suite (Monitor Mode)

**Objective:** To understand how to discover nearby Wi-Fi networks and view their properties.
**Target:** Your own Wi-Fi network environment. **Requires a compatible wireless adapter.**

**Tasks:**
1.  **Identify Wireless Interface:**
    *   Command: `iwconfig` or `ip link show`
2.  **Enable Monitor Mode:** (Replace `wlan0` with your interface name)
    *   Command: `sudo airmon-ng start wlan0`
    *   Note the name of the new monitor interface (e.g., `wlan0mon` or `mon0`).
3.  **Discover Networks:** (Replace `wlan0mon` with your monitor interface name)
    *   Command: `sudo airodump-ng wlan0mon`
    *   Let it run for a minute. Observe the output.
    *   What information is displayed about nearby Wi-Fi networks (BSSID, ESSID, Channel, Encryption type, etc.)?
4.  **Stop Discovery and Monitor Mode:**
    *   Press `Ctrl+C` in the `airodump-ng` terminal.
    *   Command: `sudo airmon-ng stop wlan0mon`
5.  *Deliverable:* What information about Wi-Fi networks could `airodump-ng` show you? Why is this information useful for an attacker (and a defender)?

**Disclaimer:** Always use these tools responsibly and ethically. Ensure you have permission for any network you are testing. For Aircrack-ng, only test on networks you own.

# Ethical Hacking Tools

This section introduces some of the most popular and powerful tools used by ethical hackers. Understanding how to use these tools effectively is crucial for penetration testing and vulnerability assessment.

## 1. Nmap (Network Mapper)

*   **Overview:** Nmap is an open-source tool for network discovery and security auditing. It's used to discover hosts and services on a computer network by sending packets and analyzing the responses. Nmap provides a number of features for probing computer networks, including host discovery, service and operating system detection.
*   **Installation:**
    *   **Official Website:** [nmap.org](https://nmap.org/download.html)
    *   **Linux (apt):** `sudo apt update && sudo apt install nmap`
    *   **Linux (yum):** `sudo yum install nmap`
    *   **Windows/macOS:** Download installers from the official website.
*   **Common Use Cases & Commands:**
    1.  **Ping Scan (Host Discovery):**
        *   *Command:* `nmap -sn <target_network_or_IP>` (e.g., `nmap -sn 192.168.1.0/24`)
        *   *Purpose:* Discovers live hosts on the network without port scanning them.
    2.  **Default TCP SYN Scan (Stealth Scan):**
        *   *Command:* `nmap -sS <target_IP_or_hostname>` (e.g., `nmap -sS scanme.nmap.org`)
        *   *Purpose:* Scans the most common 1000 TCP ports. Requires root/administrator privileges. If no privileges, use `nmap -sT <target>` for TCP Connect Scan.
    3.  **Service Version Detection:**
        *   *Command:* `nmap -sV <target_IP>`
        *   *Purpose:* Probes open ports to determine the service/version information (e.g., Apache 2.4.41, OpenSSH 8.2p1).
    4.  **OS Detection:**
        *   *Command:* `nmap -O <target_IP>` (Requires root/administrator privileges)
        *   *Purpose:* Attempts to determine the operating system of the target.
    5.  **Aggressive Scan (Comprehensive):**
        *   *Command:* `nmap -A <target_IP>`
        *   *Purpose:* Enables OS detection (`-O`), version detection (`-sV`), script scanning (`-sC`), and traceroute (`--traceroute`). This is a noisy scan.
    6.  **Scan Specific Ports:**
        *   *Command:* `nmap -p 80,443,21-25 <target_IP>`
        *   *Purpose:* Scans only the specified ports (e.g., 80, 443, and range 21 through 25). Use `-p-` to scan all 65535 ports.
    7.  **Scan from a List of Targets:**
        *   *Command:* `nmap -iL targets.txt`
        *   *Purpose:* Scans targets specified in the `targets.txt` file.
    8.  **Nmap Scripting Engine (NSE):**
        *   *Command:* `nmap -sC <target_IP>` (runs default scripts) or `nmap --script <script_name_or_category> <target_IP>` (e.g., `nmap --script vuln <target_IP>`)
        *   *Purpose:* Uses scripts to automate a wide range of networking tasks, including vulnerability detection.
*   **Documentation:**
    *   **Official Nmap Book:** [nmap.org/book/man.html](https://nmap.org/book/man.html)
    *   **NSE Documentation:** [nmap.org/nsedoc/](https://nmap.org/nsedoc/)

## 2. Metasploit Framework

*   **Overview:** The Metasploit Framework is a powerful open-source platform for developing, testing, and executing exploits. It's a cornerstone tool for penetration testers, containing a vast database of exploits, payloads, auxiliary modules, and encoders.
*   **Installation:**
    *   **Official Website:** [metasploit.com](https://www.metasploit.com/) (Rapid7, commercial versions available)
    *   **Open Source Installation:** [docs.rapid7.com/metasploit/installing-the-metasploit-framework/](https://docs.rapid7.com/metasploit/installing-the-metasploit-framework/) or often pre-installed in security-focused Linux distributions like Kali Linux.
    *   **Kali Linux:** `sudo apt update && sudo apt install metasploit-framework`
*   **Common Use Cases & Commands (within `msfconsole`):**
    1.  **Launch Console:** `msfconsole`
    2.  **Search for Exploits/Modules:**
        *   *Command:* `search <keyword>` (e.g., `search ms08-067`, `search vsftpd`)
        *   *Purpose:* Finds modules related to a specific vulnerability, service, or keyword.
    3.  **Use a Module:**
        *   *Command:* `use <module_name>` (e.g., `use exploit/windows/smb/ms08_067_netapi`)
        *   *Purpose:* Selects a module to configure and run.
    4.  **Show Options:**
        *   *Command:* `show options`
        *   *Purpose:* Displays the parameters required for the selected module (e.g., RHOSTS, LHOST, PAYLOAD).
    5.  **Set Options:**
        *   *Command:* `set <OPTION_NAME> <value>` (e.g., `set RHOSTS 192.168.1.101`, `set PAYLOAD windows/meterpreter/reverse_tcp`)
        *   *Purpose:* Configures the module parameters.
    6.  **Show Payloads:**
        *   *Command:* `show payloads`
        *   *Purpose:* Lists compatible payloads for the selected exploit.
    7.  **Exploit:**
        *   *Command:* `exploit` or `run`
        *   *Purpose:* Executes the configured module against the target.
    8.  **Meterpreter Session:** If successful, an exploit often yields a Meterpreter session, which is an advanced payload providing extensive control over the compromised system.
        *   *Common Meterpreter Commands:* `sysinfo`, `getuid`, `ps`, `migrate <pid>`, `upload`, `download`, `screenshot`, `shell`.
*   **Documentation:**
    *   **Metasploit Unleashed (Free Course):** [www.offensive-security.com/metasploit-unleashed/](https://www.offensive-security.com/metasploit-unleashed/)
    *   **Rapid7 Metasploit Docs:** [docs.rapid7.com/metasploit/](https://docs.rapid7.com/metasploit/)

## 3. Wireshark

*   **Overview:** Wireshark is the world's foremost and widely-used network protocol analyzer. It lets you see what's happening on your network at a microscopic level and is the de facto (and often de jure) standard across many commercial and non-profit enterprises, government agencies, and educational institutions.
*   **Installation:**
    *   **Official Website:** [wireshark.org](https://www.wireshark.org/download.html)
*   **Common Use Cases & Steps:**
    1.  **Select Interface:** Open Wireshark, choose the network interface (e.g., Ethernet, Wi-Fi adapter) to monitor.
    2.  **Start Capture:** Click the shark fin icon or "Capture > Start".
    3.  **Generate Traffic:** Perform the network activity you wish to analyze.
    4.  **Stop Capture:** Click the red square "Stop" icon.
    5.  **Apply Display Filters:**
        *   *Examples:* `ip.addr == 192.168.1.1`, `tcp.port == 80`, `http.request.method == "POST"`, `dns`
        *   *Purpose:* Narrow down the displayed packets to focus on specific traffic.
    6.  **Follow TCP/UDP/HTTP Stream:**
        *   *Action:* Right-click on a relevant packet and select "Follow > TCP Stream" (or UDP/HTTP Stream).
        *   *Purpose:* Reconstructs the conversation, showing data exchanged, which is useful for viewing HTTP requests/responses or finding credentials in plaintext protocols.
    7.  **Analyze Packet Details:** Select a packet and examine the different layers in the packet details pane (Frame, Ethernet, IP, TCP/UDP, Application Data).
*   **Documentation:**
    *   **Wireshark User's Guide:** [wireshark.org/docs/wsug_html_chunked/](https://wireshark.org/docs/wsug_html_chunked/)
    *   **Wireshark Wiki:** [wiki.wireshark.org](https://wiki.wireshark.org/)

## 4. Burp Suite

*   **Overview:** Burp Suite is an integrated platform for performing security testing of web applications. Its various tools work seamlessly together to support the entire testing process, from initial mapping and analysis of an application's attack surface, through to finding and exploiting security vulnerabilities.
*   **Editions:** Free Community Edition (limited features) and paid Professional/Enterprise editions.
*   **Installation:**
    *   **Official Website:** [portswigger.net/burp](https://portswigger.net/burp/releases)
*   **Key Modules & Common Use Cases:**
    1.  **Proxy:**
        *   *Purpose:* Acts as an intercepting proxy, allowing you to view and modify all HTTP/S traffic between your browser and the target web application.
        *   *Setup:* Configure your browser to use Burp Proxy (default: `127.0.0.1:8080`). Install Burp's CA certificate in your browser to intercept HTTPS traffic.
        *   *Usage:* Forward, drop, or modify requests/responses on the fly.
    2.  **Repeater:**
        *   *Purpose:* Manually modify and resend individual HTTP requests, and analyze the application's responses. Useful for testing input validation, parameter tampering, and fuzzing.
        *   *Usage:* Right-click a request in Proxy history and "Send to Repeater". Modify and send.
    3.  **Intruder:**
        *   *Purpose:* Automates customized attacks to find and exploit vulnerabilities. Can perform various types of fuzzing (e.g., dictionary attacks on password fields, parameter fuzzing).
        *   *Usage:* Send a request to Intruder, define payload positions (where to insert test data), select an attack type, and configure payloads (e.g., wordlists, number ranges).
    4.  **Decoder:**
        *   *Purpose:* Transforms encoded data into its canonical form, or canonical data into various encoded and hashed forms (e.g., URL encoding, Base64, Hex).
    5.  **Comparer:**
        *   *Purpose:* Performs a visual comparison (diff) between two items of data (e.g., two HTTP responses) to highlight differences.
*   **Documentation:**
    *   **PortSwigger Web Security Academy:** [portswigger.net/web-security](https://portswigger.net/web-security) (Extensive labs and learning material)
    *   **Burp Suite Documentation:** [portswigger.net/burp/documentation](https://portswigger.net/burp/documentation)

## 5. Aircrack-ng

*   **Overview:** Aircrack-ng is a complete suite of tools to assess Wi-Fi network security. It focuses on different areas of Wi-Fi security: monitoring (capturing packets), attacking (replay attacks, deauthentication, fake access points, etc.), testing (WEP and WPA PSK (WPA 1 and 2) cracking).
*   **Installation:**
    *   **Official Website:** [aircrack-ng.org](https://www.aircrack-ng.org/)
    *   **Linux (apt):** `sudo apt install aircrack-ng`
    *   *Note:* Requires a wireless card capable of packet injection and monitor mode.
*   **Common Tools & Use Cases (Simplified WPA/WPA2 PSK Cracking Example):**
    1.  **Identify Wireless Interface:** `iwconfig` or `ip link show`
    2.  **Start Monitor Mode:**
        *   *Command:* `sudo airmon-ng start <wireless_interface>` (e.g., `sudo airmon-ng start wlan0`)
        *   *This creates a monitor interface (e.g., `wlan0mon` or `mon0`).*
    3.  **Capture Handshake:**
        *   *Command:* `sudo airodump-ng -c <channel> --bssid <AP_MAC_address> -w <capture_file_prefix> <monitor_interface>`
        *   *Example:* `sudo airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w capture wlan0mon`
        *   *Purpose:* Sniffs traffic on a specific channel and BSSID, waiting for a WPA/WPA2 4-way handshake.
        *   *Optional Deauthentication (to speed up handshake capture):* `sudo aireplay-ng -0 1 -a <AP_MAC_address> -c <client_MAC_address> <monitor_interface>` (This disconnects a client, forcing it to re-authenticate and produce a handshake).
    4.  **Crack Handshake with Wordlist:**
        *   *Command:* `aircrack-ng -w <path_to_wordlist> -b <AP_MAC_address> <capture_file.cap>`
        *   *Example:* `aircrack-ng -w /usr/share/wordlists/rockyou.txt -b 00:11:22:33:44:55 capture-01.cap`
        *   *Purpose:* Attempts to crack the captured handshake using a wordlist.
*   **Documentation:**
    *   **Aircrack-ng Official Documentation:** [www.aircrack-ng.org/documentation.html](https://www.aircrack-ng.org/documentation.html)

## 6. John the Ripper (JtR)

*   **Overview:** John the Ripper is a fast password cracker, currently available for many flavors of Unix, Windows, DOS, BeOS, and OpenVMS. Its primary purpose is to detect weak Unix passwords. Besides several crypt(3) password hash types most commonly found on various Unix flavors, supported out of the box are Kerberos/AFS and Windows LM hashes, plus DES-based tripcodes, and many more with contributed patches.
*   **Installation:**
    *   **Official Website:** [openwall.com/john/](https://www.openwall.com/john/)
    *   **Linux (apt):** `sudo apt install john`
*   **Common Use Cases & Commands:**
    1.  **Basic Cracking (Auto-Detection):**
        *   *Command:* `john <password_hash_file>` (e.g., `john shadow.txt`)
        *   *Purpose:* JtR attempts to auto-detect hash types and uses default modes (wordlist, incremental, single crack).
    2.  **Specify Wordlist:**
        *   *Command:* `john --wordlist=<path_to_wordlist> <password_hash_file>` (e.g., `john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt`)
    3.  **Specify Hash Format (if auto-detection fails):**
        *   *Command:* `john --format=<hash_format> <password_hash_file>` (e.g., `john --format=raw-md5 pass.txt`)
        *   *List formats:* `john --list=formats`
    4.  **Incremental Mode (Brute-Force):**
        *   *Command:* `john --incremental=<mode_name> <password_hash_file>` (e.g., `john --incremental=Digits5 pass.txt` for 5-digit numbers)
    5.  **Show Cracked Passwords:**
        *   *Command:* `john --show <password_hash_file>`
*   **Documentation:**
    *   **John the Ripper Wiki:** [openwall.info/wiki/john](https://openwall.info/wiki/john)
    *   **John the Ripper `doc` directory in source or installation.**

## Further Resources & Alternative Tools

-   **Exploitation Frameworks:**
    *   Canvas (Commercial)
    *   Empire (PowerShell based post-exploitation)
-   **Vulnerability Scanners:**
    *   Nessus (Commercial, with free feed)
    *   OpenVAS (Open Source)
    *   Nikto (Web server scanner)
-   **Wireless Hacking:**
    *   Kismet (Wireless network detector, sniffer, and IDS)
    *   Reaver (WPS attacks)
-   **Password Cracking:**
    *   Hashcat (GPU-based, very fast)
    *   Cain & Abel (Windows, older but still sometimes used for specific tasks)
-   **Web Proxies / Scanners:**
    *   OWASP ZAP (Zed Attack Proxy - Open Source alternative to Burp Suite)
-   **Packet Crafting:**
    *   Scapy (Python library)
    *   Hping3 (Command-line)

Remember to always use these tools responsibly and ethically, with explicit permission from the target system owner.

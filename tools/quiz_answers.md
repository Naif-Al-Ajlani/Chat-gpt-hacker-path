# Answers: Quiz - Ethical Hacking Tools

Here are the answers to the quiz found in `tools/quiz.md`.

## Multiple Choice

1.  **Which Nmap command is used to perform OS detection?**
    *   **B. `nmap -O <target>`**
    *   *Explanation:* The `-O` flag enables Nmap's operating system detection capabilities.

2.  **What is the primary purpose of the Metasploit Framework?**
    *   **C. To develop, test, and execute exploits.**
    *   *Explanation:* Metasploit is a comprehensive platform for exploit development and execution, penetration testing, and vulnerability research.

3.  **In Burp Suite, which tool is primarily used to intercept, view, and modify HTTP/S requests and responses in real-time?**
    *   **D. Proxy (Intercept)**
    *   *Explanation:* Burp Proxy allows users to intercept traffic between their browser and web servers. Repeater is for replaying and modifying requests, Intruder for automated attacks, and Decoder for data transformation.

4.  **Which tool in the Aircrack-ng suite is used to capture wireless packets and discover nearby Wi-Fi networks once an interface is in monitor mode?**
    *   **C. `airodump-ng`**
    *   *Explanation:* `airodump-ng` is used for capturing 802.11 frames and collecting information about wireless networks. `airmon-ng` sets up monitor mode, `aireplay-ng` is for injecting frames, and `aircrack-ng` is for cracking WEP/WPA keys.

5.  **If you want to attempt to crack a captured WPA/WPA2 handshake using a wordlist, which Aircrack-ng tool would you primarily use?**
    *   **D. `aircrack-ng`**
    *   *Explanation:* `aircrack-ng` is the tool used to crack WEP keys and WPA/WPA2 PSK from captured handshake files.

## True/False

6.  **True or False:** Wireshark can only capture traffic on wired Ethernet networks, not Wi-Fi.
    *   **False.**
    *   *Explanation:* Wireshark can capture traffic from various network interfaces, including Wi-Fi (WLAN) adapters, provided the adapter and drivers support monitor mode or promiscuous mode for the OS.

7.  **True or False:** John the Ripper can use dictionary attacks and brute-force attacks to crack passwords.
    *   **True.**
    *   *Explanation:* John the Ripper supports various modes, including wordlist (dictionary) mode and incremental (brute-force) mode.

8.  **True or False:** The Nmap Scripting Engine (NSE) can only be used for host discovery.
    *   **False.**
    *   *Explanation:* NSE is a powerful feature of Nmap that can be used for a wide range of tasks beyond host discovery, including vulnerability detection, service enumeration, exploitation, and more.

## Short Answer

9.  **What is a "payload" in the context of Metasploit? Give an example of what a payload might do.**
    *   *Answer:* In Metasploit, a payload is the code that runs on the target system after an exploit successfully compromises it. It determines what the attacker can do on the compromised system.
    *   *Examples:* A common payload is Meterpreter, which provides an interactive shell with extensive capabilities like file system browsing, process control, taking screenshots, and migrating processes. Another example is a simple shell payload that gives the attacker a command prompt on the target.

10. **What is the main difference between Nmap's `-sS` (SYN scan) and `-sT` (Connect scan)?**
    *   *Answer:* The main difference is how they determine if a port is open.
        *   `-sS` (SYN Scan or Stealth Scan): Sends a TCP SYN packet. If a SYN/ACK is received, the port is open, and Nmap sends an RST to tear down the connection (not completing the 3-way handshake). It's stealthier and often preferred but usually requires root/administrator privileges.
        *   `-sT` (Connect Scan): Completes the full TCP three-way handshake with the target port. If the handshake completes, the port is open. It doesn't usually require special privileges but is more easily detected and logged.

11. **Why would an ethical hacker use Burp Suite's "Repeater" tool?**
    *   *Answer:* Burp Suite's Repeater tool allows an ethical hacker to manually modify and resend individual HTTP requests multiple times and analyze the responses. This is useful for testing specific parameters for vulnerabilities (like SQL injection or XSS), understanding how an application processes different inputs, verifying exploit conditions, or fine-tuning attack payloads.

12. **What is "monitor mode" for a wireless network card, and why is it necessary for tools like Aircrack-ng?**
    *   *Answer:* Monitor mode (or RFMON mode) for a wireless network card allows it to capture all 802.11 Wi-Fi traffic in its vicinity, not just traffic addressed to its own MAC address or connected network. It's necessary for tools like Aircrack-ng (specifically `airodump-ng`) because they need to capture raw wireless packets, including management frames (like beacons and probe responses) and data frames from all nearby access points and clients, to analyze Wi-Fi networks, discover clients, and capture handshakes for WPA/WPA2 cracking.

# Answers: Quiz - Networking Fundamentals

Here are the answers to the quiz found in `networking/quiz.md`.

## Multiple Choice

1.  **Which layer of the OSI model is responsible for logical addressing (IP addresses) and routing?**
    *   **C. Layer 3 (Network Layer)**
    *   *Explanation:* The Network Layer handles IP addressing, routing packets between networks, and path determination.

2.  **Which protocol provides reliable, connection-oriented data delivery?**
    *   **B. TCP (Transmission Control Protocol)**
    *   *Explanation:* TCP establishes a connection (three-way handshake) and ensures data is delivered reliably, in order, and with error checking. UDP is connectionless and unreliable.

3.  **What is the primary purpose of ARP (Address Resolution Protocol)?**
    *   **C. To resolve IP addresses into MAC addresses on a local network.**
    *   *Explanation:* ARP is used to map a known IP address to a physical MAC address for communication within the same Layer 2 network segment.

4.  **A standard Nmap `ping scan` (`nmap -sn`) is used for what primary purpose?**
    *   **C. To discover live hosts on a network.**
    *   *Explanation:* The `-sn` option in Nmap tells it to only perform host discovery (like a ping) and skip port scanning.

5.  **Which Wireshark feature allows you to see the complete, reconstructed conversation between two hosts for a specific protocol like HTTP or TCP?**
    *   **C. Follow TCP/HTTP Stream**
    *   *Explanation:* This feature reassembles the packets of a specific session into a human-readable format.

## True/False

6.  **True or False:** The Physical Layer (Layer 1) of the OSI model deals with MAC addresses and framing.
    *   **False.**
    *   *Explanation:* The Data Link Layer (Layer 2) deals with MAC addresses and framing. The Physical Layer (Layer 1) deals with the transmission of raw bits over a physical medium.

7.  **True or False:** UDP is considered a "connectionless" protocol, meaning it does not establish a session before sending data.
    *   **True.**
    *   *Explanation:* UDP sends datagrams without prior session establishment, making it faster but less reliable than TCP.

8.  **True or False:** HTTPS traffic is typically sniffed in plaintext using Wireshark without any special setup.
    *   **False.**
    *   *Explanation:* HTTPS traffic is encrypted using TLS/SSL. To view plaintext HTTPS data in Wireshark, you would need access to the private encryption keys (usually only possible if you control the server or are performing a Man-in-the-Middle attack with a trusted CA, like Burp Suite does for proxying).

## Short Answer

9.  **Briefly explain the difference between a TCP SYN scan (`nmap -sS`) and a TCP Connect scan (`nmap -sT`). Why might an ethical hacker prefer one over the other?**
    *   *Answer:* A TCP SYN scan (`-sS`) sends a SYN packet and waits for a SYN/ACK response; if received, it sends an RST packet, never completing the three-way handshake. It's stealthier as it's less likely to be logged by applications. A TCP Connect scan (`-sT`) completes the full three-way handshake. Ethical hackers often prefer SYN scans because they are less detectable and faster, though they typically require root/administrator privileges.

10. **What are the three parts of a TCP "three-way handshake"?**
    *   *Answer:*
        1.  **SYN:** The client sends a SYN (synchronize) packet to the server.
        2.  **SYN/ACK:** The server replies with a SYN/ACK (synchronize/acknowledge) packet.
        3.  **ACK:** The client sends an ACK (acknowledge) packet back to the server, establishing the connection.

11. **List two common network services and their default port numbers (e.g., HTTP - port 80).**
    *   *Answer:* Examples include:
        *   HTTP - port 80
        *   HTTPS - port 443
        *   FTP - port 21 (control), port 20 (data)
        *   SSH - port 22
        *   Telnet - port 23
        *   DNS - port 53 (UDP primarily, TCP for zone transfers)
        *   SMTP - port 25
        (Any two are acceptable with correct port numbers).

12. **What is a MAC address, and at which OSI model layer is it primarily used?**
    *   *Answer:* A MAC (Media Access Control) address is a unique physical hardware address assigned to a network interface controller (NIC) by the manufacturer. It is primarily used at Layer 2 (Data Link Layer) of the OSI model for addressing and communication within a local network segment (e.g., Ethernet, Wi-Fi).

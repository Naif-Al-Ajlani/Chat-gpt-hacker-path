# Quiz: Networking Fundamentals

Test your understanding of core networking concepts relevant to ethical hacking.

**Instructions:** Choose the best answer for multiple-choice questions. For short answer questions, provide a concise response.

## Multiple Choice

1.  **Which layer of the OSI model is responsible for logical addressing (IP addresses) and routing?**
    A. Layer 1 (Physical Layer)
    B. Layer 2 (Data Link Layer)
    C. Layer 3 (Network Layer)
    D. Layer 4 (Transport Layer)

2.  **Which protocol provides reliable, connection-oriented data delivery?**
    A. UDP (User Datagram Protocol)
    B. TCP (Transmission Control Protocol)
    C. IP (Internet Protocol)
    D. ICMP (Internet Control Message Protocol)

3.  **What is the primary purpose of ARP (Address Resolution Protocol)?**
    A. To route packets between different networks.
    B. To resolve domain names into IP addresses.
    C. To resolve IP addresses into MAC addresses on a local network.
    D. To assign IP addresses dynamically to hosts.

4.  **A standard Nmap `ping scan` (`nmap -sn`) is used for what primary purpose?**
    A. To determine the operating system of hosts.
    B. To identify open ports on live hosts.
    C. To discover live hosts on a network.
    D. To detect service versions on open ports.

5.  **Which Wireshark feature allows you to see the complete, reconstructed conversation between two hosts for a specific protocol like HTTP or TCP?**
    A. Display Filters
    B. Capture Filters
    C. Follow TCP/HTTP Stream
    D. Packet Details Pane

## True/False

6.  **True or False:** The Physical Layer (Layer 1) of the OSI model deals with MAC addresses and framing.
7.  **True or False:** UDP is considered a "connectionless" protocol, meaning it does not establish a session before sending data.
8.  **True or False:** HTTPS traffic is typically sniffed in plaintext using Wireshark without any special setup.

## Short Answer

9.  Briefly explain the difference between a TCP SYN scan (`nmap -sS`) and a TCP Connect scan (`nmap -sT`). Why might an ethical hacker prefer one over the other?
10. What are the three parts of a TCP "three-way handshake"?
11. List two common network services and their default port numbers (e.g., HTTP - port 80).
12. What is a MAC address, and at which OSI model layer is it primarily used?

---
*(Answers can be found in `quiz_answers.md`)*

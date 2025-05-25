# Lab Exercises: Networking Fundamentals

These exercises will help you get hands-on experience with basic networking tools and concepts.

**Important Safety Note:**
*   **Always perform these exercises on a network you own or have explicit permission to test on.**
*   **Using network scanning tools on networks without permission is illegal and unethical.**
*   **Consider using a virtual lab environment (e.g., two VMs on a host-only network) for safe practice.**

## Lab 1: Using `ping` and `traceroute` (or `tracert`)

**Objective:** To understand how to test basic network connectivity and map network paths.

**Tasks:**

1.  **Basic Connectivity with `ping`:**
    *   Open a terminal or command prompt.
    *   Use the `ping` command to check connectivity to a well-known website (e.g., `ping google.com` or `ping cloudflare.com`).
    *   Observe the output: Do you see replies? What is the Round Trip Time (RTT)? Are there any lost packets?
    *   Try pinging a local IP address on your network (e.g., your router's IP, or another computer if you have one and know its IP).
    *   *Deliverable:* Note down the IP address resolved for the website and the average RTT.

2.  **Path Mapping with `traceroute` (Linux/macOS) or `tracert` (Windows):**
    *   Use `traceroute <website_address>` (e.g., `traceroute google.com`) or `tracert <website_address>`.
    *   Observe the output: This shows the "hops" (routers) your packets pass through to reach the destination.
    *   What do the different columns in the output represent (hop number, IP addresses/hostnames, RTTs)?
    *   *Deliverable:* How many hops did it take to reach the destination? Can you identify the AS (Autonomous System) numbers or ISPs for some of the hops (you might need to look up IPs using a whois tool)?

## Lab 2: Basic Network Exploration with Nmap

**Objective:** To learn basic host discovery and port scanning with Nmap on a **controlled and permitted** target.

**Target for this lab:** Use `scanme.nmap.org`. This is a server explicitly provided by the Nmap developers for safe scanning practice. **Do NOT scan any other target without permission.**

**Tasks:**

1.  **Host Discovery (Ping Scan):**
    *   Command: `nmap -sn scanme.nmap.org`
    *   What does the output tell you? Is the host up?

2.  **Basic Port Scan (Default SYN Scan -
    may need `sudo` on Linux/macOS):**
    *   Command: `nmap scanme.nmap.org`
    *   What ports are listed as open? What services does Nmap think are running on those ports?

3.  **Service Version Detection:**
    *   Command: `nmap -sV scanme.nmap.org`
    *   How does the output differ from the previous scan? Does Nmap now provide more specific version information for the services?

4.  **Scan Specific Ports:**
    *   Command: `nmap -p 22,80,443 scanme.nmap.org`
    *   Did Nmap only scan these specified ports?

5.  *Deliverable:* For each Nmap command, briefly describe what the command does and summarize the key findings from the output.

## Lab 3: Packet Sniffing with Wireshark (Local Traffic)

**Objective:** To capture and analyze local network traffic to understand how data is transmitted.

**Tasks:**

1.  **Installation (if not already installed):** Download and install Wireshark from [wireshark.org](https://www.wireshark.org).
2.  **Start Capture:**
    *   Open Wireshark.
    *   Select your primary network interface (e.g., Ethernet or Wi-Fi).
    *   Click the "Start" button (shark fin icon).
3.  **Generate HTTP Traffic:**
    *   Open a web browser and visit a **non-HTTPS** website (e.g., `http://neverssl.com/` or `http://example.com/` - note: `example.com` may redirect to HTTPS, so `neverssl.com` is better for seeing plain HTTP).
    *   Browse a few pages on that site.
4.  **Stop Capture:** Go back to Wireshark and click the "Stop" button.
5.  **Filter for HTTP Traffic:**
    *   In the Wireshark display filter bar, type `http` and press Enter.
6.  **Analyze HTTP Packets:**
    *   Look for packets like `GET / HTTP/1.1` or `HTTP/1.1 200 OK`.
    *   Select a `GET` request. In the packet details pane, expand the "Hypertext Transfer Protocol" section. What information can you see (e.g., Host, User-Agent, Acceptable content types)?
    *   Select a corresponding `200 OK` response. What can you see in its HTTP section?
7.  **(Optional) Follow TCP Stream:**
    *   Right-click on an HTTP `GET` request and select "Follow > TCP Stream".
    *   What does this view show you? Can you see the raw request and response data?
8.  *Deliverable:* Describe the steps you took and what kind of information you were able to observe about HTTP traffic using Wireshark. What are the security implications of unencrypted HTTP?

**Disclaimer:** These labs are for educational purposes. Ensure you have permission before running any network scanning tools. Unauthorized scanning is illegal and unethical. Using a personal virtual lab is highly recommended.

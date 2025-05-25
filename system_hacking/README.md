# System Hacking

System hacking focuses on gaining unauthorized access to computer systems, networks, and devices. This can involve exploiting software vulnerabilities, cracking passwords, escalating privileges, and deploying malware. This section covers common techniques and concepts.

## Password Cracking

Password cracking is the process of recovering passwords from data that has been stored in or transmitted by a computer system.

**Common Techniques:**

1.  **Dictionary Attack:**
    *   *Explanation:* Uses a list of common words, phrases, or known breached passwords (a "dictionary" or "wordlist") and tries them against the password hashes.
    *   *Step-by-Step (Conceptual with John the Ripper):*
        1.  **Obtain Hashes:** Get the password hashes (e.g., from `/etc/shadow` on Linux, SAM file on Windows, or a database dump).
        2.  **Prepare Wordlist:** Choose a suitable wordlist (e.g., `rockyou.txt`).
        3.  **Run Tool:** `john --wordlist=path/to/wordlist.txt path/to/hashes.txt`
        4.  **Check Results:** John will output cracked passwords.

2.  **Brute-Force Attack:**
    *   *Explanation:* Systematically tries every possible combination of characters until the correct password is found. Can be very time-consuming.
    *   *Step-by-Step (Conceptual with Hashcat):*
        1.  **Obtain Hashes:** As above.
        2.  **Define Character Set & Length:** Specify which characters to try (e.g., lowercase, uppercase, numbers, symbols) and password length.
        3.  **Run Tool:** `hashcat -m <hash_type_id> -a 3 path/to/hashes.txt ?l?l?l?l?l?l` (example for a 6-char lowercase password; `?l` is a placeholder for lowercase).
        4.  **Check Results:** Hashcat will output cracked passwords.
    *   *Note:* Often combined with mask attacks (e.g., if you know the password starts with a capital letter and ends with a number).

3.  **Rainbow Table Attack:**
    *   *Explanation:* Uses precomputed tables of hash values for a large number of potential passwords. Faster than brute-force for unsalted hashes but requires large storage. Less effective against salted hashes.

**Tools:**

-   **John the Ripper (JtR):**
    *   *Overview:* A popular, versatile password cracker. Supports many hash types, dictionary attacks, and brute-force modes.
    *   *Common Usage:* `john myhashes.txt`, `john --wordlist=custom.lst --rules myhashes.txt`
-   **Hashcat:**
    *   *Overview:* A very fast password cracker that can utilize GPUs for significantly increased speed. Supports a vast number of hash types and attack modes.
    *   *Common Usage:* `hashcat -m <hash_mode> -a <attack_mode> hashes.txt wordlist.txt` (e.g., `-m 0` for MD5, `-a 0` for dictionary attack).

**Mitigation:**
-   Strong password policies (length, complexity, uniqueness).
-   Use strong, salted hashing algorithms (e.g., bcrypt, Argon2, scrypt, PBKDF2).
-   Multi-Factor Authentication (MFA).
-   Account lockout and rate limiting on login attempts.

## Privilege Escalation

Privilege escalation is the act of exploiting a bug, design flaw, or configuration oversight in an operating system or software application to gain elevated access to resources that are normally protected from an application or user.

**Types:**

-   **Vertical Privilege Escalation:** A lower-privilege user or application accesses functions or content reserved for higher-privilege users or applications (e.g., gaining root/administrator access).
-   **Horizontal Privilege Escalation:** A normal user accesses functions or content reserved for other normal users (e.g., accessing another user's bank account).

**Common Methods (Linux):**

1.  **Kernel Exploits:**
    *   *Explanation:* Exploiting vulnerabilities in the OS kernel itself. Often leads directly to root access.
    *   *Example:* "Dirty COW" (CVE-2016-5195).
    *   *Detection:* Check kernel version (`uname -a`) and search for known exploits.
2.  **Misconfigured SUID/SGID Executables:**
    *   *Explanation:* SUID (Set User ID) executables run with the permissions of the file owner (often root) rather than the user who executed them. If a SUID executable has a vulnerability (e.g., can be made to run arbitrary commands), it can be used to escalate privileges.
    *   *Detection:* `find / -perm -u=s -type f 2>/dev/null`
    *   *Exploitation:* If `nmap` is SUID (older versions), `nmap --interactive` then `!sh` could give a root shell.
3.  **Weak File Permissions:**
    *   *Explanation:* Writable sensitive files (e.g., `/etc/shadow`, `/etc/passwd`, configuration files for services running as root) or directories.
    *   *Detection:* Check permissions of critical files and directories.
4.  **Cron Job Exploitation:**
    *   *Explanation:* If a cron job (scheduled task) runs with root privileges and executes a script that is writable by a lower-privilege user, that user can modify the script to execute malicious commands.
    *   *Detection:* Examine `/etc/crontab` and scripts in `/etc/cron.*`.
5.  **Sudo Misconfigurations / Exploits:**
    *   *Explanation:* If a user is allowed to run specific commands as root via `sudo` without a password, or if those commands can be used to spawn a shell (e.g., `sudo find / -exec /bin/sh \;`).
    *   *Detection:* `sudo -l`
    *   *Resource:* GTFOBins ([gtfobins.github.io](https://gtfobins.github.io/)) lists Unix binaries that can be used to bypass local security restrictions.

**Common Methods (Windows):**

1.  **Missing Patches / Kernel Exploits:**
    *   *Explanation:* Similar to Linux, unpatched systems can be vulnerable to known exploits that grant SYSTEM privileges.
    *   *Detection:* Use tools like `Windows Exploit Suggester` or `Sherlock` to identify missing patches.
2.  **Unquoted Service Paths:**
    *   *Explanation:* If a service path is unquoted and contains spaces (e.g., `C:\Program Files\Some Folder\service.exe`), Windows may try to execute `C:\Program.exe`. If an attacker can place a malicious executable at that location, they can achieve privilege escalation.
    *   *Detection:* `wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\"`
3.  **Weak Service Permissions:**
    *   *Explanation:* If a user has permissions to modify a service that runs with SYSTEM privileges (e.g., change the binary path or restart it).
    *   *Detection:* Use tools like `accesschk.exe` from Sysinternals.
4.  **DLL Hijacking:**
    *   *Explanation:* An application may try to load a DLL without specifying its full path. If an attacker can place a malicious DLL with the same name in a directory that is searched before the legitimate DLL's directory, the malicious DLL will be loaded.
5.  **AlwaysInstallElevated:**
    *   *Explanation:* A group policy setting that allows non-privileged users to install MSI packages with SYSTEM privileges. If enabled, an attacker can craft a malicious MSI package.
    *   *Detection:* Check registry keys: `HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer` and `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer` for `AlwaysInstallElevated` set to `1`.

**Tools for Privilege Escalation:**
-   LinEnum.sh, LinPEAS.sh (Linux enumeration)
-   WinPEAS.exe (Windows enumeration)
-   PowerSploit (PowerShell post-exploitation framework)
-   Metasploit (contains many privilege escalation modules)

**Mitigation:**
-   Keep systems patched.
-   Apply the principle of least privilege.
-   Regularly audit SUID/SGID binaries and cron jobs.
-   Use strong file permissions.
-   Properly configure services and quote service paths.
-   Monitor for suspicious activity.

## Malware

Malware (malicious software) is any software intentionally designed to cause disruption to a computer, server, client, or computer network, leak private information, gain unauthorized access to information or systems, deprive users access to information or which unknowingly interferes with the user's computer security and privacy.

**Types of Malware:**

-   **Viruses:** Attach themselves to legitimate files or programs. Require human action (e.g., executing the infected program) to spread and replicate.
-   **Worms:** Self-replicating malware that spreads across networks without human intervention, exploiting vulnerabilities in target systems.
-   **Trojans (Trojan Horses):** Disguise themselves as legitimate software. Once executed, they can perform malicious actions like stealing data, installing backdoors, or giving attackers remote control.
-   **Ransomware:** Encrypts a victim's files or locks their system, demanding a ransom payment (often in cryptocurrency) for decryption or unlocking.
-   **Spyware:** Covertly gathers information about a user or organization and sends it to the attacker (e.g., keystrokes, browsing history, credentials).
-   **Adware:** Displays unwanted advertisements, often in pop-ups or by redirecting web browsers. While mostly annoying, some adware can also be spyware.
-   **Rootkits:** Designed to gain administrative-level control over a computer system without being detected. They can hide processes, files, and network connections.
-   **Botnets (Zombie Armies):** Networks of compromised computers (bots or zombies) controlled by an attacker (botmaster). Used for DDoS attacks, spamming, click fraud, etc.
-   **Keyloggers:** Record keystrokes entered by a user, often to steal passwords or other sensitive information.

**Delivery Mechanisms:**
-   Email attachments (phishing)
-   Malicious downloads (drive-by downloads from compromised websites)
-   Removable media (USB drives)
-   Software vulnerabilities
-   Social engineering

**Mitigation:**
-   Use reputable antivirus and anti-malware software and keep it updated.
-   Keep operating systems and applications patched.
-   Be cautious of email attachments and links from unknown sources.
-   Use firewalls.
-   Implement user awareness training.
-   Regularly back up important data.

## Buffer Overflows

*   **Explanation:** A buffer overflow occurs when a program, while writing data to a buffer, overruns the buffer's boundary and overwrites adjacent memory locations. This can corrupt data, crash the program, or, if carefully crafted, allow an attacker to execute arbitrary code.
*   **Conceptual Example (Simplified):**
    Imagine a program asks for your name and allocates 10 bytes for it:
    `char name[10];`
    `strcpy(name, user_input);`
    If the `user_input` is 20 bytes long, `strcpy` will write past the allocated 10 bytes, potentially overwriting other important data on the stack, such as the return address of the function. If an attacker can control the overwritten return address, they can redirect program execution to their own malicious code (shellcode).
*   **Impact:** Can lead to arbitrary code execution, denial of service.
*   **Mitigation:**
    *   Use memory-safe programming languages (e.g., Python, Java, Rust) where possible.
    *   For C/C++, use safer functions (e.g., `strncpy` instead of `strcpy`, but be mindful of null termination).
    *   Compiler-based protections (e.g., Stack Canaries/Cookies, ASLR, DEP/NX Bit).
    *   Static and dynamic code analysis.
    *   Input validation (especially length checks).

## Social Engineering

*   **Explanation:** The art of manipulating people into performing actions or divulging confidential information. It relies on psychological manipulation rather than technical hacking techniques.
*   **Common Tactics:**
    *   **Phishing:** Sending fraudulent emails or messages that appear to be from legitimate sources to trick users into revealing sensitive information (credentials, credit card numbers) or downloading malware.
        *   **Spear Phishing:** Targeted phishing attacks customized for a specific individual or organization.
        *   **Whaling:** Spear phishing aimed at high-profile targets like executives.
    *   **Pretexting:** Creating a fabricated scenario (pretext) to gain trust and obtain information.
    *   **Baiting:** Offering something enticing (e.g., free software, movie download) to lure victims into executing malware or divulging information.
    *   **Quid Pro Quo:** A "something for something" attack, where the attacker offers a supposed service or benefit in exchange for information or access (e.g., posing as IT support).
    *   **Tailgating/Piggybacking:** Following an authorized person into a restricted area.
    *   **Impersonation:** Pretending to be someone else (e.g., a colleague, IT support, a vendor).
*   **Mitigation:**
    *   User awareness training: Educate employees about social engineering tactics.
    *   Strong security policies and procedures (e.g., verifying identities, not sharing passwords).
    *   Technical controls (e.g., email filters for phishing, MFA).
    *   Physical security measures to prevent tailgating.

## Further Resources

-   [Hack The Box](https://www.hackthebox.com/) & [TryHackMe](https://tryhackme.com/) (Hands-on labs for system hacking)
-   [GTFOBins](https://gtfobins.github.io/) (Unix binaries for privilege escalation)
-   [LOLBAS Project (Living Off The Land Binaries and Scripts)](https://lolbas-project.github.io/) (Windows equivalent of GTFOBins)
-   [PayloadsAllTheThings - Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
-   [The Art of Exploitation by Jon Erickson (Book)](https://nostarch.com/hacking2.htm)
-   [Social Engineering: The Art of Human Hacking by Christopher Hadnagy (Book)](https://www.wiley.com/en-us/Social+Engineering%3A+The+Science+of+Human+Hacking%2C+2nd+Edition-p-9781119433385)

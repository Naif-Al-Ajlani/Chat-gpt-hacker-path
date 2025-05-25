# Answers: Quiz - System Hacking Concepts

Here are the answers to the quiz found in `system_hacking/quiz.md`.

## Multiple Choice

1.  **Which password cracking technique involves trying every possible combination of characters?**
    *   **B. Brute-Force Attack**
    *   *Explanation:* Brute-force systematically tries all character combinations. Dictionary attacks use wordlists, and rainbow tables use precomputed hashes.

2.  **Exploiting a vulnerability in an operating system kernel to gain root or administrator privileges is an example of:**
    *   **B. Vertical Privilege Escalation**
    *   *Explanation:* Vertical privilege escalation involves gaining higher privileges (e.g., user to admin). Horizontal is gaining access as another user with similar privileges.

3.  **What is the primary purpose of "salting" passwords before hashing them?**
    *   **B. To make dictionary and rainbow table attacks less effective.**
    *   *Explanation:* Salting adds unique random data to each password before hashing, meaning identical passwords hash to different values. This prevents precomputed rainbow tables from working directly and forces dictionary attacks to hash each word with each salt.

4.  **Which type of malware is specifically designed to encrypt a victim's files and demand payment for their release?**
    *   **D. Ransomware**
    *   *Explanation:* This is the defining characteristic of ransomware.

5.  **An attacker calls an employee pretending to be from the IT department and asks for their password to "fix an urgent issue." This is an example of which social engineering tactic?**
    *   **C. Pretexting**
    *   *Explanation:* Pretexting involves creating a fabricated scenario (the pretext) to gain trust and obtain information. Phishing is typically email/message-based, baiting offers something enticing, and tailgating is physical access.

## True/False

6.  **True or False:** SUID (Set User ID) misconfigurations on Linux can potentially lead to privilege escalation.
    *   **True.**
    *   *Explanation:* If a SUID binary owned by root has a vulnerability that allows command execution, those commands can be run as root.

7.  **True or False:** Buffer overflows can only cause a program to crash and cannot lead to code execution.
    *   **False.**
    *   *Explanation:* Carefully crafted buffer overflows can overwrite the instruction pointer (return address) to redirect execution to malicious shellcode.

8.  **True or False:** A "Virus" is a type of malware that can self-replicate and spread across networks without any human intervention or interaction with another file.
    *   **False.**
    *   *Explanation:* This describes a "Worm." A traditional virus requires a host file and typically needs human action (like running the infected program) to spread.

## Short Answer

9.  **Briefly describe what a "rootkit" is and why it is dangerous.**
    *   *Answer:* A rootkit is a type of malware designed to gain administrative-level control (root access) over a computer system while actively hiding its presence from users and security software. It's dangerous because it can conceal malicious activities, backdoors, and other malware, making detection and removal extremely difficult.

10. **What is the difference between a "dictionary attack" and a "brute-force attack" in password cracking?**
    *   *Answer:* A **dictionary attack** uses a predefined list of words (a dictionary or wordlist), common phrases, or previously breached passwords, hashes them, and compares them to the target hashes. A **brute-force attack** systematically tries every possible combination of characters (e.g., all 1-character combinations, then all 2-character, etc.) until the correct password is found.

11. **List two common delivery mechanisms for malware.**
    *   *Answer:* Common delivery mechanisms include:
        *   Email attachments (often in phishing campaigns).
        *   Malicious downloads from websites (drive-by downloads or tricking users).
        *   Exploiting software vulnerabilities.
        *   Removable media (e.g., infected USB drives).
        *   Social engineering (tricking users into running malicious files).
        (Any two are acceptable).

12. **What is "DLL Hijacking" in the context of Windows privilege escalation?**
    *   *Answer:* DLL Hijacking is a technique where an attacker places a malicious DLL file with the same name as a legitimately required DLL in a location where the application will load it before the legitimate one (due to search order). If the application runs with higher privileges, the malicious DLL will also be executed with those privileges, leading to privilege escalation.

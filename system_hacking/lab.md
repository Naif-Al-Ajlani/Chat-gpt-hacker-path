# Lab Exercises: System Hacking Concepts

These exercises are designed to help you understand the concepts behind system hacking. Some of these are research-based or conceptual due to the sensitive nature of directly practicing system attacks.

**EXTREMELY IMPORTANT: SAFETY, LEGAL, AND ETHICAL WARNING:**
*   **DO NOT attempt to perform unauthorized password cracking, privilege escalation, malware deployment, or buffer overflow exploits on any system you DO NOT OWN or DO NOT HAVE EXPLICIT, WRITTEN PERMISSION TO TEST.** This is illegal and unethical and can have severe consequences.
*   For any practical exercises involving tools, use a dedicated, isolated virtual lab environment that you own (e.g., VMs like Metasploitable2, or specific vulnerable-by-design VMs).
*   Focus on understanding the *mechanisms* and *defenses* rather than performing actual attacks on production or unauthorized systems.

## Lab 1: Password Strength & Hashing Research

**Objective:** To understand what makes a strong password and how hashing protects passwords.

**Tasks:**
1.  **Password Strength Research:**
    *   Research online resources (e.g., NIST password guidelines, articles from security sites) about what constitutes a strong password. Consider length, complexity (character types), uniqueness, and the use of passphrases.
    *   Use an online password strength checker (like those from Kaspersky or Security.org - just for testing example passwords, don't enter your real ones!) to test a few example passwords:
        *   A short, simple password (e.g., "password", "123456").
        *   A slightly more complex one (e.g., "Password123!").
        *   A long passphrase (e.g., "CorrectHorseBatteryStaple").
    *   Note how the estimated time to crack changes.
2.  **Password Hashing vs. Encryption:**
    *   Research the difference between password hashing and password encryption. Why is hashing preferred for storing passwords?
    *   What is "salting" in the context of password hashing? Why is it important?
3.  *Deliverable:* Write a short summary of your findings:
    *   List 3 key characteristics of a strong password.
    *   Explain why salting is important for password hashing.

## Lab 2: Recognizing Social Engineering Tactics

**Objective:** To identify different social engineering techniques in hypothetical scenarios.

**Tasks:**
For each scenario below, identify the primary social engineering tactic being used (e.g., Phishing, Pretexting, Baiting, Quid Pro Quo, Tailgating).

1.  **Scenario A:** An employee receives an email with a link to "update their HR benefits immediately," which leads to a fake login page.
2.  **Scenario B:** Someone calls an employee pretending to be from IT support, stating they need the employee's password to fix a critical system issue.
3.  **Scenario C:** An attacker leaves a USB drive labeled "Employee Salaries Q4" in the company parking lot.
4.  **Scenario D:** An individual in a delivery uniform walks into an office building holding several packages, closely following an employee who badges in, thus bypassing the need to badge in themselves.
5.  **Scenario E:** A person calls a company, pretending to be a valued client, and aggressively demands to speak to a specific manager about an "urgent problem," hoping to get internal contact details or information.

*Deliverable:* List the scenarios (A-E) and the corresponding social engineering tactic you identified for each.

## Lab 3: Conceptual Privilege Escalation Paths (Research)

**Objective:** To understand common ways privilege escalation can occur on Linux and Windows.

**Tasks:**
1.  **Linux Research:**
    *   Research "GTFOBins" (gtfobins.github.io).
    *   Pick one binary listed on GTFOBins that can be used for privilege escalation if it has SUID permissions (e.g., `find`, `nmap`, `vim`).
    *   Explain conceptually how this binary, if misconfigured with SUID, could lead to root access. (You do not need to perform this, just explain the principle).
2.  **Windows Research:**
    *   Research "Unquoted Service Paths" on Windows.
    *   Explain conceptually how an unquoted service path could allow an attacker to escalate privileges if they can write to certain directories on the system.
3.  *Deliverable:* Briefly explain the conceptual privilege escalation path for the SUID binary you researched and for the unquoted service path scenario.

## Lab 4: Malware Characteristics (Research)

**Objective:** To understand the basic characteristics and goals of different malware types.

**Tasks:**
Choose three different types of malware from the list below:
    *   Virus
    *   Worm
    *   Trojan
    *   Ransomware
    *   Spyware
    *   Rootkit

For each of your chosen three:
1.  Briefly describe its primary characteristic or how it typically infects a system.
2.  What is its common goal or payload (e.g., steal data, encrypt files, spread to other systems)?
3.  Suggest one common way a user might get infected with this type of malware.

*Deliverable:* For each of the three malware types you researched, provide the description, goal/payload, and common infection vector.

**Disclaimer:** These labs are for educational and research purposes. Do not engage in any unauthorized system access or malware distribution. Always prioritize ethical conduct and legal compliance.

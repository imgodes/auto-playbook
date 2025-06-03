---
title: Playbook for T1055 - Process Injection
id: playbook_T1055
date: 2025-06-03
---
# T1055 - Process Injection

**Platforms:** Linux, macOS, Windows  
**Created:** 2025-06-03

## Description
Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process. 

There are many different ways to inject code into a process, many of which abuse legitimate functionalities. These implementations exist for every major OS but are typically platform specific. 

More sophisticated samples may perform multiple process injections to segment modules and further evade detection, utilizing named pipes or other inter-process communication (IPC) mechanisms as a communication channel. 

[View on MITRE ATT&CK](https://attack.mitre.org/techniques/T1055)

## Details

| Category          | Details                  |
|-------------------|--------------------------|
| Related Tactics   | defense-evasion, privilege-escalation                |
| Data Sources      | Process: Process Access, Process: Process Modification, File: File Modification, Process: Process Metadata, File: File Metadata, Process: OS API Execution, Module: Module Load |
| Sub-techniques    | T1055.013, T1055.012, T1055.009, T1055.015, T1055.014, T1055.005, T1055.011, T1055.001, T1055.003, T1055.008, T1055.004, T1055.002               |

## Recommended Mitigations

### M1026 - Privileged Account Management

<details>
<summary>Privileged Account Management</summary>


**Privileged Account Management focuses on implementing policies, controls, and tools to securely manage privileged accounts (e.g., SYSTEM, root, or administrative accounts). This includes restricting access, limiting the scope of permissions, monitoring privileged account usage, and ensuring accountability through logging and auditing.This mitigation can be implemented through the following measures:**

**Account Permissions and Roles:**
- Implement RBAC and least privilege principles to allocate permissions securely.
- Use tools like Active Directory Group Policies to enforce access restrictions.

**Credential Security:**
- Deploy password vaulting tools like CyberArk, HashiCorp Vault, or KeePass for secure storage and rotation of credentials.
- Enforce password policies for complexity, uniqueness, and expiration using tools like Microsoft Group Policy Objects (GPO).

**Multi-Factor Authentication (MFA):**
- Enforce MFA for all privileged accounts using Duo Security, Okta, or Microsoft Azure AD MFA.

**Privileged Access Management (PAM):**
- Use PAM solutions like CyberArk, BeyondTrust, or Thycotic to manage, monitor, and audit privileged access.

**Auditing and Monitoring:**
- Integrate activity monitoring into your SIEM (e.g., Splunk or QRadar) to detect and alert on anomalous privileged account usage.

**Just-In-Time Access:**
- Deploy JIT solutions like Azure Privileged Identity Management (PIM) or configure ephemeral roles in AWS and GCP to grant time-limited elevated permissions.

***Tools for Implementation*:**

**Privileged Access Management (PAM):**
- CyberArk, BeyondTrust, Thycotic, HashiCorp Vault.

**Credential Management:**
- Microsoft LAPS (Local Admin Password Solution), Password Safe, HashiCorp Vault, KeePass.

**Multi-Factor Authentication:**
- Duo Security, Okta, Microsoft Azure MFA, Google Authenticator.

**Linux Privilege Management:**
- sudo configuration, SELinux, AppArmor.

**Just-In-Time Access:**
- Azure Privileged Identity Management (PIM), AWS IAM Roles with session constraints, GCP Identity-Aware Proxy.


[View mitigation on MITRE ATT&CK](https://attack.mitre.org/mitigations/M1026)
</details>

### M1040 - Behavior Prevention on Endpoint

<details>
<summary>Behavior Prevention on Endpoint</summary>


**Behavior Prevention on Endpoint refers to the use of technologies and strategies to detect and block potentially malicious activities by analyzing the behavior of processes, files, API calls, and other endpoint events. Rather than relying solely on known signatures, this approach leverages heuristics, machine learning, and real-time monitoring to identify anomalous patterns indicative of an attack. This mitigation can be implemented through the following measures:**

**Suspicious Process Behavior:**
- Implementation: Use Endpoint Detection and Response (EDR) tools to monitor and block processes exhibiting unusual behavior, such as privilege escalation attempts.
- Use Case: An attacker uses a known vulnerability to spawn a privileged process from a user-level application. The endpoint tool detects the abnormal parent-child process relationship and blocks the action.

**Unauthorized File Access:**
- Implementation: Leverage Data Loss Prevention (DLP) or endpoint tools to block processes attempting to access sensitive files without proper authorization.
- Use Case: A process tries to read or modify a sensitive file located in a restricted directory, such as /etc/shadow on Linux or the SAM registry hive on Windows. The endpoint tool identifies this anomalous behavior and prevents it.

**Abnormal API Calls:**
- Implementation: Implement runtime analysis tools to monitor API calls and block those associated with malicious activities.
- Use Case: A process dynamically injects itself into another process to hijack its execution. The endpoint detects the abnormal use of APIs like `OpenProcess` and `WriteProcessMemory` and terminates the offending process.

**Exploit Prevention:**
- Implementation: Use behavioral exploit prevention tools to detect and block exploits attempting to gain unauthorized access.
- Use Case: A buffer overflow exploit is launched against a vulnerable application. The endpoint detects the anomalous memory write operation and halts the process.


[View mitigation on MITRE ATT&CK](https://attack.mitre.org/mitigations/M1040)
</details>

## Detection
Monitoring Windows API calls indicative of the various types of code injection may generate a significant amount of data and may not be directly useful for defense unless collected under specific circumstances for known bad sequences of calls, since benign use of API functions may be common and difficult to distinguish from malicious behavior. Windows API calls such as <code>CreateRemoteThread</code>, <code>SuspendThread</code>/<code>SetThreadContext</code>/<code>ResumeThread</code>, <code>QueueUserAPC</code>/<code>NtQueueApcThread</code>, and those that can be used to modify memory within another process, such as <code>VirtualAllocEx</code>/<code>WriteProcessMemory</code>, may be used for this technique.(Citation: Elastic Process Injection July 2017) 

Monitor DLL/PE file events, specifically creation of these binary files as well as the loading of DLLs into processes. Look for DLLs that are not recognized or not normally loaded into a process. 

Monitoring for Linux specific calls such as the ptrace system call should not generate large amounts of data due to their specialized nature, and can be a very effective method to detect some of the common process injection methods.(Citation: ArtOfMemoryForensics)  (Citation: GNU Acct)  (Citation: RHEL auditd)  (Citation: Chokepoint preload rootkits) 

Monitor for named pipe creation and connection events (Event IDs 17 and 18) for possible indicators of infected processes with external modules.(Citation: Microsoft Sysmon v6 May 2017) 

Analyze process behavior to determine if a process is performing actions it usually does not, such as opening network connections, reading files, or other suspicious actions that could relate to post-compromise behavior. 

## Response Procedures
Customize these procedures for your organization:

1. **Detection**: 
   - Add your detection methods here
   
2. **Containment**:
   - Outline containment steps

3. **Eradication**:
   - Specify eradication actions

4. **Recovery**:
   - Document recovery procedures

## References

- [GNU Acct](https://www.gnu.org/software/acct/) - GNU. (2010, February 5). The GNU Accounting Utilities. Retrieved December 20, 2017.

- [Elastic Process Injection July 2017](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process) - Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.

- [RHEL auditd](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/chap-system_auditing) - Jahoda, M. et al.. (2017, March 14). redhat Security Guide - Chapter 7 - System Auditing. Retrieved December 20, 2017.

- [Microsoft Sysmon v6 May 2017](https://docs.microsoft.com/sysinternals/downloads/sysmon) - Russinovich, M. & Garnier, T. (2017, May 22). Sysmon v6.20. Retrieved December 13, 2017.

- [Chokepoint preload rootkits](http://www.chokepoint.net/2014/02/detecting-userland-preload-rootkits.html) - stderr. (2014, February 14). Detecting Userland Preload Rootkits. Retrieved December 20, 2017.

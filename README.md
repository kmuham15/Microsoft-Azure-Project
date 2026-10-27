# Azure Security Operations & Threat Hunting Lab

## Project Overview

This project documents hands-on security work completed while learning Microsoft Azure security and monitoring capabilities. The lab connects **Identity and Access Management (IAM), endpoint security, Kusto Query Language (KQL), threat hunting, and threat response** into a practical SOC analyst workflow.

The goal was to build experience investigating security telemetry, identifying anomalous activity, understanding access controls, and documenting investigation findings.

## Objectives

- Configure and understand Azure Identity and Access Management (IAM).
- Apply Azure Role-Based Access Control (RBAC) and least privilege.
- Explore endpoint security and Windows security telemetry.
- Use KQL to query and analyze security logs.
- Perform basic threat-hunting investigations.
- Develop a structured threat-response workflow.
- Document findings and security observations in a portfolio-ready format.


## 1. Identity & Access Management (IAM)

Created simulated employee accounts in Microsoft Entra ID to represent various organizational roles and responsibilities.
The accounts included:

- Chris Developer
- Jasmine HR
- Logan Security

<img width="1280" height="401" alt="Screenshot 2026-10-20 201805" src="https://github.com/user-attachments/assets/16662a5b-a36c-4fb4-9f0a-760f094e32af" />


## 2. Least-Privilege RBAC

I Assigned Azure roles based on each user's job responsibilities:

Chris Developer — Contributor
Jasmine HR — Reader
Logan Security — Security Reader

Applied the principle of least privilege by granting users only the permissions required to perform their assigned roles and responsibilities.

<img width="2158" height="729" alt="Azure Role Assignments List" src="https://github.com/user-attachments/assets/11abacbc-5a06-45f7-b031-4e43a61f0d37" />

## 3. Security Role Assignment


I Assigned the Security Operator role to Logan's account, enabling security event monitoring and management while restricting unnecessary administrative privileges.
Explore Microsoft Entra ID and Azure RBAC to understand how identities, authentication, authorization, and permissions are managed in Azure.

<img width="1280" height="458" alt="Screenshot 2026-10-20 210332" src="https://github.com/user-attachments/assets/ef4a0adc-e085-4351-8b9f-f89e0c2a1e65" />

## 4. Azure Windows Server Deployment

Deployed a Windows Server virtual machine named Windowslabserver in Microsoft Azure to serve as a test endpoint for Microsoft Defender for Endpoint onboarding, attack simulations, security monitoring, and incident investigations.

<img width="1257" height="629" alt="Screenshot 2026-10-20 210859" src="https://github.com/user-attachments/assets/1cd96e62-24a2-42ae-9ee5-d192e2b18e33" />

## 5. Microsoft Defender for Endpoint Onboarding

Verified Microsoft Defender for Endpoint functionality on the Windows Server using PowerShell to confirm that the Microsoft Defender Advanced Threat Protection service was running and the device was successfully onboarded.

Onboarding Status:

- Sense: Running
- OnboardingState: 1

  <img width="1196" height="755" alt="05-mde-onboarding" src="https://github.com/user-attachments/assets/35f6554d-c9dd-448f-add2-350a8af1f3aa" />

## 6. Shellcode Injection Result

Following the controlled attack simulation, the lab confirmed that shellcode was successfully injected into a running process.

This demonstrated suspicious process activity that Microsoft Defender for Endpoint could identify and flag for further investigation.

<img width="901" height="626" alt="09-shellcode-injection-result (1)" src="https://github.com/user-attachments/assets/4384229d-08a1-42ff-869e-42b1c9a611d3" />

## 7. Attack Technique Analysis

I analyzed the PowerShell script to better understand the techniques used during the attack simulation.

The script demonstrated several techniques, including:

- **Base64 Decoding:** Using `FromBase64String` to decode encoded data.
- **XOR Decoding:** Applying the `-bxor` operator to decode obfuscated content.
- **In-Memory Reconstruction:** Rebuilding decoded content directly in memory.
- **Code Execution:** Using `Invoke-Expression` to execute decoded commands.

This analysis strengthened my understanding of PowerShell obfuscation and execution techniques, allowing me to recognize suspicious behavior beyond simply running the simulation.

<img width="1640" height="914" alt="Windows PowerShell ISE with AttackScript Notepad" src="https://github.com/user-attachments/assets/73fb1afb-5f7f-4818-81b0-55d193876ca8" />


 ## 8. Microsoft Defender Alert Investigation 

 Microsoft Defender for Endpoint triggered a Medium-severity alert after identifying unusual process activity on the Windows Server.

I examined the alert details and process tree to trace the execution sequence and understand the suspicious behavior.

The investigation focused on:

- Alert Severity: Reviewing the detection's risk level.

- Affected Endpoint: Identifying the impacted Windows Server.

- Logged-on User: Determining the account associated with the activity.

- Process Relationships: Analyzing connections between processes.

- Suspicious Behavior: Examining potentially malicious execution patterns.

- Parent and Child Processes: Tracing the process execution chain.

- PowerShell Activity: Correlating the detected behavior with the controlled attack simulation.

 Established a Remote Desktop connection to the Windows Server and executed a controlled PowerShell attack simulation to generate suspicious endpoint activity for detection and analysis using Microsoft Defender for Endpoint.

 <img width="1387" height="869" alt="Microsoft Defender Alert Dashboard" src="https://github.com/user-attachments/assets/a088bec1-c763-43d4-afe8-5bc2e536cadd" />

## 9. Microsoft Defender Live Response

I used Microsoft Defender for Endpoint's Live Response feature to establish a remote session with the Windows Server.

This capability allows security analysts to securely access endpoints, execute investigative commands, gather system information, and perform incident response actions without requiring direct access to the device.

<img width="1396" height="822" alt="Microsoft Defender Live Response Console (1)" src="https://github.com/user-attachments/assets/28176d78-0c9c-473c-adb5-dce965f17486" />


## 10. KQL Failed Logon Analysis

Utilized Kusto Query Language (KQL) in Azure Log Analytics to analyze failed Windows authentication attempts, identify suspicious login activity, and investigate potential security threats.

The query retrieved key information, including:

- Time generated
- ffected computer
- Failed account
- Source IP address
- Source port
- Logon type
- Failure reason

Analyzed KQL query results that revealed multiple failed login attempts targeting the `azureuser` account from a single source IP address, demonstrating how KQL can detect repeated authentication failures and support investigations of potentially suspicious login activity.

<img width="1589" height="990" alt="Azure Log Analytics KQL Results Dashboard" src="https://github.com/user-attachments/assets/50716770-5609-4500-a2ef-213bda7a0054" />





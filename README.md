# Azure Security Operations & Threat Hunting Lab

## Project Overview

This project documents hands-on security work completed while learning Microsoft Azure security and monitoring capabilities. The lab connects **Identity and Access Management (IAM), endpoint security, Kusto Query Language (KQL), threat hunting, and threat response** into a practical SOC analyst workflow.

The goal was to build experience investigating security telemetry, identifying anomalous activity, understanding access controls, and documenting investigation findings.

---

## Objectives

- Configure and understand Azure Identity and Access Management (IAM).
- Apply Azure Role-Based Access Control (RBAC) and least privilege.
- Explore endpoint security and Windows security telemetry.
- Use KQL to query and analyze security logs.
- Perform basic threat-hunting investigations.
- Develop a structured threat-response workflow.
- Document findings and security observations in a portfolio-ready format.

---

# 1. Identity & Access Management (IAM)

## Objective

Explore Microsoft Entra ID and Azure RBAC to understand how identities, authentication, authorization, and permissions are managed in Azure.

## Activities

- Created and managed Azure Entra ID user accounts.
- Assigned built-in Azure roles based on job responsibilities.
- Reviewed permissions associated with assigned roles.
- Applied the **Principle of Least Privilege (PoLP)**.
- Configured and reviewed a break-glass/emergency access account.
- Troubleshot identity and permission-related issues.

## Security Approach

Role assignments were evaluated using:

**User → Job Responsibility → Required Permissions → Appropriate Role**

The goal was to provide enough access for users to perform their responsibilities without unnecessarily expanding their privileges.

## Security Relevance

Excessive permissions can increase the impact of a compromised account. RBAC and least privilege help reduce unnecessary access and limit potential exposure.

---

# 2. Kusto Query Language (KQL)

## Objective

Use KQL to search, filter, aggregate, and analyze security-related log data.

## Skills Practiced

- `where` — filter events
- `summarize` — aggregate events
- `count()` — count activity
- `order by` — sort results
- `ago()` — perform time-based searches
- Group events by IP address
- Analyze authentication activity
- Identify patterns in security telemetry

## Example Investigation Query

```kql
WindowsEvent
| where EventID == 4625
| where TimeGenerated > ago(60m)
| summarize FailureCount = count() by IpAddress, EventID
| where FailureCount > 3
| order by FailureCount desc
```

## Investigation Objective

This query searches for **Event ID 4625**, representing failed Windows logon attempts, during the previous 60 minutes.

The results can help identify IP addresses associated with multiple failed authentication attempts that may warrant additional investigation.

## SOC Relevance

KQL helps transform large volumes of raw telemetry into actionable investigation data:

**Raw Logs → Relevant Events → Patterns → Investigation**

---

# 3. Endpoint Security

## Objective

Explore endpoint security concepts using Windows systems and Azure security services.

## Activities

- Connected to and managed a Windows Server environment.
- Reviewed Windows security events.
- Investigated authentication activity.
- Configured Network Security Group (NSG) rules.
- Troubleshot Windows Admin Center access and permissions.
- Reviewed security recommendations through Microsoft Defender for Cloud.

## Endpoint Telemetry

Security investigations can use endpoint data such as:

- Login activity
- Failed authentication attempts
- Process activity
- Network connections
- Administrative activity
- Windows security events

## Security Relevance

Endpoints provide valuable evidence during security investigations. Effective endpoint security combines preventive controls with visibility into system activity.

---

# 4. Threat Hunting

## Objective

Practice proactive threat hunting by using KQL to search security telemetry for unusual or potentially suspicious behavior.

## Hunting Methodology

### 1. Establish a Baseline

Understand what normal activity looks like within the environment.

### 2. Develop a Hypothesis

Example:

> Could repeated failed authentication attempts indicate brute-force or password-spraying behavior?

### 3. Query the Data

Use KQL to search relevant logs.

### 4. Identify Anomalies

Look for:

- Repeated authentication failures
- Unusual source IP addresses
- Multiple accounts targeted by one source
- Unusual login times
- Unexpected geographic locations
- Abnormal behavior patterns

### 5. Investigate

Correlate events and gather additional evidence before determining whether the activity requires escalation.

## Example Hunting Query

```kql
SigninLogs
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    TargetedUsers = dcount(UserPrincipalName),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by IPAddress
| order by FailedAttempts desc
```

## Hunting Principle

An unusual event is not automatically malicious. The objective is to identify activity that is sufficiently anomalous to justify additional investigation.

---

# 5. Threat Response

## Objective

Develop a structured approach for responding to potentially suspicious security activity.

## Response Workflow

**Identify → Validate → Investigate → Contain → Remediate → Monitor → Document**

### Identify

Determine what triggered the investigation.

Example:

> Multiple failed authentication attempts were observed from the same source IP.

### Validate

Determine whether the activity is:

- Expected
- Benign
- Suspicious
- Potentially malicious

### Investigate

Collect supporting information:

- Source IP
- Targeted account
- Timestamp
- Number of attempts
- Authentication results
- Geographic information
- Related events

### Contain

Depending on organizational procedures and investigation findings, potential containment actions may include:

- Restricting suspicious network traffic
- Securing or disabling compromised accounts
- Revoking sessions or tokens
- Increasing monitoring
- Applying appropriate access controls

### Remediate

Address the underlying security issue and restore the environment to an appropriate secure state.

### Monitor

Continue monitoring for recurring activity or additional indicators.

### Document

Record:

- What happened
- Evidence collected
- Queries used
- Actions taken
- Investigation results
- Lessons learned

---

# Investigation Workflow

The concepts covered in this project were connected into a SOC-style workflow:

```text
IAM
 ↓
Endpoint
 ↓
Security Logs
 ↓
KQL Analysis
 ↓
Threat Hunting
 ↓
Investigation
 ↓
Threat Response
 ↓
Documentation
```

This workflow demonstrates how security analysts can move from raw telemetry toward evidence-based investigation and response.

---

# Tools & Technologies

| Category | Technologies |
|---|---|
| Cloud Platform | Microsoft Azure |
| Identity | Microsoft Entra ID |
| Access Control | Azure RBAC |
| SIEM | Microsoft Sentinel |
| Log Management | Azure Log Analytics |
| Query Language | Kusto Query Language (KQL) |
| Endpoint | Windows Server |
| Cloud Security | Microsoft Defender for Cloud |
| Monitoring | Azure Monitor |
| Network Security | Network Security Groups |
| Administration | Windows Admin Center |

---

# Skills Demonstrated

### Identity & Access Management
- Microsoft Entra ID
- Azure RBAC
- Least Privilege
- Access Control

### Security Monitoring
- Log Collection
- Security Event Analysis
- Authentication Monitoring
- Azure Monitor
- Microsoft Sentinel

### Threat Hunting
- Hypothesis Development
- KQL Querying
- Anomaly Detection
- IP Address Analysis
- Authentication Analysis
- Behavioral Analysis

### Threat Response
- Alert Validation
- Investigation
- Containment Concepts
- Remediation Concepts
- Security Documentation

---

# Lessons Learned

This project helped connect individual Azure security technologies into a broader security operations workflow.

One of the most valuable areas was learning how to use **KQL to move from raw log data toward an investigation**. Instead of reviewing events individually, I practiced filtering telemetry, identifying repeated activity, grouping events by source IP, and looking for behavioral patterns.

The project also reinforced the importance of:

- Least privilege
- Centralized logging
- Endpoint visibility
- Continuous monitoring
- Evidence-based investigation
- Clear security documentation

A key lesson from the troubleshooting process was that a technically correct query can still return no results if the workspace does not contain the expected table, columns, or telemetry. Understanding the available data is therefore an important first step in a real investigation.

---

# Future Improvements

Future iterations of this project could include:

- Creating custom Microsoft Sentinel analytics rules.
- Building Sentinel workbooks and dashboards.
- Creating automated response playbooks.
- Developing additional KQL threat-hunting queries.
- Investigating PowerShell and process-based activity.
- Integrating additional data sources.
- Documenting false positives and detection tuning.
- Creating simulated incidents and documenting complete incident-response cases.

---

## Disclaimer

This repository documents educational lab work performed in a controlled Azure environment. IP addresses, usernames, and other potentially identifying values should be sanitized before publishing screenshots or investigation results.

---

## Author

**Cybersecurity Professional**

Focus areas: Azure Security | SOC Operations | Threat Hunting | SIEM | KQL | Incident Response


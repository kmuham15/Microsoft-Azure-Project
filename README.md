Azure Security Learning & Investigation
1. Identity & Access Management (IAM)
Overview

Explored Azure Identity and Access Management using Microsoft Entra ID and Azure Role-Based Access Control (RBAC).

Hands-On Activities
Created and managed Azure Entra ID user accounts.
Assigned built-in Azure roles based on user responsibilities.
Reviewed permissions associated with different roles.
Applied the Principle of Least Privilege (PoLP).
Configured and reviewed emergency/break-glass access.
Troubleshot identity and permission-related issues.
Security Focus

The goal of IAM is to ensure that users and services receive only the access necessary to perform their responsibilities.

I applied least privilege by evaluating:

User → Job Responsibility → Required Permissions → Appropriate Role

Key Takeaway

Improper permissions can increase the impact of a compromised account. Using RBAC and least privilege helps reduce unnecessary access and limit potential security exposure.

2. Kusto Query Language (KQL)
Overview

Used Kusto Query Language (KQL) to search, filter, aggregate, and investigate security-related log data within Azure Monitor, Log Analytics, and Microsoft Sentinel.

Skills Practiced
Filtering events with where
Sorting results with order by
Aggregating events with summarize
Counting events with count()
Grouping events by IP address
Working with timestamps
Using ago() for time-based investigations
Identifying failed authentication attempts
Analyzing patterns within security logs
Example Investigation
WindowsEvent
| where EventID == 4625
| where TimeGenerated > ago(60m)
| summarize FailureCount = count() by IpAddress, EventID
| where FailureCount > 3
| order by FailureCount desc
Investigation Objective

The query searches for Event ID 4625, which represents failed Windows logon attempts, during the previous 60 minutes.

The results can help identify IP addresses generating multiple failed authentication attempts that may warrant additional investigation.

SOC Relevance

KQL allows analysts to move from:

Raw Logs → Relevant Events → Patterns → Investigation

rather than manually reviewing large volumes of log data.

3. Endpoint Security
Overview

Explored endpoint security concepts related to protecting and monitoring Windows systems within an Azure environment.

Areas Covered
Windows Server security
Endpoint visibility
Security event logging
Authentication monitoring
Administrative access
Network security controls
Windows Admin Center
Microsoft Defender for Cloud
Hands-On Activities
Connected to and managed a Windows Server environment.
Reviewed Windows security events.
Investigated authentication activity.
Configured Network Security Group rules.
Troubleshot Windows Admin Center access and permissions.
Reviewed security recommendations through Defender for Cloud.
Security Focus

Endpoints can provide valuable evidence during a security investigation.

Important endpoint data can include:

Login activity
Failed authentication
Process activity
Network connections
Administrative activity
Security events
Key Takeaway

Effective endpoint security requires both preventive controls and visibility so that suspicious activity can be detected and investigated.

4. Threat Hunting
Overview

Practiced the fundamentals of threat hunting by using KQL to search Azure logs for unusual or potentially suspicious activity.

Instead of waiting for an alert, threat hunting involves proactively searching available telemetry for indicators of abnormal behavior.

Hunting Process

1. Establish a Baseline

Understand what normal activity looks like.

↓

2. Develop a Hypothesis

Example:

Could repeated failed authentication attempts indicate brute-force or password-spraying activity?

↓

3. Query the Data

Use KQL to search relevant logs.

↓

4. Identify Anomalies

Look for:

Repeated authentication failures
Unusual IP addresses
Multiple accounts targeted by one source
Unusual login times
Unexpected geographic locations
Abnormal activity patterns

↓

5. Investigate

Correlate events and gather additional evidence.

Example Hunting Query
SigninLogs
| where ResultType != 0
| summarize
    FailedAttempts = count(),
    TargetedUsers = dcount(UserPrincipalName),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by IPAddress
| order by FailedAttempts desc
Security Focus

The purpose of this type of investigation isn't to automatically label an IP as malicious. Instead, it identifies anomalous behavior that deserves further investigation.

5. Threat Response
Overview

Explored the fundamentals of responding to potentially suspicious security activity after detection.

Response Workflow

Identify → Validate → Investigate → Contain → Remediate → Monitor → Document

1. Identify

Determine what triggered the investigation.

Example:

Multiple failed authentication attempts from the same IP address.

2. Validate

Determine whether the activity is:

Expected
Benign
Suspicious
Potentially malicious
3. Investigate

Collect additional information such as:

Source IP
Targeted account
Timestamp
Number of attempts
Authentication results
Geographic information
Related events
4. Contain

Depending on the investigation and organizational procedures, potential containment actions could include:

Restricting suspicious network traffic
Disabling or securing compromised accounts
Revoking sessions/tokens
Increasing monitoring
Applying appropriate access controls
5. Remediate

Address the underlying issue and restore the environment to a secure state.

6. Monitor

Continue monitoring for recurring activity or additional indicators of compromise.

7. Document

Record:

What happened
Evidence collected
KQL queries used
Actions taken
Investigation results
Lessons learned
Skills Demonstrated
Category	Skills
IAM	Entra ID, RBAC, Least Privilege, Access Control
KQL	Log Querying, Filtering, Aggregation, Event Analysis
Endpoint	Windows Server, Security Events, Endpoint Monitoring
Threat Hunting	Hypothesis Development, Anomaly Detection, Log Analysis
Threat Response	Investigation, Containment, Remediation, Documentation
Azure Security	Sentinel, Log Analytics, Defender for Cloud, Azure Monitor, NSGs
Overall Learning Outcome

This portion of the Azure course helped me connect identity, endpoint security, logging, threat hunting, and incident response into a practical security workflow.

Rather than treating each technology independently, I practiced using Azure security telemetry to investigate activity, identify anomalies, analyze potential threats, and document findings using a SOC analyst-style approach.

Core workflow:

IAM → Endpoint → Logs → KQL → Threat Hunting → Investigation → Response → Documentation

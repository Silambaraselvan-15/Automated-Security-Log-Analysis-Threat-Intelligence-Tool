# Automated Security Log Analysis & Threat Intelligence Tool

## Project Orientation

This project is a small Security Operations Center (SOC)-style detection and triage platform, not merely a Python log parser.

The objective is to:

- Ingest raw authentication and web-server logs.
- Convert them into structured security events.
- Identify suspicious behavior using deterministic detection rules.
- Enrich suspicious Internet Protocol (IP) addresses with external threat intelligence.
- Produce an analyst-readable security report.

## Architecture

```text
                         ┌─────────────────────┐
                         │   Apache Access Log  │
                         └──────────┬──────────┘
                                    │
                                    ▼
┌────────────────┐        ┌─────────────────────┐
│ SSH Auth Logs  │───────►│                     │
└────────────────┘        │    LOG PARSER       │
                          │ Regex + Normalizer  │
┌────────────────┐        │                     │
│ Future Sources │───────►│                     │
└────────────────┘        └──────────┬──────────┘
                                    │
                                    ▼
                          ┌─────────────────────┐
                          │ NORMALIZED EVENTS   │
                          │                     │
                          │ IP                  │
                          │ Username            │
                          │ Timestamp           │
                          │ Event Type          │
                          │ Request             │
                          └──────────┬──────────┘
                                     │
                                     ▼
                          ┌─────────────────────┐
                          │ DETECTION ENGINE    │
                          │                     │
                          │ Rule 1: Brute Force│
                          │ Rule 2: Distributed │
                          │ Rule 3: Web Attack │
                          │ Rule 4: Multi-user │
                          └──────────┬──────────┘
                                     │
                           Suspicious events
                                     │
                                     ▼
                          ┌─────────────────────┐
                          │ THREAT INTELLIGENCE │
                          │                     │
                          │ AbuseIPDB REST API  │
                          │ IP reputation       │
                          │ Abuse confidence    │
                          └──────────┬──────────┘
                                     │
                                     ▼
                          ┌─────────────────────┐
                          │ CORRELATION / RISK  │
                          │                     │
                          │ Severity            │
                          │ Evidence            │
                          │ Rule triggered      │
                          └──────────┬──────────┘
                                     │
                                     ▼
                          ┌─────────────────────┐
                          │ SECURITY REPORT     │
                          │                     │
                          │ JSON / HTML         │
                          │ Statistics          │
                          │ Alerts              │
                          └─────────────────────┘
```

## 1. Problem Being Solved

Imagine monitoring a Linux web server. During one hour, the server generates thousands of events:

- SSH login failed
- SSH login succeeded
- HTTP request
- HTTP 404
- HTTP 200
- SSH login failed
- HTTP request
- SSH login failed

Manually reviewing these events is inefficient.

Suppose the following occurs:

```text
192.168.1.50 → admin
192.168.1.50 → root
192.168.1.50 → test
192.168.1.50 → administrator
192.168.1.50 → user
```

If this happens with dozens of failures within a few minutes, an analyst should immediately ask:

> Is this brute-force authentication?

This project automates that first level of analysis.

## 2. Major Components

### Component 1: Log Collection

Initially, log collection should remain simple. The first sources are:

#### SSH

Linux authentication logs:

```text
/var/log/auth.log
```

Typical events include:

- `Failed password`
- `Accepted password`
- `Invalid user`
- `Connection closed`

#### Apache

Apache HTTP Server access logs:

```text
/var/log/apache2/access.log
```

Typical event:

```text
192.168.1.50 - - [15/Sep/2026:19:30:01 +0530] "GET / HTTP/1.1" 200 4210
```

For development, use controlled test logs instead of relying entirely on the machine's real logs.

### Component 2: Log Parsing

The parser converts raw logs into normalized security events.

Example SSH log:

```text
Sep 15 19:30:01 cyberdoc sshd[1201]: Failed password for admin from 192.168.1.50 port 54321 ssh2
```

The parser extracts:

- Timestamp
- Hostname
- Process ID
- Username
- Source IP
- Source port
- Authentication result

The normalized event should look like this:

```json
{
  "log_type": "ssh",
  "event_type": "authentication_failure",
  "timestamp": "Sep 15 19:30:01",
  "hostname": "cyberdoc",
  "username": "admin",
  "source_ip": "192.168.1.50",
  "source_port": 54321
}
```

This process is called **normalization**. It allows later components to work with a consistent event format regardless of the original log source.

### Component 3: Detection Engine

The detection engine contains the security logic. It is what makes this project more than a parser.

The initial implementation will contain four high-level rules.

#### Rule 1: SSH Brute Force

Example events:

```text
19:30:01 192.168.1.50 admin       FAILED
19:30:05 192.168.1.50 root        FAILED
19:30:09 192.168.1.50 admin       FAILED
19:30:14 192.168.1.50 test        FAILED
19:30:20 192.168.1.50 admin       FAILED
```

Detection criteria:

- **Rule ID:** `AUTH-001`
- **Condition:** At least 5 failures from the same IP within 5 minutes
- **Severity:** `HIGH`

Example alert:

```json
{
  "rule_id": "AUTH-001",
  "alert": "SSH Brute Force",
  "source_ip": "192.168.1.50",
  "attempts": 5,
  "severity": "HIGH"
}
```

#### Rule 2: Distributed Authentication Attack

Example activity:

```text
10.10.10.10 → admin
10.10.10.11 → admin
10.10.10.12 → admin
10.10.10.13 → admin
...
```

Possible interpretation:

- Distributed password spraying
- Credential stuffing
- Coordinated attack activity

Detection criteria:

- **Rule ID:** `AUTH-002`
- **Condition:** At least 10 authentication failures against one account from at least 5 source IPs within 10 minutes
- **Severity:** `HIGH`

#### Rule 3: Suspicious Apache Request

Apache logs can reveal indicators of web attacks.

Path traversal example:

```text
GET /../../../../etc/passwd
```

SQL injection example:

```text
GET /search?id=1' OR '1'='1
```

Command injection example:

```text
GET /index.php?cmd=whoami
```

The web detector can internally recognize several patterns while producing one high-level rule category:

| Rule ID | Category | Example patterns |
| --- | --- | --- |
| `WEB-001` | Suspicious web request | `../` |
| `WEB-001` | Suspicious web request | `UNION SELECT`, `' OR '`, `' AND '` |
| `WEB-001` | Suspicious web request | `;whoami`, `|whoami`, `$(whoami)` |

For a clean project and resume claim, these patterns should remain grouped under one high-level web detection rule.

#### Rule 4: Multi-Account Authentication Attack

Example activity:

```text
192.168.1.50 → admin
192.168.1.50 → root
192.168.1.50 → test
192.168.1.50 → guest
192.168.1.50 → administrator
```

Detection criteria:

- **Rule ID:** `AUTH-003`
- Same source IP
- At least 4 usernames
- Authentication failures
- Within 10 minutes

Alert description:

> Potential credential attack or username enumeration.

### Component 4: Threat Intelligence

When the detector identifies a suspicious IP, the tool can query the AbuseIPDB REST API.

```text
Our tool
   │
   │ HTTPS request
   ▼
AbuseIPDB
   │
   ▼
IP reputation
```

Potential response data includes:

- IP address
- Abuse confidence score
- Country
- Internet service provider
- Domain
- Total reports
- Last reported date

Threat intelligence enriches local detection; it should not replace local detection.

Example with a high reputation score:

```text
Local detection:
  SSH brute force
  42 failures
  HIGH severity

Threat intelligence:
  Abuse confidence score = 92

Final assessment:
  CRITICAL
```

Example with no reputation history:

```text
Local detection:
  SSH brute force
  42 failures

Threat intelligence:
  Abuse confidence score = 0

Final assessment:
  HIGH
```

### Component 5: Correlation and Risk Scoring

The project combines two sources of evidence.

#### Local Evidence

- Failed login count
- Unique usernames
- Time window
- HTTP attack pattern

#### External Evidence

- AbuseIPDB reputation
- Abuse confidence score

Example scoring model:

```text
Base severity:
  Brute force = HIGH

Threat intelligence adjustment:
  Abuse confidence > 80  = +20
  Abuse confidence 50-80 = +10
  Abuse confidence < 50  = +0

Risk Score = Detection Score + Threat Intelligence Score
```

Example:

| Evidence | Score |
| --- | ---: |
| Brute force detection | 70 |
| AbuseIPDB enrichment | 20 |
| **Final risk score** | **90** |

Risk classification:

| Score | Classification |
| ---: | --- |
| 0-29 | LOW |
| 30-59 | MEDIUM |
| 60-79 | HIGH |
| 80-100 | CRITICAL |

The scoring model should remain transparent rather than pretending to be a machine-learning model.

### Component 6: Reporting

The final product must generate reports that an analyst can read and use.

Possible outputs:

- `reports/report.json`
- `reports/report.html`

Example report:

```text
========================================
SECURITY ANALYSIS REPORT
========================================

Analysis Time:
2026-09-15 20:15:32

Logs Analyzed:
SSH:       1,250
Apache:    8,431

Total Events:
9,681

Alerts:
23

----------------------------------------
HIGH SEVERITY
----------------------------------------

Rule:
AUTH-001 SSH Brute Force

Source IP:
192.168.1.50

Failed Attempts:
27

Target Accounts:
admin, root, test

Time Window:
19:30:01 - 19:34:51

Threat Intelligence:
Abuse Confidence: 87%

Risk Score:
91
```

The HTML report can eventually become a basic SOC dashboard.

## 3. Controlled Attack Scenarios

This part is critical if the project claims:

> Implemented 4 detection rules that identified 66 of 70 controlled attack scenarios.

The project should actually construct and test those 70 scenarios.

### SSH Scenarios

- Scenario 001: 5 failed logins from one IP
- Scenario 002: 10 failed logins from one IP
- Scenario 003: 20 failed logins from one IP
- Scenario 004: 5 failed logins against `root`

### Distributed Attack Scenarios

- Scenario 020: 5 IPs targeting the same username
- Scenario 021: 10 IPs targeting the same username

### Apache Scenarios

- Scenario 040: Path traversal
- Scenario 041: SQL injection
- Scenario 042: Command injection

### Benign Traffic

The dataset must also include legitimate activity:

- Successful login
- Normal HTTP `GET`
- HTTP 404 requests
- Normal API requests
- Different users logging in normally

Without benign traffic, false-positive measurements are not meaningful.

## 4. False-Positive Analysis

A defensible resume claim might be:

> Tuned authentication thresholds through false-positive analysis, reducing test false positives from 14 to 3.

This must be demonstrated with data.

Suppose the first threshold is:

```text
At least 3 failures within 5 minutes
```

Normal user mistakes could trigger it:

```text
admin → wrong password
admin → wrong password
admin → wrong password
```

This produces too many false positives.

Test several thresholds:

| Threshold | True alerts | False alerts |
| ---: | ---: | ---: |
| 3 | 6 | 14 |
| 5 | 6 | 3 |
| 7 | 6 | 1 |
| 10 | 5 | 0 |

The project can then justify a threshold of 5 because it offers a better detection and false-positive tradeoff than the initial threshold.

## 5. Testing Methodology

The project should eventually contain:

```text
tests/
├── test_parser.py
├── test_detector.py
├── test_threat_intel.py
└── test_scenarios.py
```

The controlled datasets should contain:

```text
datasets/
├── benign/
├── attack/
└── scenarios.json
```

Each scenario can contain metadata such as:

```json
{
  "scenario_id": 1,
  "category": "ssh_bruteforce",
  "expected_detection": true,
  "source_ip": "192.168.1.50",
  "failed_attempts": 10
}
```

The test framework should determine:

- Whether the scenario was detected
- Whether an attack was missed
- Whether benign activity caused a false positive

This is how a result such as `66 / 70 detected` can be measured legitimately.

## 6. Target Repository Structure

```text
security-log-analyzer/
│
├── main.py
├── config.py
├── parser.py
│
├── detectors/
│   ├── __init__.py
│   ├── ssh_detector.py
│   └── apache_detector.py
│
├── threat_intel/
│   ├── __init__.py
│   └── abuseipdb.py
│
├── reporting/
│   ├── __init__.py
│   ├── json_report.py
│   └── html_report.py
│
├── logs/
│   ├── auth.log
│   └── access.log
│
├── datasets/
│   ├── benign/
│   ├── attack/
│   └── scenarios.json
│
├── tests/
│   ├── test_parser.py
│   ├── test_detector.py
│   ├── test_threat_intel.py
│   └── test_scenarios.py
│
├── reports/
├── requirements.txt
├── README.md
└── .gitignore
```

## 7. Interview Demonstration

This project provides several strong technical talking points.

### Python

- Regular expressions
- File processing
- Dictionaries and lists
- Modular architecture
- Exception handling
- REST API integration
- JSON processing
- Unit testing

### Cybersecurity

- SSH brute-force detection
- Password spraying
- Username enumeration
- Web attack indicators
- Log analysis
- Threat intelligence
- Security event normalization
- Detection thresholds
- False-positive analysis
- Risk scoring

### SOC Concepts

```text
Raw telemetry
      ↓
Parsing
      ↓
Normalization
      ↓
Detection
      ↓
Enrichment
      ↓
Correlation
      ↓
Risk assessment
      ↓
Reporting
```

This is a simplified security detection pipeline.

## 8. Project Scope

This project is **not**:

- A Security Information and Event Management (SIEM) platform
- A machine-learning intrusion detection system
- A replacement for Splunk
- A vulnerability scanner
- An endpoint detection and response platform
- A real-time enterprise Security Operations Center platform

It is a Python-based security log analysis, rule-based detection, and threat-intelligence enrichment tool. That description is technically defensible.

## 9. Development Order

Build the project in this sequence:

1. SSH parser
2. Apache parser
3. Unified event schema
4. Detection engine
5. Four detection rules
6. Controlled attack dataset
7. 70-scenario testing framework
8. False-positive analysis
9. AbuseIPDB REST API integration
10. Risk scoring
11. JSON reporting
12. HTML reporting
13. Unit tests
14. README and architecture diagram
15. Final performance measurements
16. Resume claims

Do not jump directly to AbuseIPDB. The intelligence API is the least important part of the core project. If the parser and detection logic are weak, an AbuseIPDB lookup only makes a weak project look more complicated.

The strongest version of this project lets you open a terminal, feed it a controlled log containing an attack, and demonstrate:

```text
Raw Log
   ↓
Parsed Event
   ↓
Detection Rule Triggered
   ↓
IP Enrichment
   ↓
Risk Score
   ↓
Security Alert
   ↓
Report
```

That is the complete target. Step 1 is the first layer: getting trustworthy structured events out of raw SSH logs.

## 10. Immediate Next Step

Begin with the SSH parser. Implement and test parsing for:

- Failed passwords
- Accepted passwords
- Invalid users
- Connection-closed events
- Source IP addresses
- Source ports
- Usernames
- Timestamps

Once those events are normalized reliably, build the Apache parser and the shared event schema.

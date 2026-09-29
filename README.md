# Automated Security Log Analysis & Detection Pipeline

A Python-based, SOC-style detection and triage platform. This tool is designed to ingest raw server logs (SSH and Apache), normalize them into a unified schema, detect malicious behavior using a stateful rules engine, enrich suspicious IPs with external threat intelligence, and generate actionable security reports.

**Disclaimer:** This is not a machine-learning IDS or a full-scale SIEM replacement. It is a deterministic, rule-based security telemetry pipeline demonstrating core Security Operations Center (SOC) engineering principles.

---

## Architecture & Data Flow

The pipeline operates in 6 distinct phases, mirroring enterprise SIEM workflows:

```text
 ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
 │   Raw Logs   │────►│    Parser    │────►│  Normalized  │
 │ (SSH/Apache) │     │ (Regex Ext.) │     │    Events    │
 └──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │
 ┌──────────────┐     ┌──────────────┐     ┌──────▼───────┐
 │ Threat Intel │◄────│   Detector   │◄────│ Stateful     │
 │ (AbuseIPDB)  │────►│  Alert Gen.  │     │ Rules Engine │
 └──────┬───────┘     └──────────────┘     └──────────────┘
        │
 ┌──────▼───────┐     ┌──────────────┐     ┌──────────────┐
 │ Risk Scorer  │────►│  Reporting   │────►│ JSON & HTML  │
 │  Correlation │     │  Generation  │     │ SOC Dashboard│
 └──────────────┘     └──────────────┘     └──────────────┘
# AbuseCVE Usage Guide

This guide provides detailed instructions on how to operate the AbuseCVE platform, from monitoring the dashboard to creating advanced vulnerability filters.

## Table of Contents
1. [Dashboard and Overview](#dashboard-and-overview)
2. [Vulnerability Database](#vulnerability-database)
3. [Policy Query Language (PQL)](#policy-query-language-pql)
4. [Managing Filter Rules](#managing-filter-rules)
5. [Alerting and Notifications](#alerting-and-notifications)
6. [System Health and Maintenance](#system-health-and-maintenance)

## Dashboard and Overview

The Dashboard is your primary operational view. It provides real-time statistics on the state of your vulnerability intelligence.

- **Total CVEs**: The total number of unique vulnerabilities currently indexed in your local database from all 4 sources.
- **Today's Alerts**: The number of notifications dispatched in the current UTC day based on your active filters.
- **Active Filters**: The count of rules currently loaded and being applied to incoming data.
- **Severity Distribution**: A visual breakdown of vulnerabilities by their CVSS severity level (Critical, High, Medium, Low).
- **Recent CVEs**: A live feed of the latest vulnerabilities discovered by the ingestion pipeline. Clicking a row expands the details, showing descriptions and references.

## Vulnerability Database

The **CVE Database** page allows you to explore the entire history of ingested vulnerabilities. You can use the standard filters for Vendor, Product, and Severity, or employ the search bar for quick ID lookups.

Each record includes:
- **CVE ID**: The unique identifier (e.g., CVE-2024-1234).
- **KEV Status**: Indicated by a red badge if the vulnerability is on the CISA Known Exploited Vulnerabilities catalog.
- **CVSS Score**: The base score and vector string providing technical context on the impact.
- **Source**: Which upstream provider (NVD, MITRE, RedHat, CISA) provided the record.

## Policy Query Language (PQL)

AbuseCVE implements a powerful Policy Query Language (PQL) for both ad-hoc searching and permanent filter rules. PQL allows you to build complex logic using simple field-value pairs.

### Basic Syntax
- `field:value` — Case-insensitive "contains" match.
- `field:=value` — Exact match.
- `field:!value` — Does not contain.
- `field:~"regex"` — Regular expression match (PCRE2 compatible).
- `field:>=N` — Numeric comparison (also supports `>`, `<`, `<=`).
- `field:val1,val2` — Match any of the comma-separated values (logical OR).
- `field:blank` — Match if the field is empty or null.

### Supported Fields and Aliases
- **id** (or `cve`, `cveid`): The CVE identifier.
- **vendor**: The software or hardware manufacturer.
- **product**: The specific software or hardware name.
- **severity** (or `sev`, `level`): CRITICAL, HIGH, MEDIUM, LOW.
- **score** (or `cvss`): The CVSS base score (0.0 - 10.0).
- **kev**: Boolean (true/false) for CISA KEV status.
- **desc** (or `description`): The vulnerability text description.

### Logical Operators
You can group conditions using parentheses and boolean operators:
- `AND` (implicit if omitted)
- `OR`
- `NOT`

**Example Query:**
`(vendor:fortinet OR vendor:paloalto) AND severity:CRITICAL,HIGH AND kev:true`

## Managing Filter Rules

Filter rules are defined in the `abusecve_filters.yaml` file at the root of the project. This file is monitored and reloaded by the system during service startup or manual scan triggers.

### Rule Structure
A rule consists of a name, an enabled status, and a query (either as a PQL string or a conditions block).

```yaml
rules:
  - id: 1
    name: "Critical Networking Gear"
    enabled: true
    pql: "vendor:cisco AND severity:CRITICAL"
  
  - id: 2
    name: "Exploited VPNs"
    enabled: true
    pql: "product:vpn AND kev:true"
```

When a new CVE is ingested, it is evaluated against every enabled rule. If a match is found, an alert is generated and the match is logged.

## Alerting and Notifications

When a vulnerability matches an active filter, the **Dispatch Pipeline** handles notification.

1. **SMTP Alerts**: An email is sent to the addresses defined in the `ALERT_RECIPIENTS` environment variable. The email contains the CVE ID, description, severity, and the name of the rule that was triggered.
2. **Alert Logs**: All sent alerts are recorded in the **Alerts** section of the UI. This provides an audit trail of what was sent, to whom, and when.
3. **Status Tracking**: The system tracks whether an email was successfully accepted by your SMTP server. Failures are logged in the **Logs** section for troubleshooting.

## System Health and Maintenance

### Manual Scans
While the system runs on an automated schedule (defined by `SCAN_INTERVAL_MINUTES`), you can manually trigger a synchronization cycle using the **Trigger Scan** button on the Dashboard. This will immediately check all 4 sources for new updates.

### Health Reports
The system automatically generates a comprehensive health report daily. This report includes:
- Component status (PostgreSQL, Redis, Worker connectivity).
- Ingestion statistics (CVEs fetched per source).
- Alerting statistics.
You can view past reports in the **Health Reports** section or trigger an immediate report generation.

### Worker Logs
The **Logs** section provides a real-time view into the background worker activity. This is essential for:
- Monitoring the progress of large database initializations.
- Debugging connection issues with upstream APIs (like NVD rate limiting).
- Verifying that scheduled tasks (Beat) are firing correctly.

# Administrative API Guide (CLI & cURL)

This guide documents advanced administrative functionality that may not be fully exposed in the web interface or is intended for programmatic access and automation via `cURL` or scripts.

## Table of Contents
1. [Database Maintenance](#database-maintenance)
2. [Advanced CVE Search](#advanced-cve-search)
3. [Filter Rules Management](#filter-rules-management)
4. [Log Management](#log-management)
5. [System Health & Reports](#system-health--reports)

---

## Database Maintenance

### Clear System Data
The `/api/dashboard/clear-data` endpoint allows you to selectively purge different categories of information from the database while preserving your core configuration and filter rules.

**cURL Example (Clear Alerts and Health Reports):**
```bash
curl -X POST http://localhost/api/dashboard/clear-data 
     -H "Content-Type: application/json" 
     -d '{
       "clear_alerts": true,
       "clear_health_reports": true,
       "clear_cves": false,
       "clear_knowledge_articles": false
     }'
```

### Manual Database Initialization (API)
Trigger the background task to fetch historical data from NVD, CISA, and RedHat.
```bash
curl -X POST http://localhost/api/dashboard/initialize-db
```

### Manual Database Initialization (Local Path)
If you have a local clone of `cvelistV5` on the server's filesystem.
```bash
curl -X POST http://localhost/api/dashboard/initialize-db-local 
     -H "Content-Type: application/json" 
     -d '{"mitre_dir": "/path/to/cvelistV5/cves"}'
```

---

## Advanced CVE Search

### PQL Search via API
Execute complex Policy Query Language (PQL) searches programmatically.

**cURL Example:**
```bash
curl -X POST http://localhost/api/cves/search/pql 
     -H "Content-Type: application/json" 
     -d '{
       "pql": "vendor:fortinet AND severity:CRITICAL,HIGH",
       "page": 1,
       "per_page": 10
     }'
```

### Structured Advanced Search
Use a JSON structure for filtering across any CVE field.
```bash
curl -X POST http://localhost/api/cves/search 
     -H "Content-Type: application/json" 
     -d '{
       "query": {
         "logic": "AND",
         "conditions": [
           {"field": "vendor", "operator": "equal", "value": "microsoft"},
           {"field": "cvss_score", "operator": "gte", "value": 9.0}
         ]
       },
       "page": 1,
       "per_page": 5
     }'
```

---

## Filter Rules Management

### Hot-Reload Rules
After manually editing the `abusecve_filters.yaml` file on the server, trigger a reload without restarting services.
```bash
curl -X POST http://localhost/api/filters/reload
```

### Test Filter Logic (Ad-hoc)
Test a PQL string against the entire local database to see what it *would* have matched, optionally sending a test alert email.
```bash
curl -X POST http://localhost/api/filters/test 
     -H "Content-Type: application/json" 
     -d '{
       "pql": "product:exchange AND severity:CRITICAL",
       "send_test_alert": true,
       "limit": 5
     }'
```

---

## Log Management

### Clear Worker Logs
Delete internal execution logs for specific worker types (e.g., `cve_scan`, `health`, `init`).
```bash
curl -X DELETE "http://localhost/api/logs/clear?worker_type=cve_scan"
```

### Get Celery/Redis Internal State
Inspect the current lengths of processing queues and the last synchronization timestamp.
```bash
curl http://localhost/api/health-reports/scheduler
```

---

## System Health & Reports

### Generate & Email Daily Health Report
Manually trigger the daily health summary to be generated and dispatched to the configured recipients immediately.
```bash
curl -X POST http://localhost/api/health-reports/send
```

### Component Status Check
Get a JSON representation of the health of PostgreSQL, Redis, and the Worker pool.
```bash
curl http://localhost/api/health-reports/status
```

# CVE Monitor

A lightweight PHP-based CVE monitoring dashboard for tracking recent vulnerabilities, CVSS information, affected products, CISA KEV entries, and early security warnings.

The application uses the official CVEProject CVE List as its primary CVE source and stores collected data in SQLite.

## Features

- Fetches CVE records from the official CVEProject CVE List V5
- Uses `delta.json` and `deltaLog.json` to detect new and updated CVEs
- Checks the CISA Known Exploited Vulnerabilities (KEV) catalog
- Stores CVE records locally in SQLite
- Extracts CVE ID, title, description, publication and update dates
- Extracts severity, CVSS score, CVSS vector, CWE, CPEs, vendors, products, and references
- Supports CVSS v4, v3.1, v3.0, and v2
- Collects early warnings from:
  - GitHub Security Advisories
  - CERT/CC
  - Openwall oss-security
- Filters early warnings using a configurable product and technology watch list
- Marks early warnings relevant to the monitored server stack
- Preserves CISA KEV records during database cleanup
- Provides a web dashboard with search and filtering
- Supports CLI updates for cron jobs
- Uses a lock file to prevent concurrent update processes
- Uses SQLite WAL mode and database maintenance for better performance

## Data Sources

### CVEProject

The primary CVE source is the official CVEProject CVE List V5 repository:

https://github.com/CVEProject/cvelistV5

The application uses:

- `delta.json`
- `deltaLog.json`
- Individual CVE JSON records

CVE records are downloaded directly from the CVEProject repository rather than from a third-party CVE database.

### CISA KEV

The CISA Known Exploited Vulnerabilities catalog is used to identify vulnerabilities known to have been exploited in the wild.

Available KEV information may include:

- Date added
- Due date
- Required action
- Known ransomware use

If a CVE exists in the KEV catalog but is not available locally, the application attempts to retrieve its official CVE record.

### Early Warning Sources

The monitor also checks additional security advisory sources for vulnerabilities that may become relevant before they are detected through the normal CVE update process.

Current sources:

- GitHub Security Advisories
- CERT/CC Vulnerability Notes
- Openwall oss-security

Early warnings are stored separately in the `early_warnings` table and matched against the configured technology watch list.

The default watch list includes technologies such as:

- Linux
- Ubuntu
- Debian
- RHEL
- cPanel
- LiteSpeed
- MariaDB
- MySQL
- Redis
- Nginx
- Apache
- PHP
- OpenSSH
- OpenSSL
- Docker
- Kubernetes
- HAProxy
- WordPress
- GitLab
- Gitea
- Jenkins
- Grafana
- Prometheus
- Elasticsearch
- KVM

## Requirements

- PHP 8.x
- cURL extension
- PDO SQLite extension
- SQLite
- Internet access
- A web server capable of running PHP

## Installation

Create the application directory:

```bash
mkdir -p /var/www/cve-monitor
cd /var/www/cve-monitor
```

Copy the application:

```bash
cp cve_monitor.php /var/www/cve-monitor/
```

Make sure PHP has write access to the application directory because the application creates the SQLite database and lock file there.

The database is created automatically on the first run:

```text
cve_monitor.sqlite
```

No separate database server is required.

## Initial Update

Run:

```bash
php /var/www/cve-monitor/cve_monitor.php --update
```

The update process will:

1. Read the current CVE delta information.
2. Find CVEs changed during the configured time window.
3. Download the corresponding official CVE records.
4. Update the local SQLite database.
5. Update CISA KEV information.
6. Check the early-warning sources.
7. Remove expired early-warning entries.
8. Remove CVE records older than the configured retention period, except KEV records.
9. Perform database maintenance.
10. Store the latest synchronization status.

The command reports discovered, successful, and failed records.

## Cron

For automatic updates, add the following to cron:

```bash
*/30 * * * * /usr/bin/php /var/www/cve-monitor/cve_monitor.php --update >> /var/www/cve-monitor/cve_monitor.log 2>&1
```

The interval can be changed according to the required update frequency.

The application creates a lock file:

```text
cve_monitor.lock
```

This prevents multiple update processes from running simultaneously.

## Web Dashboard

Open the PHP file through your web server:

```text
https://example.com/cve_monitor.php
```

The dashboard supports filtering by:

- Time period
- Published/updated date
- Severity
- Minimum CVSS score
- Vendor
- Product
- CWE
- Keyword
- CISA KEV status

The default dashboard view shows the last 7 days. Older records remain available according to the configured retention period.

## Configuration

The main configuration values are defined near the beginning of the PHP file.

### CVE Retention

```php
const RETENTION_DAYS = 90;
```

CVE records are normally retained for 90 days.

CISA KEV records are preserved during retention cleanup.

### CVE Synchronization Window

```php
const DELTA_WINDOW_HOURS = 168;
```

The application checks the CVEProject delta log for changes within the last 168 hours.

This provides additional tolerance if the scheduled update job is temporarily unavailable.

### Early Warning Retention

```php
const EARLY_WARNING_DAYS = 7;
```

Early-warning records older than this period are removed from the `early_warnings` table.

### Product Watch List

The technologies monitored by the early-warning system are defined in:

```php
const WATCH_TERMS = [
    ...
];
```

Add or remove products according to the technologies and services that need to be monitored.

## Database

The application uses SQLite and creates the required tables automatically.

Main tables:

```text
cves
settings
early_warnings
```

The `cves` table contains normalized CVE information.

The `early_warnings` table contains advisory information collected from the additional security sources.

SQLite is configured with WAL mode, a busy timeout, memory-backed temporary storage, and other settings intended for frequent update operations.

## Important Notes

The application does not use the NVD API as its primary bulk CVE discovery source.

The official CVEProject repository is used for the main CVE records.

Additional security sources are used as an early-warning layer and are stored separately from the main CVE records.

A vulnerability discovered through an early-warning source is not automatically treated as a confirmed CVE record unless the corresponding CVE information is available through the normal CVE processing workflow.

## License

Use and modify the project according to your requirements.

The project relies on external vulnerability databases and security advisory services. Their respective terms, licenses, and usage policies remain applicable to their data.

<?php
declare(strict_types=1);

/*
 * CVE Monitor from Nimafire - https://github.com/nimafire/cve_monitor
 *
 * Sources:
 *   - Official CVEProject CVE List V5
 *   - CISA Known Exploited Vulnerabilities (KEV)
 *
 * CLI:
 *   php cve_monitor.php --update
 *   php cve_monitor.php --import-cve CVE-YYYY-NNNN
 *   php cve_monitor.php --watch      CVE-YYYY-NNNN
 *   php cve_monitor.php --unwatch    CVE-YYYY-NNNN
 *   php cve_monitor.php --watch-list
 *
 * Web:
 *   Open cve_monitor.php in browser
 */

const CVE_BASE_URL =
    'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/';

const DELTA_LOG_URL =
    CVE_BASE_URL . 'deltaLog.json';

const DELTA_URL =
    CVE_BASE_URL . 'delta.json';

const KEV_URL =
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

const USER_AGENT =
    'CVE-Monitor/1.0 (personal security dashboard)';

const SYNC_WINDOW_HOURS = 168;

const DELTA_WINDOW_HOURS = SYNC_WINDOW_HOURS;

const SYNC_DELAY_US = 0;

const HTTP_CONCURRENCY = 12;

const GITHUB_API_URL =
    'https://api.github.com/repos/CVEProject/cvelistV5/releases';

const RETENTION_CRITICAL = 365;
const RETENTION_HIGH     = 180;
const RETENTION_MEDIUM   = 90;
const RETENTION_LOW      = 60;
const RETENTION_DEFAULT  = 30;


function http_get(string $url, int $timeout = 60): string
{
    $ch = curl_init($url);

    if ($ch === false) {
        throw new RuntimeException('Unable to initialize cURL');
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_CONNECTTIMEOUT => 15,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_USERAGENT => USER_AGENT,
        CURLOPT_HTTPHEADER => ['Accept: application/json'],
        CURLOPT_ENCODING => '',
    ]);

    $data = curl_exec($ch);

    if ($data === false) {
        $error = curl_error($ch);
        curl_close($ch);
        throw new RuntimeException("HTTP error: {$error}");
    }

    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($code < 200 || $code >= 300) {
        throw new RuntimeException("HTTP {$code} while fetching {$url}");
    }

    return $data;
}


function json_get(string $url): array
{
    $raw = http_get($url);
    $data = json_decode($raw, true);

    if (!is_array($data)) {
        throw new RuntimeException("Invalid JSON returned from {$url}");
    }

    return $data;
}


function h(?string $value): string
{
    return htmlspecialchars(
        $value ?? '',
        ENT_QUOTES | ENT_SUBSTITUTE,
        'UTF-8'
    );
}


function now_utc(): string
{
    return gmdate('Y-m-d H:i:s');
}


function iso_to_sql(?string $value): ?string
{
    if (!$value) {
        return null;
    }

    $ts = strtotime($value);

    if ($ts === false) {
        return null;
    }

    return gmdate('Y-m-d H:i:s', $ts);
}


function normalize_list(array $items): string
{
    $out = [];

    foreach ($items as $item) {
        if (is_string($item)) {
            $item = trim($item);

            if ($item !== '') {
                $out[] = $item;
            }
        }
    }

    $out = array_values(array_unique($out));

    return implode(', ', $out);
}


function database_file(): string
{
    $correct = __DIR__ . '/cve_monitor.sqlite';
    $legacy  = __DIR__ . 'cve_monitor.sqlite';

    if (file_exists($correct)) {
        return $correct;
    }

    if (file_exists($legacy)) {
        return $legacy;
    }

    return $correct;
}


function db(): PDO
{
    static $pdo = null;

    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $pdo = new PDO(
        'sqlite:' . database_file(),
        null,
        null,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]
    );

    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA synchronous=NORMAL');
    $pdo->exec('PRAGMA busy_timeout=10000');
    $pdo->exec('PRAGMA auto_vacuum=INCREMENTAL');
    $pdo->exec('PRAGMA temp_store=MEMORY');
    $pdo->exec('PRAGMA cache_size=-20000');

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            title TEXT,
            description TEXT,
            published TEXT,
            updated TEXT,
            assigner TEXT,
            severity TEXT,
            cvss REAL,
            cvss_version TEXT,
            vector TEXT,
            cwe TEXT,
            vendors TEXT,
            products TEXT,
            cpes TEXT,
            kev INTEGER DEFAULT 0,
            kev_date TEXT,
            kev_due_date TEXT,
            kev_required_action TEXT,
            kev_ransomware_use TEXT,
            ssvc_exploitation TEXT,
            ssvc_automatable TEXT,
            ssvc_technical_impact TEXT,
            references_json TEXT,
            synced_at TEXT
        )
    ");

    $pdo->exec("
        CREATE INDEX IF NOT EXISTS idx_cves_published
        ON cves(published)
    ");

    $pdo->exec("
        CREATE INDEX IF NOT EXISTS idx_cves_updated
        ON cves(updated)
    ");

    $pdo->exec("
        CREATE INDEX IF NOT EXISTS idx_cves_severity
        ON cves(severity)
    ");

    $pdo->exec("
        CREATE INDEX IF NOT EXISTS idx_cves_cvss
        ON cves(cvss)
    ");

    $pdo->exec("
        CREATE INDEX IF NOT EXISTS idx_cves_kev
        ON cves(kev)
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS watchlist (
            cve_id TEXT PRIMARY KEY,
            note TEXT,
            added_at TEXT
        )
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS settings (
            name TEXT PRIMARY KEY,
            value TEXT
        )
    ");

    return $pdo;
}


function get_setting(string $name): ?string
{
    $stmt = db()->prepare(
        'SELECT value FROM settings WHERE name = ?'
    );

    $stmt->execute([$name]);

    $value = $stmt->fetchColumn();

    return $value === false ? null : (string)$value;
}


function set_setting(string $name, string $value): void
{
    $stmt = db()->prepare("
        INSERT INTO settings(name, value)
        VALUES(?, ?)
        ON CONFLICT(name)
        DO UPDATE SET value = excluded.value
    ");

    $stmt->execute([$name, $value]);
}


function get_containers(array $record): array
{
    $containers = [];

    if (!empty($record['containers']['cna'])) {
        $containers[] = $record['containers']['cna'];
    }

    if (!empty($record['containers']['adp'])
        && is_array($record['containers']['adp'])) {

        foreach ($record['containers']['adp'] as $container) {
            if (is_array($container)) {
                $containers[] = $container;
            }
        }
    }

    return $containers;
}


function extract_description(array $record): string
{
    foreach (get_containers($record) as $container) {
        if (empty($container['descriptions'])) {
            continue;
        }

        foreach ($container['descriptions'] as $desc) {
            if (
                isset($desc['lang'], $desc['value'])
                && strtolower((string)$desc['lang']) === 'en'
            ) {
                return trim((string)$desc['value']);
            }
        }
    }

    return '';
}


function extract_title(array $record): string
{
    foreach (get_containers($record) as $container) {
        if (!empty($container['title'])) {
            return trim((string)$container['title']);
        }
    }

    return '';
}


function severity_from_score(?float $score): ?string
{
    if ($score === null) {
        return null;
    }

    if ($score >= 9.0) {
        return 'CRITICAL';
    }

    if ($score >= 7.0) {
        return 'HIGH';
    }

    if ($score >= 4.0) {
        return 'MEDIUM';
    }

    if ($score > 0) {
        return 'LOW';
    }

    return 'NONE';
}


function extract_cvss(array $record): array
{
    $best = [
        'score' => null,
        'severity' => null,
        'version' => null,
        'vector' => null,
    ];

    $priority = [
        'cvssV4_0' => 4.0,
        'cvssV3_1' => 3.1,
        'cvssV3_0' => 3.0,
        'cvssV2_0' => 2.0,
    ];

    $bestPriority = -1;

    foreach (get_containers($record) as $container) {
        if (empty($container['metrics'])
            || !is_array($container['metrics'])) {
            continue;
        }

        foreach ($container['metrics'] as $metric) {
            if (!is_array($metric)) {
                continue;
            }

            foreach ($priority as $key => $version) {
                if (empty($metric[$key])
                    || !is_array($metric[$key])) {
                    continue;
                }

                $cvss = $metric[$key];

                if (!isset($cvss['baseScore'])) {
                    continue;
                }

                $score = (float)$cvss['baseScore'];

                if ($version > $bestPriority) {
                    $bestPriority = $version;

                    $severity = $cvss['baseSeverity'] ?? null;

                    if (!$severity) {
                        $severity = severity_from_score($score);
                    }

                    $best = [
                        'score' => $score,
                        'severity' => strtoupper((string)$severity),
                        'version' => $key,
                        'vector' => $cvss['vectorString'] ?? null,
                    ];
                }
            }
        }
    }

    return $best;
}


function extract_cwe(array $record): string
{
    $values = [];

    foreach (get_containers($record) as $container) {
        if (empty($container['problemTypes'])) {
            continue;
        }

        foreach ($container['problemTypes'] as $problem) {
            if (empty($problem['descriptions'])) {
                continue;
            }

            foreach ($problem['descriptions'] as $desc) {
                if (!empty($desc['cweId'])) {
                    $values[] = (string)$desc['cweId'];
                }

                if (!empty($desc['description'])) {
                    $values[] = (string)$desc['description'];
                }
            }
        }
    }

    return normalize_list($values);
}


function extract_products(array $record): array
{
    $vendors = [];
    $products = [];
    $cpes = [];

    foreach (get_containers($record) as $container) {
        if (empty($container['affected'])) {
            continue;
        }

        foreach ($container['affected'] as $affected) {
            if (!is_array($affected)) {
                continue;
            }

            if (!empty($affected['vendor'])) {
                $vendors[] = (string)$affected['vendor'];
            }

            if (!empty($affected['product'])) {
                $products[] = (string)$affected['product'];
            }

            if (!empty($affected['cpes'])
                && is_array($affected['cpes'])) {
                foreach ($affected['cpes'] as $cpe) {
                    $cpes[] = (string)$cpe;
                }
            }

            if (!empty($affected['packageURL'])) {
                $products[] = (string)$affected['packageURL'];
            }
        }
    }

    return [
        'vendors' => normalize_list($vendors),
        'products' => normalize_list($products),
        'cpes' => normalize_list($cpes),
    ];
}


function extract_references(array $record): array
{
    $references = [];

    foreach (get_containers($record) as $container) {
        if (empty($container['references'])) {
            continue;
        }

        foreach ($container['references'] as $ref) {
            if (!is_array($ref)) {
                continue;
            }

            $references[] = [
                'url' => $ref['url'] ?? '',
                'name' => $ref['name'] ?? '',
                'tags' => $ref['tags'] ?? [],
            ];
        }
    }

    return $references;
}


function extract_cisa_data(array $record): array
{
    $result = [
        'kev' => 0,
        'kev_date' => null,
        'kev_due_date' => null,
        'kev_required_action' => null,
        'kev_ransomware_use' => null,
        'ssvc_exploitation' => null,
        'ssvc_automatable' => null,
        'ssvc_technical_impact' => null,
    ];

    foreach (get_containers($record) as $container) {
        $provider = $container['providerMetadata']['shortName'] ?? '';

        $json = json_encode($container, JSON_UNESCAPED_SLASHES);

        if ($json !== false) {
            if (
                stripos((string)$provider, 'CISA') !== false
                || stripos($json, 'knownExploited') !== false
                || stripos($json, '"kev"') !== false
            ) {
                $result['kev'] = 1;
            }
        }

        if (!empty($container['metrics'])
            && is_array($container['metrics'])) {

            foreach ($container['metrics'] as $metric) {
                if (!is_array($metric)) {
                    continue;
                }

                if (isset($metric['ssvc'])
                    && is_array($metric['ssvc'])) {

                    $ssvc = $metric['ssvc'];

                    if (isset($ssvc['exploitation'])) {
                        $result['ssvc_exploitation'] =
                            (string)$ssvc['exploitation'];
                    }

                    if (isset($ssvc['automatable'])) {
                        $result['ssvc_automatable'] =
                            (string)$ssvc['automatable'];
                    }

                    if (isset($ssvc['technicalImpact'])) {
                        $result['ssvc_technical_impact'] =
                            (string)$ssvc['technicalImpact'];
                    }
                }
            }
        }
    }

    return $result;
}


function cve_raw_url(string $cveId): string
{
    if (!preg_match('/^CVE-(\d{4})-(\d+)$/i', $cveId, $m)) {
        throw new InvalidArgumentException("Invalid CVE ID: {$cveId}");
    }

    $year = $m[1];
    $number = (int)$m[2];
    $bucket = (string)floor($number / 1000) . 'xxx';

    return CVE_BASE_URL
        . $year
        . '/'
        . $bucket
        . '/'
        . strtoupper($cveId)
        . '.json';
}


function save_cve(array $record): void
{
    if (empty($record['cveMetadata']['cveId'])) {
        return;
    }

    $meta = $record['cveMetadata'];
    $id = strtoupper((string)$meta['cveId']);
    $title = extract_title($record);
    $description = extract_description($record);
    $cvss = extract_cvss($record);
    $products = extract_products($record);
    $refs = extract_references($record);
    $cisa = extract_cisa_data($record);

    $pdo = db();

    $existing = $pdo->prepare("
        SELECT
            kev,
            kev_date,
            kev_due_date,
            kev_required_action,
            kev_ransomware_use
        FROM cves
        WHERE cve_id = ?
    ");

    $existing->execute([$id]);
    $old = $existing->fetch();

    if ($old) {
        if ((int)$old['kev'] === 1) {
            $cisa['kev'] = 1;
        }

        if (!$cisa['kev_date']) {
            $cisa['kev_date'] = $old['kev_date'];
        }

        if (!$cisa['kev_due_date']) {
            $cisa['kev_due_date'] = $old['kev_due_date'];
        }

        if (!$cisa['kev_required_action']) {
            $cisa['kev_required_action'] = $old['kev_required_action'];
        }

        if (!$cisa['kev_ransomware_use']) {
            $cisa['kev_ransomware_use'] = $old['kev_ransomware_use'];
        }
    }

    $stmt = $pdo->prepare("
        INSERT INTO cves (
            cve_id,
            title,
            description,
            published,
            updated,
            assigner,
            severity,
            cvss,
            cvss_version,
            vector,
            cwe,
            vendors,
            products,
            cpes,
            kev,
            kev_date,
            kev_due_date,
            kev_required_action,
            kev_ransomware_use,
            ssvc_exploitation,
            ssvc_automatable,
            ssvc_technical_impact,
            references_json,
            synced_at
        )
        VALUES (
            :cve_id,
            :title,
            :description,
            :published,
            :updated,
            :assigner,
            :severity,
            :cvss,
            :cvss_version,
            :vector,
            :cwe,
            :vendors,
            :products,
            :cpes,
            :kev,
            :kev_date,
            :kev_due_date,
            :kev_required_action,
            :kev_ransomware_use,
            :ssvc_exploitation,
            :ssvc_automatable,
            :ssvc_technical_impact,
            :references_json,
            :synced_at
        )
        ON CONFLICT(cve_id)
        DO UPDATE SET
            title = excluded.title,
            description = excluded.description,
            published = excluded.published,
            updated = excluded.updated,
            assigner = excluded.assigner,
            severity = excluded.severity,
            cvss = excluded.cvss,
            cvss_version = excluded.cvss_version,
            vector = excluded.vector,
            cwe = excluded.cwe,
            vendors = excluded.vendors,
            products = excluded.products,
            cpes = excluded.cpes,
            kev = excluded.kev,
            kev_date = excluded.kev_date,
            kev_due_date = excluded.kev_due_date,
            kev_required_action = excluded.kev_required_action,
            kev_ransomware_use = excluded.kev_ransomware_use,
            ssvc_exploitation = excluded.ssvc_exploitation,
            ssvc_automatable = excluded.ssvc_automatable,
            ssvc_technical_impact = excluded.ssvc_technical_impact,
            references_json = excluded.references_json,
            synced_at = excluded.synced_at
    ");

    $stmt->execute([
        ':cve_id' => $id,
        ':title' => $title,
        ':description' => $description,
        ':published' => iso_to_sql($meta['datePublished'] ?? null),
        ':updated' => iso_to_sql($meta['dateUpdated'] ?? null),
        ':assigner' => $meta['assignerShortName'] ?? null,
        ':severity' => $cvss['severity'],
        ':cvss' => $cvss['score'],
        ':cvss_version' => $cvss['version'],
        ':vector' => $cvss['vector'],
        ':cwe' => extract_cwe($record),
        ':vendors' => $products['vendors'],
        ':products' => $products['products'],
        ':cpes' => $products['cpes'],
        ':kev' => $cisa['kev'],
        ':kev_date' => $cisa['kev_date'],
        ':kev_due_date' => $cisa['kev_due_date'],
        ':kev_required_action' => $cisa['kev_required_action'],
        ':kev_ransomware_use' => $cisa['kev_ransomware_use'],
        ':ssvc_exploitation' => $cisa['ssvc_exploitation'],
        ':ssvc_automatable' => $cisa['ssvc_automatable'],
        ':ssvc_technical_impact' => $cisa['ssvc_technical_impact'],
        ':references_json' => json_encode(
            $refs,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        ),
        ':synced_at' => now_utc(),
    ]);
}


function fetch_delta_log(): array
{
    echo "Downloading official CVE delta log...\n";
    return json_get(DELTA_LOG_URL);
}


function fetch_delta(): array
{
    echo "Downloading current CVE delta...\n";
    return json_get(DELTA_URL);
}


function extract_cve_ids_from_delta(array $delta): array
{
    $ids = [];

    foreach (['new', 'updated'] as $section) {
        if (empty($delta[$section]) || !is_array($delta[$section])) {
            continue;
        }

        foreach ($delta[$section] as $item) {
            if (!is_array($item) || empty($item['cveId'])) {
                continue;
            }

            $id = strtoupper(trim((string)$item['cveId']));

            if (preg_match('/^CVE-\d{4}-\d{4,7}$/', $id)) {
                $ids[$id] = true;
            }
        }
    }

    return array_keys($ids);
}


function extract_cve_ids_from_delta_from_log(
    array $delta,
    int $hours = DELTA_WINDOW_HOURS
): array {

    $ids = [];
    $cutoff = time() - ($hours * 3600);

    $walker = function ($node, $timestamp = null) use (&$walker, &$ids, $cutoff) {
        if (is_array($node)) {
            $localTimestamp = $timestamp;

            foreach ($node as $value) {
                if (is_string($value) && preg_match(
                    '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/',
                    $value
                )) {
                    $parsed = strtotime($value);

                    if ($parsed !== false) {
                        $localTimestamp = $parsed;
                    }
                }

                if (is_string($value) && preg_match_all(
                    '/CVE-\d{4}-\d{4,7}/i',
                    $value,
                    $matches
                )) {
                    foreach ($matches[0] as $id) {
                        $id = strtoupper($id);

                        if ($localTimestamp !== null && $localTimestamp >= $cutoff) {
                            $ids[$id] = $localTimestamp;
                        }
                    }
                }

                $walker($value, $localTimestamp);
            }
        } elseif (is_string($node)) {
            if (preg_match_all('/CVE-\d{4}-\d{4,7}/i', $node, $matches)) {
                foreach ($matches[0] as $id) {
                    $id = strtoupper($id);

                    if ($timestamp !== null && $timestamp >= $cutoff) {
                        $ids[$id] = $timestamp;
                    }
                }
            }
        }
    };

    $walker($delta);

    arsort($ids, SORT_NUMERIC);

    return array_keys($ids);
}


function discover_cve_ids(): array
{
    $ids = [];

    try {
        $delta = fetch_delta();

        foreach (extract_cve_ids_from_delta($delta) as $id) {
            $ids[$id] = true;
        }
    } catch (Throwable $e) {
        echo "Current delta failed: {$e->getMessage()}\n";
    }

    try {
        $deltaLog = fetch_delta_log();

        foreach (
            extract_cve_ids_from_delta_from_log(
                $deltaLog,
                SYNC_WINDOW_HOURS
            ) as $id
        ) {
            $ids[$id] = true;
        }
    } catch (Throwable $e) {
        echo "Delta log failed: {$e->getMessage()}\n";
    }

    return array_keys($ids);
}


function fetch_and_save_cves(array $ids): array
{
    $success = 0;
    $failedIds = [];

    foreach (array_chunk($ids, HTTP_CONCURRENCY) as $batch) {
        $multi = curl_multi_init();
        $handles = [];

        foreach ($batch as $id) {
            try {
                $url = cve_raw_url($id);
                $ch = curl_init($url);

                if ($ch === false) {
                    throw new RuntimeException('Unable to initialize cURL');
                }

                curl_setopt_array($ch, [
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_FOLLOWLOCATION => true,
                    CURLOPT_CONNECTTIMEOUT => 15,
                    CURLOPT_TIMEOUT => 60,
                    CURLOPT_USERAGENT => USER_AGENT,
                    CURLOPT_HTTPHEADER => ['Accept: application/json'],
                    CURLOPT_ENCODING => '',
                ]);

                curl_multi_add_handle($multi, $ch);
                $handles[(int)$ch] = [$ch, $id];
            } catch (Throwable $e) {
                $failedIds[] = $id;
                echo "FAILED {$id}: {$e->getMessage()}\n";
            }
        }

        do {
            $status = curl_multi_exec($multi, $running);

            if ($running) {
                curl_multi_select($multi, 1.0);
            }
        } while ($running && $status === CURLM_OK);

        foreach ($handles as [$ch, $id]) {
            $raw = curl_multi_getcontent($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $error = curl_error($ch);

            if ($error !== '' || $code < 200 || $code >= 300 || $raw === false) {
                $failedIds[] = $id;
                echo "FAILED {$id}: HTTP {$code}"
                    . ($error ? " {$error}" : '')
                    . "\n";
            } else {
                $record = json_decode($raw, true);

                if (!is_array($record)) {
                    $failedIds[] = $id;
                    echo "FAILED {$id}: Invalid JSON\n";
                } else {
                    try {
                        save_cve($record);
                        $success++;
                    } catch (Throwable $e) {
                        $failedIds[] = $id;
                        echo "FAILED {$id}: {$e->getMessage()}\n";
                    }
                }
            }

            curl_multi_remove_handle($multi, $ch);
            curl_close($ch);
        }

        curl_multi_close($multi);
    }

    return [$success, $failedIds];
}


function update_kev(): int
{
    echo "Downloading CISA KEV...\n";

    $data = json_get(KEV_URL);

    if (empty($data['vulnerabilities'])
        || !is_array($data['vulnerabilities'])) {
        throw new RuntimeException('Invalid CISA KEV feed');
    }

    $pdo = db();

    $update = $pdo->prepare("
        UPDATE cves
        SET
            kev = 1,
            kev_date = ?,
            kev_due_date = ?,
            kev_required_action = ?,
            kev_ransomware_use = ?
        WHERE cve_id = ?
    ");

    $exists = $pdo->prepare("
        SELECT 1 FROM cves WHERE cve_id = ? LIMIT 1
    ");

    $count = 0;

    foreach ($data['vulnerabilities'] as $item) {
        $id = $item['cveID'] ?? null;

        if (!$id) {
            continue;
        }

        $id = strtoupper(trim((string)$id));

        $exists->execute([$id]);
        $found = $exists->fetchColumn();

        if ($found === false) {
            try {
                $url = cve_raw_url($id);

                echo "KEV CVE missing locally: {$id} -> downloading...\n";

                $record = json_get($url);
                save_cve($record);
            } catch (Throwable $e) {
                echo "FAILED KEV CVE {$id}: {$e->getMessage()}\n";
                continue;
            }
        }

        $update->execute([
            $item['dateAdded'] ?? null,
            $item['dueDate'] ?? null,
            $item['requiredAction'] ?? null,
            $item['knownRansomwareCampaignUse'] ?? null,
            $id,
        ]);

        $count += $update->rowCount();
    }

    set_setting('kev_sync', now_utc());

    return $count;
}


function retention_days_for(?string $severity): int
{
    return match (strtoupper((string)$severity)) {
        'CRITICAL' => RETENTION_CRITICAL,
        'HIGH'     => RETENTION_HIGH,
        'MEDIUM'   => RETENTION_MEDIUM,
        'LOW'      => RETENTION_LOW,
        default    => RETENTION_DEFAULT,
    };
}


function prune_old_records(): int
{
    $pdo = db();
    $total = 0;

    $groups = [
        'CRITICAL' => RETENTION_CRITICAL,
        'HIGH'     => RETENTION_HIGH,
        'MEDIUM'   => RETENTION_MEDIUM,
        'LOW'      => RETENTION_LOW,
    ];

    foreach ($groups as $sev => $days) {
        $stmt = $pdo->prepare("
            DELETE FROM cves
            WHERE kev = 0
              AND cve_id NOT IN (SELECT cve_id FROM watchlist)
              AND severity = ?
              AND COALESCE(updated, published) < datetime('now', ?)
        ");

        $stmt->execute([$sev, "-{$days} days"]);
        $total += $stmt->rowCount();
    }

    $stmt = $pdo->prepare("
        DELETE FROM cves
        WHERE kev = 0
          AND cve_id NOT IN (SELECT cve_id FROM watchlist)
          AND (
                severity IS NULL
                OR severity NOT IN ('CRITICAL','HIGH','MEDIUM','LOW')
              )
          AND COALESCE(updated, published) < datetime('now', ?)
    ");

    $stmt->execute(['-' . RETENTION_DEFAULT . ' days']);
    $total += $stmt->rowCount();

    if ($total > 0) {
        $pdo->exec('PRAGMA incremental_vacuum');
    }

    return $total;
}


function optimize_db(): void
{
    $pdo = db();

    $pdo->exec('PRAGMA wal_checkpoint(TRUNCATE)');
    $pdo->exec('PRAGMA optimize');

    $lastVacuum = (int)(get_setting('last_vacuum') ?? 0);

    if (time() - $lastVacuum > 86400) {
        $pdo->exec('VACUUM');
        set_setting('last_vacuum', (string)time());
    }
}


function watch_cve(string $cveId, ?string $note = null): void
{
    $id = strtoupper(trim($cveId));

    if (!preg_match('/^CVE-\d{4}-\d{4,7}$/', $id)) {
        throw new InvalidArgumentException("Invalid CVE ID: {$cveId}");
    }

    $stmt = db()->prepare("
        INSERT INTO watchlist(cve_id, note, added_at)
        VALUES(?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            note = COALESCE(excluded.note, watchlist.note)
    ");

    $stmt->execute([$id, $note, now_utc()]);
}


function unwatch_cve(string $cveId): bool
{
    $id = strtoupper(trim($cveId));

    $stmt = db()->prepare('DELETE FROM watchlist WHERE cve_id = ?');
    $stmt->execute([$id]);

    return $stmt->rowCount() > 0;
}


function list_watchlist(): array
{
    return db()
        ->query('SELECT cve_id, note, added_at FROM watchlist ORDER BY cve_id')
        ->fetchAll();
}


function update_database(): void
{
    $fp = fopen(__DIR__ . '/cve_monitor.lock', 'c');

    if (!$fp || !flock($fp, LOCK_EX | LOCK_NB)) {
        echo "Another update is already running.\n";
        exit(0);
    }

    try {
        db();

        echo "========================================\n";
        echo "CVE Monitor Update\n";
        echo "UTC: " . now_utc() . "\n";
        echo "Database: " . database_file() . "\n";
        echo "========================================\n";

        $ids = discover_cve_ids();
        $totalDelta = count($ids);

        echo "CVE records found in official change feeds: {$totalDelta}\n";
        echo "CVE records to fetch: {$totalDelta}\n";

        [$success, $failedIds] = fetch_and_save_cves($ids);
        $failed = count($failedIds);

        set_setting(
            'last_failed_ids',
            json_encode($failedIds, JSON_UNESCAPED_SLASHES)
        );

        try {
            $kevChanged = update_kev();
            echo "CISA KEV updated: {$kevChanged} rows\n";
        } catch (Throwable $e) {
            echo "CISA KEV update failed: {$e->getMessage()}\n";
        }

        try {
            $pruned = prune_old_records();
            echo "Pruned old records: {$pruned}\n";
        } catch (Throwable $e) {
            echo "Prune failed: {$e->getMessage()}\n";
        }

        try {
            optimize_db();
            echo "Database optimized.\n";
        } catch (Throwable $e) {
            echo "Optimize failed: {$e->getMessage()}\n";
        }

        set_setting('last_sync', now_utc());
        set_setting('last_sync_count', (string)$success);
        set_setting('last_sync_failed', (string)$failed);
        set_setting('last_delta_count', (string)$totalDelta);

        echo "----------------------------------------\n";
        echo "Delta found: {$totalDelta}\n";
        echo "Successful: {$success}\n";
        echo "Failed:     {$failed}\n";
        echo "Finished:   " . now_utc() . "\n";

        if ($failedIds) {
            echo "Failed CVEs:\n";

            foreach ($failedIds as $failedId) {
                echo "  - {$failedId}\n";
            }
        }

        echo "----------------------------------------\n";
    } finally {
        flock($fp, LOCK_UN);
        fclose($fp);
    }
}


function dashboard(): void
{
    $pdo = db();

    $days = isset($_GET['days'])
        ? max(0, min(3650, (int)$_GET['days']))
        : 7;

    $severity = trim((string)($_GET['severity'] ?? ''));
    $minCvss = trim((string)($_GET['min_cvss'] ?? ''));
    $kev = isset($_GET['kev']) ? (int)$_GET['kev'] : 0;
    $q = trim((string)($_GET['q'] ?? ''));
    $vendor = trim((string)($_GET['vendor'] ?? ''));
    $product = trim((string)($_GET['product'] ?? ''));
    $cwe = trim((string)($_GET['cwe'] ?? ''));
    $type = trim((string)($_GET['type'] ?? 'published'));

    $where = [];
    $params = [];

    if ($days > 0) {
        $column = $type === 'updated' ? 'updated' : 'published';
        $where[] = "cves.{$column} >= datetime('now', ?)";
        $params[] = "-{$days} days";
    }

    if ($severity !== '') {
        $where[] = 'cves.severity = ?';
        $params[] = strtoupper($severity);
    }

    if ($minCvss !== '' && is_numeric($minCvss)) {
        $where[] = 'cves.cvss >= ?';
        $params[] = (float)$minCvss;
    }

    if ($kev === 1) {
        $where[] = 'cves.kev = 1';
    }

    if ($vendor !== '') {
        $where[] = 'cves.vendors LIKE ?';
        $params[] = '%' . $vendor . '%';
    }

    if ($product !== '') {
        $where[] = 'cves.products LIKE ?';
        $params[] = '%' . $product . '%';
    }

    if ($cwe !== '') {
        $where[] = 'cves.cwe LIKE ?';
        $params[] = '%' . $cwe . '%';
    }

    if ($q !== '') {
        $where[] = "
            (
                cves.cve_id LIKE ?
                OR cves.title LIKE ?
                OR cves.description LIKE ?
                OR cves.vendors LIKE ?
                OR cves.products LIKE ?
                OR cves.cwe LIKE ?
            )
        ";

        $search = '%' . $q . '%';

        for ($i = 0; $i < 6; $i++) {
            $params[] = $search;
        }
    }

    $sql = "
        SELECT
            cves.*,
            CASE
                WHEN w.cve_id IS NOT NULL THEN 1
                ELSE 0
            END AS watched
        FROM cves
        LEFT JOIN watchlist w
            ON w.cve_id = cves.cve_id
    ";

    if ($where) {
        $sql .= ' WHERE ' . implode(' AND ', $where);
    }

    $orderColumn = $type === 'updated' ? 'updated' : 'published';

    $sql .= "
        ORDER BY
            CASE
                WHEN cves.kev = 1 THEN 0
                WHEN cves.severity = 'CRITICAL' THEN 1
                WHEN cves.severity = 'HIGH' THEN 2
                WHEN cves.severity = 'MEDIUM' THEN 3
                WHEN cves.severity = 'LOW' THEN 4
                ELSE 5
            END,
            cves.{$orderColumn} IS NULL,
            cves.{$orderColumn} DESC,
            cves.cve_id DESC
        LIMIT 500
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    $total = (int)$pdo
        ->query('SELECT COUNT(*) FROM cves')
        ->fetchColumn();

    $critical = (int)$pdo
        ->query("SELECT COUNT(*) FROM cves WHERE severity = 'CRITICAL'")
        ->fetchColumn();

    $high = (int)$pdo
        ->query("SELECT COUNT(*) FROM cves WHERE severity = 'HIGH'")
        ->fetchColumn();

    $kevTotal = (int)$pdo
        ->query("SELECT COUNT(*) FROM cves WHERE kev = 1")
        ->fetchColumn();

    $watchTotal = (int)$pdo
        ->query("SELECT COUNT(*) FROM watchlist")
        ->fetchColumn();

    $lastSync = get_setting('last_sync');
    $kevSync = get_setting('kev_sync');
    $lastDeltaCount = get_setting('last_delta_count');
    $lastSyncCount = get_setting('last_sync_count');
    $lastSyncFailed = get_setting('last_sync_failed');

    ?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CVE Security Dashboard</title>
<style>
body {
    margin: 0;
    font-family: Arial, Helvetica, sans-serif;
    background: #f5f6f8;
    color: #202124;
}
header {
    background: #111827;
    color: white;
    padding: 22px;
}
.container {
    max-width: 1500px;
    margin: auto;
    padding: 20px;
}
h1 {
    margin: 0 0 5px;
}
.muted {
    color: #6b7280;
    font-size: 13px;
}
.cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
}
.card {
    background: white;
    border-radius: 10px;
    padding: 18px;
    box-shadow: 0 1px 3px rgba(0,0,0,.08);
}
.card .number {
    font-size: 28px;
    font-weight: bold;
    margin-top: 5px;
}
.filters {
    background: white;
    padding: 18px;
    border-radius: 10px;
    margin-bottom: 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,.08);
}
.filters form {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 10px;
}
input,
select,
button {
    width: 100%;
    box-sizing: border-box;
    padding: 10px;
    border: 1px solid #d1d5db;
    border-radius: 7px;
    background: white;
}
button {
    background: #111827;
    color: white;
    cursor: pointer;
}
.table-wrap {
    background: white;
    border-radius: 10px;
    overflow-x: auto;
    box-shadow: 0 1px 3px rgba(0,0,0,.08);
}
table {
    width: 100%;
    border-collapse: collapse;
    min-width: 1100px;
}
th,
td {
    padding: 12px;
    border-bottom: 1px solid #e5e7eb;
    vertical-align: top;
    text-align: left;
}
th {
    background: #f9fafb;
    font-size: 13px;
}
.cve {
    font-weight: bold;
    white-space: nowrap;
}
.badge {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 5px;
    font-size: 12px;
    font-weight: bold;
}
.critical {
    background: #fee2e2;
    color: #991b1b;
}
.high {
    background: #ffedd5;
    color: #9a3412;
}
.medium {
    background: #fef3c7;
    color: #92400e;
}
.low {
    background: #dcfce7;
    color: #166534;
}
.none {
    background: #e5e7eb;
    color: #374151;
}
.kev {
    background: #7f1d1d;
    color: white;
}
.watched {
    background: #1e40af;
    color: white;
}
.desc {
    max-width: 500px;
    line-height: 1.45;
}
.small {
    font-size: 12px;
    color: #6b7280;
}
a {
    color: #2563eb;
    text-decoration: none;
}
a:hover {
    text-decoration: underline;
}
</style>
</head>
<body>

<header>
<div class="container">
<h1>CVE Security Dashboard</h1>
<div class="muted" style="color:#d1d5db">
Official CVE List / CVEProject
</div>
</div>
</header>

<div class="container">

<div class="cards">

<div class="card">
Total stored
<div class="number"><?=number_format($total)?></div>
</div>

<div class="card">
Critical
<div class="number"><?=number_format($critical)?></div>
</div>

<div class="card">
High
<div class="number"><?=number_format($high)?></div>
</div>

<div class="card">
CISA KEV
<div class="number"><?=number_format($kevTotal)?></div>
</div>

<div class="card">
Watched
<div class="number"><?=number_format($watchTotal)?></div>
</div>

<div class="card">
Last CVE sync
<div class="number" style="font-size:16px">
<?=h($lastSync ?: 'Never')?>
</div>
</div>

</div>

<div class="filters">

<form method="get">

<div>
<label>Period</label>
<select name="days">
<option value="1" <?=$days === 1 ? 'selected' : ''?>>Last 24 hours</option>
<option value="3" <?=$days === 3 ? 'selected' : ''?>>Last 3 days</option>
<option value="7" <?=$days === 7 ? 'selected' : ''?>>Last 7 days</option>
<option value="30" <?=$days === 30 ? 'selected' : ''?>>Last 30 days</option>
<option value="90" <?=$days === 90 ? 'selected' : ''?>>Last 90 days</option>
<option value="365" <?=$days === 365 ? 'selected' : ''?>>Last year</option>
<option value="0" <?=$days === 0 ? 'selected' : ''?>>All stored</option>
</select>
</div>

<div>
<label>Date field</label>
<select name="type">
<option value="published" <?=$type === 'published' ? 'selected' : ''?>>Published</option>
<option value="updated" <?=$type === 'updated' ? 'selected' : ''?>>Updated</option>
</select>
</div>

<div>
<label>Severity</label>
<select name="severity">
<option value="">All</option>
<?php foreach (['CRITICAL','HIGH','MEDIUM','LOW','NONE'] as $s): ?>
<option value="<?=h($s)?>" <?=$severity === $s ? 'selected' : ''?>><?=h($s)?></option>
<?php endforeach; ?>
</select>
</div>

<div>
<label>Minimum CVSS</label>
<input type="number" step="0.1" min="0" max="10" name="min_cvss" value="<?=h($minCvss)?>" placeholder="e.g. 8.0">
</div>

<div>
<label>Vendor</label>
<input type="text" name="vendor" value="<?=h($vendor)?>" placeholder="Linux, Microsoft...">
</div>

<div>
<label>Product</label>
<input type="text" name="product" value="<?=h($product)?>" placeholder="OpenSSH, nginx...">
</div>

<div>
<label>CWE</label>
<input type="text" name="cwe" value="<?=h($cwe)?>" placeholder="CWE-79">
</div>

<div>
<label>Search</label>
<input type="text" name="q" value="<?=h($q)?>" placeholder="CVE / keyword / product...">
</div>

<div>
<label>Exploit</label>
<select name="kev">
<option value="0">All</option>
<option value="1" <?=$kev === 1 ? 'selected' : ''?>>CISA KEV only</option>
</select>
</div>

<div style="align-self:end">
<button type="submit">Apply Filters</button>
</div>

</form>

<div style="margin-top:12px" class="small">
CISA KEV last sync: <?=h($kevSync ?: 'Never')?>
<br>
Last delta: <?=h($lastDeltaCount ?: '0')?> CVEs |
Successful: <?=h($lastSyncCount ?: '0')?> |
Failed: <?=h($lastSyncFailed ?: '0')?>
</div>

</div>

<div class="table-wrap">

<table>
<thead>
<tr>
<th>CVE</th>
<th>Severity</th>
<th>CVSS</th>
<th>Vendor / Product</th>
<th>CWE</th>
<th>Published</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<?php if (!$rows): ?>
<tr>
<td colspan="7">No results.</td>
</tr>
<?php endif; ?>

<?php foreach ($rows as $row): ?>
<tr>

<td>
<div class="cve">
<a href="https://www.cve.org/CVERecord?id=<?=urlencode($row['cve_id'])?>" target="_blank" rel="noopener">
<?=h($row['cve_id'])?>
</a>
</div>

<?php if ((int)$row['kev'] === 1): ?>
<br>
<span class="badge kev">CISA KEV</span>
<?php endif; ?>

<?php if ((int)$row['watched'] === 1): ?>
<br>
<span class="badge watched">WATCHED</span>
<?php endif; ?>
</td>

<td>
<?php
$severityClass = strtolower($row['severity'] ?: 'none');
$severityClass = preg_replace('/[^a-z]/', '', $severityClass);
?>
<span class="badge <?=$severityClass?>">
<?=h($row['severity'] ?: 'N/A')?>
</span>
</td>

<td>
<?php if ($row['cvss'] !== null): ?>
<strong><?=h((string)$row['cvss'])?></strong>
<div class="small"><?=h($row['cvss_version'] ?? '')?></div>
<?php else: ?>
N/A
<?php endif; ?>
</td>

<td>
<?php if ($row['vendors']): ?>
<strong><?=h($row['vendors'])?></strong>
<br>
<?php endif; ?>
<span class="small"><?=h($row['products'])?></span>
</td>

<td>
<?=h($row['cwe'] ?: 'N/A')?>
</td>

<td>
<?=h($row['published'] ?: '')?>
<br>
<span class="small">Updated: <?=h($row['updated'] ?: '')?></span>
</td>

<td>
<div class="desc">
<strong><?=h($row['title'] ?: '')?></strong>
<br><br>
<?=nl2br(h(mb_substr($row['description'] ?? '', 0, 700)))?>
<?php if (mb_strlen($row['description'] ?? '') > 700): ?>
...
<?php endif; ?>
<br><br>
<?php if ($row['vector']): ?>
<span class="small"><?=h($row['vector'])?></span>
<?php endif; ?>
</div>
</td>

</tr>
<?php endforeach; ?>

</tbody>
</table>

</div>

</div>

</body>
</html>
<?php
}


if (PHP_SAPI === 'cli') {

    $cmd = $argv[1] ?? null;

    if ($cmd === '--update') {
        update_database();
        exit(0);
    }

    if ($cmd === '--import-cve' && isset($argv[2])) {
        $id = strtoupper(trim($argv[2]));

        if (!preg_match('/^CVE-\d{4}-\d{4,7}$/', $id)) {
            fwrite(STDERR, "Invalid CVE ID.\n");
            exit(1);
        }

        try {
            save_cve(json_get(cve_raw_url($id)));
            echo "Imported {$id}\n";
            exit(0);
        } catch (Throwable $e) {
            fwrite(STDERR, "Import failed: {$e->getMessage()}\n");
            exit(1);
        }
    }

    if ($cmd === '--watch' && isset($argv[2])) {
        $id = strtoupper(trim($argv[2]));
        $note = $argv[3] ?? null;

        if (!preg_match('/^CVE-\d{4}-\d{4,7}$/', $id)) {
            fwrite(STDERR, "Invalid CVE ID.\n");
            exit(1);
        }

        try {
            watch_cve($id, $note);

            try {
                save_cve(json_get(cve_raw_url($id)));
                echo "Watched and imported: {$id}\n";
            } catch (Throwable $e) {
                echo "Watched {$id} (import failed: {$e->getMessage()})\n";
            }

            exit(0);
        } catch (Throwable $e) {
            fwrite(STDERR, "Watch failed: {$e->getMessage()}\n");
            exit(1);
        }
    }

    if ($cmd === '--unwatch' && isset($argv[2])) {
        $id = strtoupper(trim($argv[2]));

        if (unwatch_cve($id)) {
            echo "Removed from watchlist: {$id}\n";
        } else {
            echo "Not in watchlist: {$id}\n";
        }

        exit(0);
    }

    if ($cmd === '--watch-list') {
        $items = list_watchlist();

        if (!$items) {
            echo "Watchlist is empty.\n";
            exit(0);
        }

        printf("%-20s  %-20s  %s\n", 'CVE ID', 'ADDED AT', 'NOTE');

        foreach ($items as $item) {
            printf(
                "%-20s  %-20s  %s\n",
                $item['cve_id'],
                $item['added_at'] ?? '',
                $item['note'] ?? ''
            );
        }

        exit(0);
    }

    echo <<<TXT

CVE Monitor

Usage:

  php cve_monitor.php --update
  php cve_monitor.php --import-cve CVE-YYYY-NNNN
  php cve_monitor.php --watch      CVE-YYYY-NNNN ["optional note"]
  php cve_monitor.php --unwatch    CVE-YYYY-NNNN
  php cve_monitor.php --watch-list

Dashboard:

  Open cve_monitor.php in your browser.

TXT;

    exit(0);
}


dashboard();

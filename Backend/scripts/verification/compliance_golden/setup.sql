-- Compliance golden: what run.sh adds to the restored template, once, before
-- any capture. Every capture of every commit starts from the same rows, so the
-- additions are inputs, never results.
--
-- The development installation holds three assets, no web scan, no network
-- link and two installed catalogues, which leaves most of the evidence
-- adapters' branches and most of the automated rules unexercised. This adds:
--
--   * every catalogue installed for the development organisation, and a policy
--     holding every active rule mapped to a catalogue that has none;
--   * three assets: a Windows host whose attributes answer every
--     offline-configuration and credential key, a Linux host answering some of
--     them (an unparseable date, a NULL, an empty list), and a host the
--     scanner could not authenticate to, with no operating system;
--   * services in each observed state, TLS details (expired, weak,
--     self-signed), anti-malware services under both a port and a collected
--     process name, and copies of real findings, some with no severity or
--     score of their own;
--   * network links between the hosts;
--   * web scans and findings: a completed scan matched by address and port, an
--     older one it supersedes, one matched by host name in another case, a
--     failed one and a deleted one; findings in every status the adapter
--     counts and two it does not.
BEGIN;

INSERT INTO compliance_tenant_frameworks (id, tenant_id, framework_id, is_enabled, enabled_at)
SELECT 'ctf_g4_' || f.id, 'org_development', f.id, true, '2026-10-01T00:00:00Z'
FROM compliance_frameworks f
WHERE NOT EXISTS (
  SELECT 1 FROM compliance_tenant_frameworks t
  WHERE t.tenant_id = 'org_development' AND t.framework_id = f.id
);

CREATE TEMP TABLE g4_policy_frameworks AS
SELECT f.id AS framework_id FROM compliance_frameworks f
WHERE NOT EXISTS (
  SELECT 1 FROM compliance_policies p
  WHERE p.tenant_id = 'org_development' AND p.framework_id = f.id
);

INSERT INTO compliance_policies (id, framework_id, tenant_id, policy_family_code,
  version_number, name, target_platform, description, status, tags, is_active,
  created_at)
SELECT 'cpl_g4_' || g.framework_id, g.framework_id, 'org_development',
  'G4-' || upper(g.framework_id), 1, 'Golden policy for ' || g.framework_id,
  p.target_platform, 'compliance golden', 'active', p.tags, true,
  '2026-10-01T00:00:00Z'
FROM g4_policy_frameworks g
CROSS JOIN (SELECT target_platform, tags FROM compliance_policies
            WHERE id = 'cpl_org_development_iso27001_2022_default') p;

INSERT INTO compliance_policy_rules (policy_id, rule_id)
SELECT DISTINCT 'cpl_g4_' || c.framework_id, rc.rule_id
FROM compliance_rule_controls rc
JOIN compliance_controls c ON c.id = rc.control_id
JOIN compliance_rules r ON r.id = rc.rule_id
JOIN g4_policy_frameworks g ON g.framework_id = c.framework_id
WHERE r.status = 'active';

-- Three assets, cloned from the Windows workstation's row for its columns.
CREATE TEMP TABLE g4_assets (id text, ip text, hostname text, os_family text,
  os_name text, tags jsonb, attrs jsonb);
INSERT INTO g4_assets VALUES
('ast_g4_win', '10.250.0.11', 'g4-win', 'Windows', 'Microsoft Windows Server 2022', '["cde"]',
 '{"credentialed_status": "success",
   "password_policy": {"complexity": true, "history_length": 24, "min_length": 14,
                       "max_age_days": 60, "lockout_threshold": 5},
   "registry_hardening": {"rdp_disabled": false, "rdp_nla_enforced": 1, "fim_active": true,
     "fim_monitored_dirs": ["C:\\Windows\\System32"], "session_timeout_minutes": 15,
     "account_lockout_threshold": 5, "retention_days": 400, "disk_encryption_enabled": true,
     "uac_enabled": true, "firewall_active": true, "audit_configured": false,
     "smbv1_disabled": true, "netbios_disabled": false, "legacy_tls_disabled": true,
     "telnet_disabled": true, "ntp_servers": ["time.windows.com"],
     "incident_reporting_sla_hours": 6, "vpn_log_retention_years": 1},
   "credentialed_system_info": {"running_services": [
     {"name": "WinDefend", "description": "Microsoft Defender Antivirus Service"},
     {"name": "Spooler"}, {"description": "CrowdStrike Falcon Sensor"}]},
   "pam_mfa_modules": [], "asv_last_passing_scan_date": "2026-09-01T00:00:00Z",
   "pci_log_daily_reviewed": true, "ir_last_test_date": "2025-06-01T00:00:00Z",
   "waf_active": true, "ids_ips_active": false, "last_vuln_scan_at": "2026-10-20T00:00:00Z",
   "mfa_enforced_admin": true, "account_review_completed": false,
   "log_review_frequency_days": 7, "backup_frequency_days": 1, "scrm_plan_documented": true,
   "pii_encryption_enabled": true, "dpo_designated": false, "dpia_conducted": true,
   "breach_notification_sla_hours": 72, "consent_management_active": true,
   "pii_retention_days": 365, "tags": ["pci"], "cde_scope": "cde"}'),
('ast_g4_lnx', '10.250.0.12', 'g4-lnx', 'Linux', 'Rocky Linux 9.4', '[]',
 '{"credentialed_status": "success",
   "password_policy": {"min_length": 8, "lockout_threshold": null},
   "registry_hardening": {"rdp_disabled": true},
   "pam_mfa_modules": ["pam_google_authenticator.so"],
   "asv_last_passing_scan_date": "not-a-date", "ir_last_test_date": "2026-01-15",
   "fim_active": false, "session_timeout_minutes": 30, "log_retention_days": 90,
   "ntp_servers": ["10.0.0.1", "10.0.0.2"], "last_vuln_scan_at": "2026-06-01T00:00:00Z",
   "credentialed_system_info": {"running_services": [{"name": "clamav-daemon"},
     {"name": "sshd"}]}}'),
('ast_g4_bare', '10.250.0.13', NULL, NULL, NULL, '[]',
 '{"credentialed_status": "failed"}');

INSERT INTO assets
SELECT (jsonb_populate_record(NULL::assets, to_jsonb(src) || jsonb_build_object(
  'id', g.id, 'ip_address', g.ip, 'mac_address', NULL, 'hostname', g.hostname,
  'os_family', g.os_family, 'os_name', g.os_name, 'tags', g.tags,
  'custom_attributes', g.attrs, 'last_scan_id', NULL,
  'first_seen_at', '2026-10-01T00:00:00Z', 'last_seen_at', '2026-10-20T00:00:00Z',
  'created_at', '2026-10-01T00:00:00Z', 'updated_at', '2026-10-20T00:00:00Z'))).*
FROM g4_assets g
CROSS JOIN (SELECT * FROM assets WHERE id = 'ast_org_80029f7f_10_180_6_30') src;

CREATE TEMP TABLE g4_services (id text, asset_id text, port int, protocol text,
  state text, name text);
INSERT INTO g4_services VALUES
('svc_g4_win_3389', 'ast_g4_win', 3389, 'tcp', 'open', 'ms-wbt-server'),
('svc_g4_win_445', 'ast_g4_win', 445, 'tcp', 'open', 'microsoft-ds'),
('svc_g4_win_8443', 'ast_g4_win', 8443, 'tcp', 'open', 'https'),
('svc_g4_win_8014', 'ast_g4_win', 8014, 'tcp', 'listening', 'Symantec Endpoint Protection'),
('svc_g4_win_135', 'ast_g4_win', 135, 'tcp', 'host_only', 'msrpc'),
('svc_g4_lnx_22', 'ast_g4_lnx', 22, 'tcp', 'open', 'ssh'),
('svc_g4_lnx_443', 'ast_g4_lnx', 443, 'tcp', 'open', 'https'),
('svc_g4_lnx_5432', 'ast_g4_lnx', 5432, 'tcp', 'fixed', 'postgresql'),
('svc_g4_lnx_631', 'ast_g4_lnx', 631, 'udp', 'host_only', NULL);

INSERT INTO services
SELECT (jsonb_populate_record(NULL::services, to_jsonb(src) || jsonb_build_object(
  'id', g.id, 'asset_id', g.asset_id, 'port', g.port, 'protocol', g.protocol,
  'state', g.state, 'service_name', g.name, 'scan_id', NULL,
  'created_at', '2026-10-01T00:00:00Z', 'updated_at', '2026-10-20T00:00:00Z'))).*
FROM g4_services g
CROSS JOIN (SELECT * FROM services ORDER BY id LIMIT 1) src;

INSERT INTO tls_details (service_id, is_enabled, protocol_version, cert_is_expired,
  cert_is_self_signed, cert_san_domains, is_weak_cipher, issues, created_at)
VALUES
('svc_g4_win_8443', true, 'TLSv1.0', true, false, '["g4-win"]', true, '[]', '2026-10-01T00:00:00Z'),
('svc_g4_lnx_443', true, 'TLSv1.3', false, true, '[]', false, '[]', '2026-10-01T00:00:00Z'),
('svc_g4_win_3389', true, NULL, NULL, NULL, '[]', false, '[]', '2026-10-01T00:00:00Z');

-- Real findings copied onto the new hosts: every status, and a few with no
-- severity or score of their own, so the catalogue's are read instead.
INSERT INTO asset_vulnerabilities
SELECT (jsonb_populate_record(NULL::asset_vulnerabilities, to_jsonb(v) || jsonb_build_object(
  'id', 'g4' || n.suffix || '_' || v.id, 'asset_id', n.asset_id, 'service_id', NULL))).*
FROM (VALUES ('w', 'ast_g4_win'), ('l', 'ast_g4_lnx')) n(suffix, asset_id)
CROSS JOIN LATERAL (
  SELECT * FROM asset_vulnerabilities
  WHERE asset_id = 'ast_org_80029f7f_10_180_6_45'
  ORDER BY status, id LIMIT 80
) v;
UPDATE asset_vulnerabilities SET severity = NULL
WHERE id IN (SELECT id FROM asset_vulnerabilities WHERE asset_id = 'ast_g4_win' ORDER BY id LIMIT 6);
UPDATE asset_vulnerabilities SET cvss_score = NULL
WHERE id IN (SELECT id FROM asset_vulnerabilities WHERE asset_id = 'ast_g4_win' ORDER BY id DESC LIMIT 6);

INSERT INTO network_links (id, org_id, scan_id, source_asset_id, target_asset_id,
  source_ip, target_ip, link_type, created_at)
SELECT l.id, 'org_development', (SELECT id FROM scans ORDER BY started_at, id LIMIT 1),
  l.src, l.dst, l.sip, l.dip, l.kind, '2026-10-01T00:00:00Z'
FROM (VALUES
  ('nl_g4_1', 'ast_g4_win', 'ast_g4_lnx', '10.250.0.11', '10.250.0.12', 'physical'),
  ('nl_g4_2', 'ast_g4_lnx', 'ast_org_80029f7f_10_180_6_45', '10.250.0.12', '10.180.6.45', 'logical'),
  ('nl_g4_3', 'ast_org_80029f7f_10_180_6_30', 'ast_g4_win', '10.180.6.30', '10.250.0.11', 'physical')
) l(id, src, dst, sip, dip, kind);

INSERT INTO web_scans (id, org_id, target_url, target_domain, status,
  authorization_confirmed, is_deleted, completed_at, created_at, queued_at)
VALUES
('ws_g4_latest', 'org_development', 'https://10.250.0.12:8443/', '10.250.0.12:8443', 'complete', true, false, '2026-10-10T00:00:00Z', '2026-10-10T00:00:00Z', '2026-10-10T00:00:00Z'),
('ws_g4_older', 'org_development', 'https://10.250.0.12/', '10.250.0.12', 'complete', true, false, '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z'),
('ws_g4_byname', 'org_development', 'https://G4-WIN/', 'G4-WIN', 'complete', true, false, '2026-10-05T00:00:00Z', '2026-10-05T00:00:00Z', '2026-10-05T00:00:00Z'),
('ws_g4_failed', 'org_development', 'https://10.250.0.11/', '10.250.0.11', 'failed', true, false, '2026-10-12T00:00:00Z', '2026-10-12T00:00:00Z', '2026-10-12T00:00:00Z'),
('ws_g4_deleted', 'org_development', 'https://10.250.0.11/', '10.250.0.11', 'complete', true, true, '2026-10-13T00:00:00Z', '2026-10-13T00:00:00Z', '2026-10-13T00:00:00Z');

INSERT INTO web_findings (id, web_scan_id, org_id, finding_type, title, severity,
  status, first_found_at, last_found_at, created_at)
SELECT f.id, f.scan, 'org_development', f.kind, f.title, f.severity, f.status,
  '2026-10-01T00:00:00Z', '2026-10-10T00:00:00Z', '2026-10-01T00:00:00Z'
FROM (VALUES
  ('wf_g4_1', 'ws_g4_latest', 'sqli', 'SQL injection', 'critical', 'open'),
  ('wf_g4_2', 'ws_g4_latest', 'xss', 'Reflected XSS', 'high', 'confirmed'),
  ('wf_g4_3', 'ws_g4_latest', 'tls_issue', 'Weak TLS', 'medium', 'fixed'),
  ('wf_g4_4', 'ws_g4_latest', 'info_disclosure', 'Banner', 'info', 'open'),
  ('wf_g4_5', 'ws_g4_older', 'sqli', 'SQL injection', 'critical', 'open'),
  ('wf_g4_6', 'ws_g4_byname', 'xss', 'Stored XSS', 'high', 'reopened'),
  ('wf_g4_7', 'ws_g4_byname', 'sqli', 'SQL injection', 'critical', 'false_positive'),
  ('wf_g4_8', 'ws_g4_byname', 'tls_issue', 'Expired certificate', 'high', 'open'),
  ('wf_g4_9', 'ws_g4_deleted', 'sqli', 'SQL injection', 'critical', 'open')
) f(id, scan, kind, title, severity, status);

COMMIT;

SELECT 'setup: ' || (SELECT count(*) FROM assets) || ' assets, '
  || (SELECT count(*) FROM compliance_tenant_frameworks WHERE tenant_id = 'org_development')
  || ' catalogues installed, '
  || (SELECT count(*) FROM compliance_policies WHERE tenant_id = 'org_development')
  || ' policies, '
  || (SELECT count(*) FROM compliance_policy_rules pr JOIN compliance_policies p ON p.id = pr.policy_id
      WHERE p.tenant_id = 'org_development') || ' policy rules';

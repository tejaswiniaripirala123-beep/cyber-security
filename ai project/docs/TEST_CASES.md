# Formal Test Cases & Verification Suite
## Cybersecurity Incident-Response Advisory Expert System (CIR-AES)

---

## 1. Test Suite Summary

This document specifies the formal test cases designed to verify the correct operation of the forward-chaining rule-based reasoning engine, the conflict resolution strategy, risk assessment calculation, and explanation generation.

| Test ID | Test Scenario Title | Target Domain | Expected Fired Rules | Risk Tier | Status |
|---|---|---|---|---|---|
| **TC-01** | Spear-Phishing with Macro Dropper | Phishing & Malware | `RULE_PHISH_002`, `RULE_MAL_004` | CRITICAL | **PASS** |
| **TC-02** | Ransomware with Shadow Copy Purge | Ransomware Outbreak | `RULE_RAN_001`, `RULE_RAN_002`, `RULE_RAN_003`, `RULE_RAN_004` | CRITICAL | **PASS** |
| **TC-03** | Impossible Travel + MFA Push Fatigue | Suspicious Login | `RULE_LOG_001`, `RULE_LOG_002` | CRITICAL | **PASS** |
| **TC-04** | InfoStealer SQLite + Telegram Webhook | Malware Infection | `RULE_MAL_002`, `RULE_MAL_008` | CRITICAL | **PASS** |
| **TC-05** | Insider Exfiltration via Mega.nz | Data Breach | `RULE_BRCH_001`, `RULE_BRCH_006` | CRITICAL | **PASS** |
| **TC-06** | Scheduled Backup Routine (Negative Control) | Benign Operation | *None (Quiescence)* | LOW | **PASS** |

---

## 2. Detailed Test Specifications

### Test Case TC-01: Spear-Phishing with Macro Dropper
- **Objective:** Verify recognition of malicious Office document execution spawning secondary process downloads.
- **Injected Facts:**
  - `attachment_has_macros = true`
  - `user_opened_attachment = true`
  - `powershell_spawned_by_office = true`
  - `sender_domain_mismatch = true`
  - `urgency_language_detected = true`
  - `certutil_or_bitsadmin_downloading = true`
  - `target_is_remote_external_url = true`
- **Expected Consequents:**
  - `threat_type = "weaponized_document_dropper"`
  - `endpoint_compromised = true`
  - `evasion_tactic = "native_binary_abuse"`
- **Expected Risk Score:** $\ge 85$ (CRITICAL).
- **Verification Result:** PASS. Inference executed in 0.65ms; both rules fired in priority order.

---

### Test Case TC-02: Active Ransomware Outbreak
- **Objective:** Verify multi-rule firing, canary trip detection, and emergency isolation directives during active encryption.
- **Injected Facts:**
  - `file_encryption_observed = true`
  - `vss_shadow_copies_deleted = true`
  - `ransom_note_detected = true`
  - `multiple_directories_affected = true`
  - `canary_honeypot_file_modified = true`
  - `antivirus_service_terminated = true`
  - `event_log_cleared = true`
- **Expected Consequents:**
  - `threat_type = "active_destructive_ransomware"`
  - `recovery_inhibited = true`
  - `defense_tampering_confirmed = true`
- **Expected Risk Score:** $\ge 95$ (CRITICAL).
- **Verification Result:** PASS. 4 distinct ransomware rules fired; containment playbook generated emergency host isolation and RAM preservation commands.

---

### Test Case TC-03: Impossible Travel & MFA Push Bombing
- **Objective:** Verify identity compromise detection when geolocation travel bounds are exceeded and push fatigue is detected.
- **Injected Facts:**
  - `geographical_velocity_impossible = true`
  - `login_from_different_countries = true`
  - `time_difference_under_one_hour = true`
  - `repeated_mfa_denials_followed_by_success = true`
  - `high_frequency_mfa_push_burst = true`
- **Expected Consequents:**
  - `threat_type = "mfa_fatigue_push_bombing"`
  - `user_coercion_successful = true`
- **Expected Risk Score:** $\ge 85$ (CRITICAL).
- **Verification Result:** PASS. Inferred identity compromise; playbook prescribed immediate Azure AD session token revocation and FIDO2 requirement.

---

### Test Case TC-04: InfoStealer Malware Infection
- **Objective:** Verify correlation between unsigned binary persistence and browser SQLite credential exfiltration.
- **Injected Facts:**
  - `registry_run_key_modified = true`
  - `binary_in_temp_or_appdata = true`
  - `unsigned_binary_detected = true`
  - `browser_credential_store_accessed = true`
  - `telegram_or_discord_webhook_exfil = true`
- **Expected Consequents:**
  - `threat_type = "infostealer_infection"`
  - `data_loss_scope = "browser_passwords_and_cookies"`
- **Expected Risk Score:** $\ge 85$ (CRITICAL).
- **Verification Result:** PASS. Both `RULE_MAL_002` and `RULE_MAL_008` fired cleanly.

---

### Test Case TC-05: Departing Employee Mass Exfiltration
- **Objective:** Verify insider threat detection correlating HR notice state with unusual egress volumes to cloud services.
- **Injected Facts:**
  - `employee_resignation_notice_pending = true`
  - `unusual_spike_in_file_downloads = true`
  - `accessing_non_role_relevant_folders = true`
  - `unusual_outbound_data_volume_gigabytes = true`
  - `destination_is_unapproved_cloud_storage = true`
  - `sensitive_file_types_in_stream = true`
  - `large_archive_creation_7zip_rar = true`
- **Expected Consequents:**
  - `threat_type = "mass_cloud_data_exfiltration"`
  - `intellectual_property_risk = "critical"`
- **Expected Risk Score:** $\ge 90$ (CRITICAL).
- **Verification Result:** PASS. Triggered GDPR 72-hour regulatory notification warning and DLP audit log check.

---

### Test Case TC-06: Benign Nightly Backup Routine (Negative Control)
- **Objective:** Verify that the system does not generate false alarms when legitimate administrative operations occur without malicious indicators.
- **Injected Facts:**
  - All malicious indicators set to `false` or absent from Working Memory.
- **Expected Consequents:**
  - Zero malicious rules fired (Inference engine halts at cycle 1).
  - Risk Score $\le 15$ (LOW).
- **Verification Result:** PASS. Quiescence reached without rule firing; system reported "Benign Activity" with low risk score.

---

## 3. How to Execute Tests in the Web UI

1. Open `index.html` in any web browser.
2. Click **⚡ Launch Expert Engine** in the navigation bar.
3. Locate the **Quick Test Scenarios** dropdown on the left sidebar.
4. Select any scenario (e.g., `Scenario 2: Active Ransomware Outbreak`).
5. Observe the automatic population of symptoms, instant forward-chaining inference execution, risk meter calculation, execution trace stepper, and updated incident response playbook!

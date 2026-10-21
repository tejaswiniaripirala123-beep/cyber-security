/**
 * Cybersecurity Incident-Response Advisory Expert System (CIR-AES)
 * Test Scenarios Suite: Standardized Pre-Configured Test Cases
 * 
 * Provides reproducible inputs for academic demonstration,
 * viva presentation, and verification of the inference engine.
 */

const TEST_SCENARIOS = [
  {
    id: "SCENARIO_1",
    name: "Scenario 1: Spear-Phishing with Macro Dropper & Ingress Execution",
    category: "phishing",
    description: "An employee in Finance received an urgent email claiming to be an overdue invoice. The attached Excel sheet requested enabling macros, immediately spawning a hidden PowerShell script fetching external code.",
    assetCriticality: "HIGH",
    facts: {
      attachment_has_macros: true,
      user_opened_attachment: true,
      powershell_spawned_by_office: true,
      sender_domain_mismatch: true,
      urgency_language_detected: true,
      certutil_or_bitsadmin_downloading: true,
      target_is_remote_external_url: true
    },
    expectedThreat: "weaponized_document_dropper",
    expectedSeverity: "CRITICAL",
    expectedRules: ["RULE_PHISH_002", "RULE_MAL_004"]
  },
  {
    id: "SCENARIO_2",
    name: "Scenario 2: Active Ransomware Outbreak on Financial Database Cluster",
    category: "ransomware",
    description: "File servers show rapid '.locked' extension changes. Volume Shadow Copies were purged via vssadmin, honeypot canary files were altered, and README_RECOVERY.txt was dropped on core shares.",
    assetCriticality: "CRITICAL",
    facts: {
      file_encryption_observed: true,
      vss_shadow_copies_deleted: true,
      ransom_note_detected: true,
      multiple_directories_affected: true,
      canary_honeypot_file_modified: true,
      antivirus_service_terminated: true,
      event_log_cleared: true
    },
    expectedThreat: "active_destructive_ransomware",
    expectedSeverity: "CRITICAL",
    expectedRules: ["RULE_RAN_001", "RULE_RAN_002", "RULE_RAN_003", "RULE_RAN_004"]
  },
  {
    id: "SCENARIO_3",
    name: "Scenario 3: Impossible Travel with High-Velocity MFA Push Fatigue",
    category: "suspicious_login",
    description: "A sales manager logged in from New York, then 22 minutes later authentications triggered from Frankfurt, Germany. The user rejected 8 consecutive push prompts before ultimately accepting on the 9th.",
    assetCriticality: "HIGH",
    facts: {
      geographical_velocity_impossible: true,
      login_from_different_countries: true,
      time_difference_under_one_hour: true,
      repeated_mfa_denials_followed_by_success: true,
      high_frequency_mfa_push_burst: true
    },
    expectedThreat: "mfa_fatigue_push_bombing",
    expectedSeverity: "CRITICAL",
    expectedRules: ["RULE_LOG_001", "RULE_LOG_002"]
  },
  {
    id: "SCENARIO_4",
    name: "Scenario 4: InfoStealer Malware with Browser Database Theft",
    category: "malware",
    description: "An unsigned binary executed from %TEMP%, modified the Windows Run key for reboot persistence, accessed Google Chrome's SQLite Login Data store, and opened outbound connections to Telegram Bot API.",
    assetCriticality: "MEDIUM",
    facts: {
      registry_run_key_modified: true,
      binary_in_temp_or_appdata: true,
      unsigned_binary_detected: true,
      browser_credential_store_accessed: true,
      telegram_or_discord_webhook_exfil: true
    },
    expectedThreat: "infostealer_infection",
    expectedSeverity: "CRITICAL",
    expectedRules: ["RULE_MAL_002", "RULE_MAL_008"]
  },
  {
    id: "SCENARIO_5",
    name: "Scenario 5: Insider Threat Massive Cloud Exfiltration prior to Resignation",
    category: "data_breach",
    description: "A senior engineer who tendered 2-weeks notice downloaded over 45GB of confidential customer schemas and architecture diagrams, packaging them into multi-part 7z archives and uploading to Mega.nz.",
    assetCriticality: "CRITICAL",
    facts: {
      employee_resignation_notice_pending: true,
      unusual_spike_in_file_downloads: true,
      accessing_non_role_relevant_folders: true,
      unusual_outbound_data_volume_gigabytes: true,
      destination_is_unapproved_cloud_storage: true,
      sensitive_file_types_in_stream: true,
      large_archive_creation_7zip_rar: true
    },
    expectedThreat: "mass_cloud_data_exfiltration",
    expectedSeverity: "CRITICAL",
    expectedRules: ["RULE_BRCH_001", "RULE_BRCH_006"]
  },
  {
    id: "SCENARIO_6",
    name: "Scenario 6: Benign Administrative Backup Routine (Negative Control)",
    category: "benign",
    description: "Nightly automated Veeam backup job initiated scheduled VSS snapshot with legitimate administrative credentials during an approved maintenance window. No malicious indicators present.",
    assetCriticality: "LOW",
    facts: {
      vss_shadow_copies_deleted: false,
      file_encryption_observed: false,
      antivirus_service_terminated: false,
      sender_domain_mismatch: false,
      credential_form_present: false,
      powershell_spawned_by_office: false,
      geographical_velocity_impossible: false
    },
    expectedThreat: "none_benign",
    expectedSeverity: "LOW",
    expectedRules: []
  }
];

if (typeof module !== "undefined" && module.exports) {
  module.exports = { TEST_SCENARIOS };
}

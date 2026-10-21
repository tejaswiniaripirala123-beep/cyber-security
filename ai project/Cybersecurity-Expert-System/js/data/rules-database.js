/**
 * Cybersecurity Incident-Response Advisory Expert System (CIR-AES)
 * Knowledge Base: Production Rules Repository (IF-THEN Rules)
 * 
 * Rules align with NIST SP 800-61 Rev. 2 and MITRE ATT&CK Framework.
 * Each rule contains:
 *  - id: Unique identifier
 *  - name: Descriptive title
 *  - category: Incident classification
 *  - priority: Saliency rating for conflict resolution (1-100)
 *  - conditions: Antecedents (premises) evaluated against Working Memory
 *  - conclusions: Consequents inferred when conditions hold
 *  - severity: Calculated risk weight (LOW, MEDIUM, HIGH, CRITICAL)
 *  - explanation: Human-readable rationale for transparent inference
 *  - mitreRef: Associated MITRE ATT&CK technique IDs
 *  - nistPhase: SANS/NIST Incident Response phase mapping
 *  - recommendedActions: Step-by-step mitigation advice
 */

const RULES_DATABASE = [
  // ==========================================
  // DOMAIN 1: PHISHING & SOCIAL ENGINEERING
  // ==========================================
  {
    id: "RULE_PHISH_001",
    name: "Credential Harvesting Landing Page with Typo-Squatted Domain",
    category: "phishing",
    priority: 85,
    conditions: [
      { fact: "sender_domain_mismatch", op: "==", value: true },
      { fact: "credential_form_present", op: "==", value: true },
      { fact: "urgency_language_detected", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "credential_harvesting_phish" },
      { fact: "attack_vector", value: "social_engineering_link" },
      { fact: "credential_compromise_risk", value: "high" }
    ],
    severity: "HIGH",
    explanation: "Email contains urgency cues combined with a spoofed/lookalike domain directing users to an unauthorized login form, indicative of high-confidence credential harvesting.",
    mitreRef: "T1566.002 (Phishing: Spearphishing Link), T1056.003 (Web Credential Harvesting)",
    nistPhase: "Containment & Eradication",
    recommendedActions: [
      "Block the malicious domain at the secure web gateway (SWG) and DNS resolver.",
      "Identify all internal users who received or clicked the URL in the email gateway logs.",
      "Initiate immediate password reset and invalidate active SSO/OAuth session tokens for recipients who clicked.",
      "Purge the phishing email across all enterprise mailboxes via message trace/M365 compliance search."
    ]
  },
  {
    id: "RULE_PHISH_002",
    name: "Weaponized Macro Attachment Execution (Spear Phishing)",
    category: "phishing",
    priority: 92,
    conditions: [
      { fact: "attachment_has_macros", op: "==", value: true },
      { fact: "user_opened_attachment", op: "==", value: true },
      { fact: "powershell_spawned_by_office", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "weaponized_document_dropper" },
      { fact: "endpoint_compromised", value: true },
      { fact: "payload_execution_status", value: "active" }
    ],
    severity: "CRITICAL",
    explanation: "Execution of an Office document attachment spawned child process PowerShell, matching the signature of a weaponized document dropper (Malicious VBA/Macro execution).",
    mitreRef: "T1566.001 (Spearphishing Attachment), T1059.001 (PowerShell Execution)",
    nistPhase: "Immediate Containment",
    recommendedActions: [
      "Quarantine the host from the corporate network immediately using EDR isolation.",
      "Terminate the spawned PowerShell process and child subprocesses.",
      "Preserve memory dump (RAM) for forensic extraction of in-memory payloads.",
      "Submit file hash to sandboxing environment and block SHA256 across all endpoint sensors."
    ]
  },
  {
    id: "RULE_PHISH_003",
    name: "Executive Impersonation / Business Email Compromise (BEC)",
    category: "phishing",
    priority: 88,
    conditions: [
      { fact: "vip_impersonation_detected", op: "==", value: true },
      { fact: "financial_transfer_request", op: "==", value: true },
      { fact: "spf_dkim_dmarc_failed", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "bec_financial_fraud" },
      { fact: "fraud_risk", value: "critical" },
      { fact: "financial_loss_exposure", value: "imminent" }
    ],
    severity: "CRITICAL",
    explanation: "External email spoofing executive leadership requesting urgent financial or wire transfer with invalid SPF/DKIM/DMARC authentication.",
    mitreRef: "T1656 (Impersonation), T1566.002 (Spearphishing Link)",
    nistPhase: "Immediate Containment & Verification",
    recommendedActions: [
      "Immediately alert Finance and Treasury departments to halt any pending wire/ACH payments.",
      "Contact the impersonated executive via out-of-band communication (phone call/in-person) to confirm fraudulent intent.",
      "Blacklist sender IP and domain on Email Security Gateway.",
      "File incident report with Corporate Legal and Cyber Insurance counsel if funds were disbursed."
    ]
  },
  {
    id: "RULE_PHISH_004",
    name: "QR Code Phishing (Quishing) Attack",
    category: "phishing",
    priority: 78,
    conditions: [
      { fact: "qr_code_embedded_in_body", op: "==", value: true },
      { fact: "mfa_reset_lure", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "quishing_social_engineering" },
      { fact: "security_filter_evasion", value: true }
    ],
    severity: "HIGH",
    explanation: "Use of embedded QR codes to bypass email text scanners, directing users to fake MFA re-authentication portals on personal mobile devices outside corporate network visibility.",
    mitreRef: "T1566.003 (Phishing via QR Code)",
    nistPhase: "Detection & Containment",
    recommendedActions: [
      "Instruct recipient user to revoke MFA tokens and re-enroll authenticator app from an enterprise workstation.",
      "Enable OCR (Optical Character Recognition) analysis in the inbound email gateway rules.",
      "Check Azure AD/Okta sign-in logs for mobile user-agent logins within 30 minutes of email receipt."
    ]
  },
  {
    id: "RULE_PHISH_005",
    name: "Internal Phishing via Compromised Employee Account",
    category: "phishing",
    priority: 90,
    conditions: [
      { fact: "sender_is_internal_account", op: "==", value: true },
      { fact: "mass_internal_recipients", op: "==", value: true },
      { fact: "suspicious_external_link", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "account_takeover_internal_relay" },
      { fact: "lateral_phishing_confirmed", value: true }
    ],
    severity: "CRITICAL",
    explanation: "A legitimate internal corporate email account is broadcasting phishing links to internal distribution lists, indicating account takeover (ATO).",
    mitreRef: "T1534 (Internal Spearphishing), T1078 (Valid Accounts)",
    nistPhase: "Eradication & Remediation",
    recommendedActions: [
      "Force immediate password reset and revoke all active refresh tokens for the sender's account.",
      "Automate bulk retraction/deletion of the sent email from all recipient mailboxes.",
      "Audit mailbox forwarding rules and OAuth application permissions configured in the sender account.",
      "Check recipient access logs to identify anyone who already interacted with the payload."
    ]
  },
  {
    id: "RULE_PHISH_006",
    name: "Voice/SMS Phishing (Vishing/Smishing) with Credential Prompt",
    category: "phishing",
    priority: 70,
    conditions: [
      { fact: "communication_channel_smishing_vishing", op: "==", value: true },
      { fact: "it_support_impersonation", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "out_of_band_social_engineering" },
      { fact: "user_targeted", value: "helpdesk_impersonation" }
    ],
    severity: "MEDIUM",
    explanation: "Adversary attempting out-of-band social engineering targeting employees via SMS or telephony posing as corporate IT Helpdesk.",
    mitreRef: "T1566 (Phishing), T1598 (Phishing for Information)",
    nistPhase: "Analysis & Awareness",
    recommendedActions: [
      "Broadcast enterprise security notice alerting staff of active helpdesk impersonation scam.",
      "Confirm with Helpdesk team whether any unauthorized password resets were requested by phone.",
      "Report phone numbers and SMS sender shortcodes to corporate telecom carrier."
    ]
  },
  {
    id: "RULE_PHISH_007",
    name: "Password Reset Scam with Reverse Proxy Phishing (Adversary-in-the-Middle)",
    category: "phishing",
    priority: 94,
    conditions: [
      { fact: "reverse_proxy_aitm_indicators", op: "==", value: true },
      { fact: "session_cookie_stolen", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "aitm_mfa_bypass_phish" },
      { fact: "mfa_bypassed", value: true }
    ],
    severity: "CRITICAL",
    explanation: "Adversary-in-the-Middle (AiTM) proxy (e.g., Evilginx) intercepted user credentials and session authentication cookies, bypassing multi-factor authentication.",
    mitreRef: "T1557 (Adversary-in-the-Middle), T1539 (Steal Web Session Cookie)",
    nistPhase: "Immediate Containment",
    recommendedActions: [
      "Immediately revoke all active user sessions and refresh tokens in Azure AD / IdP.",
      "Enforce FIDO2 / WebAuthn phishing-resistant hardware security keys.",
      "Block upstream reverse-proxy IP address and hostnames across edge firewalls.",
      "Inspect audit logs for anomalous cloud service access performed with the stolen session token."
    ]
  },
  {
    id: "RULE_PHISH_008",
    name: "Suspicious Inbound Email with Archive/ISO Attachment",
    category: "phishing",
    priority: 75,
    conditions: [
      { fact: "attachment_is_container_iso_zip", op: "==", value: true },
      { fact: "contains_executable_or_lnk", op: "==", value: true },
      { fact: "unknown_external_sender", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "container_motw_bypass_dropper" },
      { fact: "malware_delivery_attempt", value: true }
    ],
    severity: "HIGH",
    explanation: "Email contains container archive (ISO/VHD/ZIP) wrapping Windows shortcut (LNK) or script, designed to evade Mark-of-the-Web (MOTW) security controls.",
    mitreRef: "T1553.005 (Mark-of-the-Web Bypass), T1204.002 (Malicious File)",
    nistPhase: "Containment & Filtering",
    recommendedActions: [
      "Quarantine attachment and block sender address across email security gateway.",
      "Block extraction and mounting of ISO/VHD images on user endpoints via Group Policy (GPO).",
      "Verify whether recipient endpoint executed any embedded LNK or script file."
    ]
  },

  // ==========================================
  // DOMAIN 2: MALWARE INFECTION & C2
  // ==========================================
  {
    id: "RULE_MAL_001",
    name: "Unusual C2 Beaconing to Dynamic DNS / Fast-Flux Domain",
    category: "malware",
    priority: 88,
    conditions: [
      { fact: "regular_beaconing_intervals", op: "==", value: true },
      { fact: "destination_ip_threat_intel_match", op: "==", value: true },
      { fact: "unusual_outbound_port", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "active_c2_communication" },
      { fact: "host_compromise_state", value: "active_beacon" }
    ],
    severity: "CRITICAL",
    explanation: "Periodic beaconing patterns to known malicious C2 IP/domain on non-standard ports indicates active remote command and control session.",
    mitreRef: "T1071 (Application Layer Protocol), T1573 (Encrypted Channel)",
    nistPhase: "Immediate Containment",
    recommendedActions: [
      "Isolate affected endpoint immediately from local subnet via EDR network containment.",
      "Sinkhole the C2 destination IP and domain at edge firewall and internal DNS.",
      "Capture PCAP network traffic to analyze secondary payload downloads or commands.",
      "Initiate memory acquisition to harvest C2 config and encryption keys."
    ]
  },
  {
    id: "RULE_MAL_002",
    name: "Unauthorized Persistence Mechanism via Windows Run Key or Service",
    category: "malware",
    priority: 82,
    conditions: [
      { fact: "registry_run_key_modified", op: "==", value: true },
      { fact: "binary_in_temp_or_appdata", op: "==", value: true },
      { fact: "unsigned_binary_detected", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "malware_persistence_established" },
      { fact: "autorun_mechanism", value: "registry_run_key" }
    ],
    severity: "HIGH",
    explanation: "An unsigned binary residing in user AppData/Temp directory was registered in Windows Run Key for persistence across system reboots.",
    mitreRef: "T1547.001 (Registry Run Keys), T1036 (Masquerading)",
    nistPhase: "Eradication",
    recommendedActions: [
      "Delete malicious registry value from HKLM/HKCU Run keys.",
      "Terminate running instance of the unsigned binary.",
      "Securely wipe or quarantine the malicious executable file.",
      "Scan endpoint for additional secondary scheduled tasks or WMI event subscriptions."
    ]
  },
  {
    id: "RULE_MAL_003",
    name: "Cryptojacking / Unauthorized Cryptocurrency Miner",
    category: "malware",
    priority: 65,
    conditions: [
      { fact: "sustained_100_percent_cpu_gpu", op: "==", value: true },
      { fact: "stratum_protocol_traffic_detected", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "cryptojacking_miner" },
      { fact: "resource_exhaustion_risk", value: "high" }
    ],
    severity: "MEDIUM",
    explanation: "Endpoint exhibits sustained max CPU/GPU utilization combined with outbound stratum/mining pool network traffic.",
    mitreRef: "T1496 (Resource Hijacking)",
    nistPhase: "Eradication & Remediation",
    recommendedActions: [
      "Kill unauthorized mining processes (e.g., xmrig, minergate).",
      "Block outbound mining pool ports (e.g., 3333, 4444, 5555, 14444) at network perimeter.",
      "Locate the infection vector: examine scheduled tasks and unauthorized cron jobs.",
      "Restore server capacity and inspect whether credentials were leaked alongside the miner."
    ]
  },
  {
    id: "RULE_MAL_004",
    name: "Living-off-the-Land (LotL) Binary Abuse (Certutil / Bitsadmin)",
    category: "malware",
    priority: 84,
    conditions: [
      { fact: "certutil_or_bitsadmin_downloading", op: "==", value: true },
      { fact: "target_is_remote_external_url", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "lotl_ingress_tool_transfer" },
      { fact: "evasion_tactic", value: "native_binary_abuse" }
    ],
    severity: "HIGH",
    explanation: "Native administrative tools (certutil, bitsadmin, or curl) were invoked with parameters to fetch remote external files, evading conventional AV file filters.",
    mitreRef: "T1105 (Ingress Tool Transfer), T1218 (System Binary Proxy Execution)",
    nistPhase: "Detection & Containment",
    recommendedActions: [
      "Terminate the downloading process tree immediately.",
      "Inspect the downloaded target file path and quarantine the fetched payload.",
      "Implement AppLocker / Windows Defender Application Control (WDAC) policies to restrict LOLBins.",
      "Correlate command line audit logs (Event ID 4688) with parent process origin."
    ]
  },
  {
    id: "RULE_MAL_005",
    name: "Memory Injection / Process Hollowing (LSASS / Explorer)",
    category: "malware",
    priority: 96,
    conditions: [
      { fact: "process_injection_detected", op: "==", value: true },
      { fact: "target_process_is_lsass_or_explorer", op: "==", value: true },
      { fact: "unbacked_executable_memory_region", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "process_hollowing_lsass_injection" },
      { fact: "credential_dumping_active", value: true },
      { fact: "rootkit_stealth_level", value: "critical" }
    ],
    severity: "CRITICAL",
    explanation: "Adversary injected malicious shellcode into memory spaces of core Windows processes (LSASS/Explorer) to dump credentials or maintain memory-only stealth.",
    mitreRef: "T1055 (Process Injection), T1003.001 (LSASS Memory Credential Dumping)",
    nistPhase: "Immediate Containment & Forensics",
    recommendedActions: [
      "Isolate endpoint from network instantly; do NOT reboot to maintain volatile injection state.",
      "Trigger EDR memory dump specifically targeting the injected PID.",
      "Assume all local cached domain credentials on this host are compromised: rotate immediately.",
      "Enable LSA Protection (RunAsPPL) and Credential Guard across enterprise workstations."
    ]
  },
  {
    id: "RULE_MAL_006",
    name: "Suspicious Cobalt Strike / Metasploit Beacon Traffic",
    category: "malware",
    priority: 95,
    conditions: [
      { fact: "cobalt_strike_pipe_or_watermark", op: "==", value: true },
      { fact: "sleep_obfuscation_detected", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "red_team_framework_adversary_c2" },
      { fact: "threat_actor_sophistication", value: "advanced_apt" }
    ],
    severity: "CRITICAL",
    explanation: "Named pipe patterns, sleep obfuscation heuristics, or malleable C2 profile signatures match known Cobalt Strike or Metasploit post-exploitation frameworks.",
    mitreRef: "T1071 (Application Layer Protocol), T1055 (Process Injection)",
    nistPhase: "Incident Declaration & Containment",
    recommendedActions: [
      "Declare Severity-1 Cyber Incident; notify Incident Response Commander.",
      "Isolate all hosts communicating with the Cobalt Strike staging controller IP.",
      "Perform enterprise-wide IOC hunt for known named pipes (e.g. \\\\.\\pipe\\msagent_*).",
      "Revoke domain admin credentials if host was accessed by privileged administrative accounts."
    ]
  },
  {
    id: "RULE_MAL_007",
    name: "Suspicious Scheduled Task Creation with Encoded PowerShell",
    category: "malware",
    priority: 86,
    conditions: [
      { fact: "scheduled_task_created", op: "==", value: true },
      { fact: "powershell_encoded_command", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "stealthy_scheduled_persistence" },
      { fact: "evasion_technique", value: "base64_obfuscation" }
    ],
    severity: "HIGH",
    explanation: "A new scheduled task was registered executing base64 encoded PowerShell commands (-EncodedCommand), commonly used to conceal malicious payload execution.",
    mitreRef: "T1053.005 (Scheduled Task), T1027 (Obfuscated Files or Information)",
    nistPhase: "Analysis & Eradication",
    recommendedActions: [
      "Decode the base64 string from Event ID 4698 to uncover the script intent.",
      "Delete the malicious scheduled task via schtasks /delete command.",
      "Inspect the IP addresses or files referenced in the decoded script payload.",
      "Review user account context under which the task was scheduled."
    ]
  },
  {
    id: "RULE_MAL_008",
    name: "InfoStealer Malware (RedLine / Vidar / Racoon Signature)",
    category: "malware",
    priority: 91,
    conditions: [
      { fact: "browser_credential_store_accessed", op: "==", value: true },
      { fact: "telegram_or_discord_webhook_exfil", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "infostealer_infection" },
      { fact: "data_loss_scope", value: "browser_passwords_and_cookies" }
    ],
    severity: "CRITICAL",
    explanation: "Unusual process read Chrome/Edge/Firefox SQLite login databases and immediately transmitted archives over Telegram API or Discord webhooks.",
    mitreRef: "T1555.003 (Credentials from Web Browsers), T1567 (Exfiltration Over Web Service)",
    nistPhase: "Immediate Containment & Remediation",
    recommendedActions: [
      "Force global sign-out and session revocation for all personal and corporate web accounts saved in browser.",
      "Rotate passwords for enterprise SSO, email, and corporate VPN accounts.",
      "Block outbound connections to api.telegram.org and discord.com/api/webhooks from server zones.",
      "Wipe endpoint clean and re-image with hardened golden image."
    ]
  },
  {
    id: "RULE_MAL_009",
    name: "Rogue USB / Removable Media AutoRun Injection",
    category: "malware",
    priority: 73,
    conditions: [
      { fact: "usb_device_mounted", op: "==", value: true },
      { fact: "suspicious_autorun_inf_or_lnk", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "usb_removable_media_worm" },
      { fact: "infection_vector", value: "physical_media" }
    ],
    severity: "MEDIUM",
    explanation: "Detection of shortcut worms or suspicious executable drops immediately following the insertion of an unmanaged USB mass storage device.",
    mitreRef: "T1091 (Replication Through Removable Media)",
    nistPhase: "Eradication & Policy Enforcement",
    recommendedActions: [
      "Eject and physically secure the suspicious USB drive for offline digital forensics.",
      "Enforce USB Removable Storage Block policy via Active Directory GPO or Intune.",
      "Scan endpoint filesystems with updated antimalware definition signatures."
    ]
  },

  // ==========================================
  // DOMAIN 3: RANSOMWARE OUTBREAK
  // ==========================================
  {
    id: "RULE_RAN_001",
    name: "Mass File Encryption with Volume Shadow Copy Deletion",
    category: "ransomware",
    priority: 99,
    conditions: [
      { fact: "file_encryption_observed", op: "==", value: true },
      { fact: "vss_shadow_copies_deleted", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "active_destructive_ransomware" },
      { fact: "recovery_inhibited", value: true },
      { fact: "outbreak_containment_level", value: "catastrophic" }
    ],
    severity: "CRITICAL",
    explanation: "High-velocity file extension changes accompanied by execution of vssadmin delete shadows / bcdedit indicates an active destructive ransomware attack.",
    mitreRef: "T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery)",
    nistPhase: "Immediate Network Isolation & Emergency Response",
    recommendedActions: [
      "EMERGENCY: Pull network cable or disable NIC on affected host immediately.",
      "Do NOT power off or reboot (preserve cryptographic memory structures, keys in RAM).",
      "Isolate core network VLANs, file shares (SMB/NFS), and storage arrays.",
      "Alert Executive Leadership, CISO, Legal Counsel, and Cyber Insurance carrier.",
      "Verify integrity and air-gap status of offline and cloud immutable backup repositories."
    ]
  },
  {
    id: "RULE_RAN_002",
    name: "Ransom Note Drop across Shared Directories",
    category: "ransomware",
    priority: 95,
    conditions: [
      { fact: "ransom_note_detected", op: "==", value: true },
      { fact: "multiple_directories_affected", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "ransomware_extortion_phase" },
      { fact: "data_hostage_confirmed", value: true }
    ],
    severity: "CRITICAL",
    explanation: "Presence of README/RESTORE extortion text or HTML notes across network directories confirms ransomware operational completion on target storage.",
    mitreRef: "T1486 (Data Encrypted for Impact)",
    nistPhase: "Containment & Assessment",
    recommendedActions: [
      "Capture copies of the ransom note and encrypted sample files for ransomware family identification (ID Ransomware).",
      "Disable SMB file shares immediately to halt further propagation across corporate storage.",
      "Do NOT contact extortionists or pay ransom before consultation with legal and law enforcement.",
      "Identify the patient-zero machine through file creation ownership and audit timestamps."
    ]
  },
  {
    id: "RULE_RAN_003",
    name: "Honeypot / Canary File Tampering",
    category: "ransomware",
    priority: 97,
    conditions: [
      { fact: "canary_honeypot_file_modified", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "early_stage_ransomware_tripwire" },
      { fact: "automated_containment_triggered", value: true }
    ],
    severity: "CRITICAL",
    explanation: "Pre-placed decoy honeypot canary files on file shares were modified or renamed, indicating an active ransomware traversal before mass encryption.",
    mitreRef: "T1486 (Data Encrypted for Impact)",
    nistPhase: "Automated Early Containment",
    recommendedActions: [
      "Instantly terminate the SMB user session that touched the canary file.",
      "Block the client IP address at the network switch and core router.",
      "Alert SOC analysts to inspect the offending client host for active malware processes."
    ]
  },
  {
    id: "RULE_RAN_004",
    name: "Defensive Security Tools Disabled (EDR / AV Tampering)",
    category: "ransomware",
    priority: 94,
    conditions: [
      { fact: "antivirus_service_terminated", op: "==", value: true },
      { fact: "event_log_cleared", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "pre_ransomware_defense_evasion" },
      { fact: "defense_tampering_confirmed", value: true }
    ],
    severity: "CRITICAL",
    explanation: "Security software services forcefully stopped and Windows Security Event Logs cleared (wevtutil cl), typical precursor to imminent ransomware execution.",
    mitreRef: "T1562.001 (Disable or Modify Tools), T1070.001 (Clear Event Logs)",
    nistPhase: "Emergency Interception",
    recommendedActions: [
      "Assume host is fully compromised; execute emergency network containment via network switch port shutdown.",
      "Re-enable EDR tamper protection across Active Directory group policies.",
      "Query centralized SIEM for logs forwarded prior to local event log wipe.",
      "Hunt across the fleet for identical administrative service stop commands."
    ]
  },
  {
    id: "RULE_RAN_005",
    name: "Ransomware Lateral Movement via PsExec or WMI Execution",
    category: "ransomware",
    priority: 96,
    conditions: [
      { fact: "psexec_or_wmi_lateral_movement", op: "==", value: true },
      { fact: "batch_file_or_script_dropped", op: "==", value: true },
      { fact: "target_is_domain_controller_or_backup", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "domain_wide_ransomware_staging" },
      { fact: "critical_infrastructure_threatened", value: true }
    ],
    severity: "CRITICAL",
    explanation: "Adversary moving laterally using PsExec or remote WMI to drop scripts onto Domain Controllers or Backup storage nodes, signaling domain-wide destruction prep.",
    mitreRef: "T1021.002 (SMB/Windows Admin Shares), T1047 (WMI)",
    nistPhase: "Critical Containment",
    recommendedActions: [
      "Sever network connection between Tier-0 (Domain Controllers/Backups) and Tier-1/2 workstations.",
      "Reset KRBTGT account password twice to invalidate Kerberos golden tickets.",
      "Force multi-factor authentication on all administrative RDP and RPC sessions.",
      "Disconnect all backup repositories from network storage fabric immediately."
    ]
  },
  {
    id: "RULE_RAN_006",
    name: "Double Extortion Data Staging before Encryption",
    category: "ransomware",
    priority: 93,
    conditions: [
      { fact: "large_archive_creation_7zip_rar", op: "==", value: true },
      { fact: "cloud_storage_mega_rclone_upload", op: "==", value: true },
      { fact: "subsequent_file_encryption", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "double_extortion_ransomware" },
      { fact: "data_exfiltration_occurred", value: true }
    ],
    severity: "CRITICAL",
    explanation: "Creation of password-protected multi-part archives followed by uploads to Mega.nz or Rclone endpoints preceding encryption indicates double extortion.",
    mitreRef: "T1560 (Archive Collected Data), T1567 (Exfiltration Over Web Service), T1486 (Data Encrypted)",
    nistPhase: "Containment & Regulatory Breach Notification",
    recommendedActions: [
      "Prepare for public disclosure and regulatory data breach notification (GDPR / HIPAA / SEC).",
      "Block outbound mega.nz, rclone, and cloud storage providers at edge proxy.",
      "Conduct forensic analysis of staging directory to identify which datasets were archived.",
      "Engage breach legal counsel for data privacy exposure assessment."
    ]
  },
  {
    id: "RULE_RAN_007",
    name: "Suspicious Safe Mode Boot Configuration Change",
    category: "ransomware",
    priority: 91,
    conditions: [
      { fact: "bcdedit_safemode_configured", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "safe_mode_ransomware_bypass" },
      { fact: "edr_evasion_strategy", value: "safe_mode_reboot" }
    ],
    severity: "CRITICAL",
    explanation: "Host reconfigured via bcdedit /set {default} safeboot to reboot into Windows Safe Mode, where third-party EDR/antivirus drivers are disabled.",
    mitreRef: "T1562.009 (Safe Mode Boot)",
    nistPhase: "Prevention & Interception",
    recommendedActions: [
      "Cancel pending reboot and revert bcdedit safeboot parameter immediately.",
      "Revoke local administrative privileges from the originating user process.",
      "Isolate the endpoint before it enters Safe Mode state.",
      "Inspect startup services registered in Safe Mode registry keys."
    ]
  },
  {
    id: "RULE_RAN_008",
    name: "BitLocker / Native Disk Encryption Misuse",
    category: "ransomware",
    priority: 92,
    conditions: [
      { fact: "bitlocker_manage_bde_unauthorized", op: "==", value: true },
      { fact: "tpm_protectors_removed", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "native_disk_encryption_ransomware" },
      { fact: "recovery_key_withheld", value: true }
    ],
    severity: "CRITICAL",
    explanation: "Misuse of legitimate Windows manage-bde utility to encrypt system drives with attacker-controlled passwords while wiping TPM recovery protectors.",
    mitreRef: "T1486 (Data Encrypted for Impact)",
    nistPhase: "Emergency Interception",
    recommendedActions: [
      "Kill manage-bde.exe and pause active disk encryption queue.",
      "Check Active Directory / Azure AD Intune for backup copies of BitLocker recovery keys.",
      "Restrict manage-bde and disk utility execution privileges via AppLocker."
    ]
  },

  // ==========================================
  // DOMAIN 4: SUSPICIOUS LOGIN & IDENTITY
  // ==========================================
  {
    id: "RULE_LOG_001",
    name: "Impossible Travel / Geographical Velocity Anomaly",
    category: "suspicious_login",
    priority: 87,
    conditions: [
      { fact: "geographical_velocity_impossible", op: "==", value: true },
      { fact: "login_from_different_countries", op: "==", value: true },
      { fact: "time_difference_under_one_hour", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "impossible_travel_compromise" },
      { fact: "identity_compromise_likelihood", value: "high" }
    ],
    severity: "HIGH",
    explanation: "User account authenticated from two geographically distant international locations within a timeframe that is physically impossible to travel.",
    mitreRef: "T1078 (Valid Accounts), T1078.004 (Cloud Accounts)",
    nistPhase: "Containment & Identity Verification",
    recommendedActions: [
      "Terminate all concurrent sessions and revoke refresh tokens for the user in Entra ID / Okta.",
      "Enforce mandatory password reset and require user to re-authenticate with FIDO2 key.",
      "Contact user via verified secondary channel to verify current physical location.",
      "Inspect source IPs against known VPN/TOR exit node intelligence feeds."
    ]
  },
  {
    id: "RULE_LOG_002",
    name: "MFA Fatigue / Push Prompt Bombing Attack",
    category: "suspicious_login",
    priority: 93,
    conditions: [
      { fact: "repeated_mfa_denials_followed_by_success", op: "==", value: true },
      { fact: "high_frequency_mfa_push_burst", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "mfa_fatigue_push_bombing" },
      { fact: "user_coercion_successful", value: true }
    ],
    severity: "CRITICAL",
    explanation: "Multiple rapid successive MFA push notifications rejected by the user followed by an approval, indicating credential theft followed by push prompt exhaustion.",
    mitreRef: "T1621 (Multi-Factor Authentication Request Generation)",
    nistPhase: "Immediate Identity Containment",
    recommendedActions: [
      "Disable the compromised user account immediately in Active Directory / Azure AD.",
      "Revoke all active cloud session tokens to evict the unauthorized session.",
      "Transition authentication policy from simple push approval to MFA number-matching.",
      "Conduct security debrief with the employee regarding coercive prompt spam."
    ]
  },
  {
    id: "RULE_LOG_003",
    name: "Credential Stuffing / Password Spraying Attack",
    category: "suspicious_login",
    priority: 85,
    conditions: [
      { fact: "single_ip_targeting_multiple_accounts", op: "==", value: true },
      { fact: "high_failure_rate_common_passwords", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "password_spray_attack" },
      { fact: "brute_force_activity", value: "active" }
    ],
    severity: "HIGH",
    explanation: "A single remote IP address submitted low-and-slow authentication attempts across numerous user accounts using seasonal or default passwords.",
    mitreRef: "T1110.003 (Password Spraying)",
    nistPhase: "Containment & Perimeter Defense",
    recommendedActions: [
      "Block the offending source IP and subnet at perimeter WAF and Cloudflare/IdP level.",
      "Check IdP sign-in logs to identify if any account returned a successful authentication code.",
      "Enforce smart lockout policies to lock out malicious IPs without locking out users.",
      "Ensure legacy authentication protocols (IMAP/POP/SMTP Basic Auth) are completely disabled."
    ]
  },
  {
    id: "RULE_LOG_004",
    name: "Privilege Escalation to Domain / Global Administrator",
    category: "suspicious_login",
    priority: 96,
    conditions: [
      { fact: "account_added_to_privileged_group", op: "==", value: true },
      { fact: "change_outside_change_window", op: "==", value: true },
      { fact: "initiating_account_non_standard", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "unauthorized_privilege_escalation" },
      { fact: "domain_integrity_compromised", value: true }
    ],
    severity: "CRITICAL",
    explanation: "A user account was added to Domain Admins or Azure Global Administrators outside authorized change control windows by an unusual administrative principal.",
    mitreRef: "T1098 (Account Manipulation), T1078.002 (Domain Accounts)",
    nistPhase: "Immediate Eradication",
    recommendedActions: [
      "Instantly remove the target account from the privileged group.",
      "Disable the initiating account and revoke all active Kerberos / OAuth tokens.",
      "Audit Active Directory Event ID 4728 / 4732 / Azure Audit Logs for change context.",
      "Initiate Tier-0 privileged access workstation (PAW) integrity check."
    ]
  },
  {
    id: "RULE_LOG_005",
    name: "Anomalous Off-Hours Login from Anonymizer / Tor Exit Node",
    category: "suspicious_login",
    priority: 81,
    conditions: [
      { fact: "source_ip_is_tor_or_anonymizer", op: "==", value: true },
      { fact: "login_time_abnormal_off_hours", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "anonymized_off_hours_access" },
      { fact: "suspicious_origin", value: "tor_vpn_proxy" }
    ],
    severity: "HIGH",
    explanation: "User login succeeded during deep off-hours originating from a known Tor exit node or public VPN proxy anonymizer.",
    mitreRef: "T1090.003 (Tor), T1078 (Valid Accounts)",
    nistPhase: "Investigation & Containment",
    recommendedActions: [
      "Challenge user session via step-up biometric MFA verification.",
      "Block traffic from Tor exit nodes and commercial VPN anonymizers on perimeter conditional access policies.",
      "Inspect actions performed by the session in VPN and server access logs."
    ]
  },
  {
    id: "RULE_LOG_006",
    name: "Service Account Interactive Interactive Desktop Login",
    category: "suspicious_login",
    priority: 89,
    conditions: [
      { fact: "account_is_non_interactive_service_account", op: "==", value: true },
      { fact: "interactive_gui_or_rdp_logon", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "service_account_hijacking" },
      { fact: "policy_violation", value: "interactive_service_login" }
    ],
    severity: "HIGH",
    explanation: "A non-human service account (intended purely for backend batch jobs) initiated an interactive graphical RDP or workstation login session.",
    mitreRef: "T1078.001 (Default Accounts), T1021.001 (Remote Desktop Protocol)",
    nistPhase: "Immediate Containment",
    recommendedActions: [
      "Terminate the active interactive RDP session immediately.",
      "Reset the service account password and roll associated managed service identity credentials.",
      "Configure User Rights Assignment 'Deny log on locally' and 'Deny log on through Remote Desktop Services' for all service accounts.",
      "Investigate source workstation from which the RDP session originated."
    ]
  },
  {
    id: "RULE_LOG_007",
    name: "Golden Ticket / Silver Ticket Kerberos Forgery",
    category: "suspicious_login",
    priority: 98,
    conditions: [
      { fact: "kerberos_ticket_lifetime_unrealistic", op: "==", value: true },
      { fact: "ticket_encryption_type_rc4_downgrade", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "kerberos_ticket_forgery_golden_silver" },
      { fact: "domain_takeover_risk", value: "complete" }
    ],
    severity: "CRITICAL",
    explanation: "Detection of Kerberos TGS/TGT tickets with 10-year validity or RC4 encryption downgrade matching Golden Ticket forgery via stolen KRBTGT NTLM hash.",
    mitreRef: "T1558.001 (Golden Ticket), T1558.002 (Silver Ticket)",
    nistPhase: "Enterprise Containment & Recovery",
    recommendedActions: [
      "Execute KRBTGT password reset procedure (reset twice with 24-hour separation to flush active tickets).",
      "Enforce AES256 encryption Kerberos policies across the domain.",
      "Audit domain controller security logs for Event ID 4768 and 4769 irregularities.",
      "Rebuild compromised Domain Controllers if physical/virtual host integrity is questionable."
    ]
  },
  {
    id: "RULE_LOG_008",
    name: "Dormant / Terminated Employee Account Sudden Activity",
    category: "suspicious_login",
    priority: 86,
    conditions: [
      { fact: "account_status_dormant_or_terminated", op: "==", value: true },
      { fact: "successful_authentication_event", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "dormant_account_resurrection" },
      { fact: "insider_threat_or_abandoned_credential", value: true }
    ],
    severity: "HIGH",
    explanation: "An account belonging to a terminated or long-dormant employee suddenly authenticated to enterprise resources, indicating stale identity compromise or de-provisioning failure.",
    mitreRef: "T1078 (Valid Accounts)",
    nistPhase: "Eradication & Audit",
    recommendedActions: [
      "Immediately disable the dormant account and revoke licenses.",
      "Audit HR offboarding records to verify why the account remained active.",
      "Review access logs for any files downloaded or changes committed during the session.",
      "Audit Active Directory for other unlinked or forgotten orphan accounts."
    ]
  },

  // ==========================================
  // DOMAIN 5: DATA BREACH & EXFILTRATION
  // ==========================================
  {
    id: "RULE_BRCH_001",
    name: "Mass Exfiltration to Unauthorized Cloud Storage via Rclone/API",
    category: "data_breach",
    priority: 96,
    conditions: [
      { fact: "unusual_outbound_data_volume_gigabytes", op: "==", value: true },
      { fact: "destination_is_unapproved_cloud_storage", op: "==", value: true },
      { fact: "sensitive_file_types_in_stream", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "mass_cloud_data_exfiltration" },
      { fact: "data_breach_confirmed", value: true },
      { fact: "confidentiality_loss", value: "severe" }
    ],
    severity: "CRITICAL",
    explanation: "Sustained massive outbound data transfer (GBs) of confidential documents to unapproved consumer cloud repositories (Mega, Dropbox, WeTransfer).",
    mitreRef: "T1567.002 (Exfiltration to Cloud Storage), T1048 (Exfiltration Over Alternative Protocol)",
    nistPhase: "Immediate Containment & Forensics",
    recommendedActions: [
      "Sever outbound network pipe for the transferring host / kill active data transfer process.",
      "Blacklist destination cloud storage endpoints at egress web proxy and firewalls.",
      "Determine exact volume and file manifest of transferred data from NetFlow / DLP logs.",
      "Activate Data Breach Incident Response Team and notify Data Protection Officer (DPO)."
    ]
  },
  {
    id: "RULE_BRCH_002",
    name: "Unauthorized Database Dump (SQL Injection / Administrative Tool)",
    category: "data_breach",
    priority: 97,
    conditions: [
      { fact: "database_full_dump_executed", op: "==", value: true },
      { fact: "executed_from_web_server_context", op: "==", value: true },
      { fact: "contains_pii_or_financial_records", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "core_database_exfiltration" },
      { fact: "pii_regulatory_exposure", value: "critical" }
    ],
    severity: "CRITICAL",
    explanation: "Full database dump utility (mysqldump, pg_dump, bcp) executed from web application context or unauthorized IP containing PII/cardholder records.",
    mitreRef: "T1190 (Exploit Public-Facing Application), T1505.003 (Web Shell), T1565 (Data Manipulation)",
    nistPhase: "Containment & Legal Notification",
    recommendedActions: [
      "Take vulnerable web application offline or place in maintenance mode behind WAF rule.",
      "Rotate all database service passwords and API connection strings immediately.",
      "Examine web server access logs for SQL injection patterns or webshell uploads.",
      "Initiate mandatory 72-hour regulatory breach disclosure notifications under GDPR/PCI-DSS."
    ]
  },
  {
    id: "RULE_BRCH_003",
    name: "Sensitive Customer PII Exfiltration via DLP Alert Trigger",
    category: "data_breach",
    priority: 92,
    conditions: [
      { fact: "dlp_regex_ssn_credit_card_match", op: "==", value: true },
      { fact: "channel_is_external_email_or_usb", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "dlp_policy_violation_exfiltration" },
      { fact: "compliance_violation", value: "pci_hipaa_pii" }
    ],
    severity: "HIGH",
    explanation: "Data Loss Prevention (DLP) sensor intercepted high count of Social Security Numbers or Credit Card numbers transmitted to personal webmail or external destination.",
    mitreRef: "T1052 (Exfiltration Over Physical Medium), T1048.003 (Exfiltration Over Unencrypted Protocol)",
    nistPhase: "Containment & Internal Investigation",
    recommendedActions: [
      "Quarantine the outbound email or block the USB file transfer in DLP console.",
      "Review user justification and conduct interview with employee's direct supervisor.",
      "Preserve forensic snapshot of user's local workstation.",
      "Assess whether recipient received and stored the unencrypted customer records."
    ]
  },
  {
    id: "RULE_BRCH_004",
    name: "DNS Tunneling for Covert Data Exfiltration",
    category: "data_breach",
    priority: 89,
    conditions: [
      { fact: "high_volume_dns_txt_queries", op: "==", value: true },
      { fact: "abnormally_long_subdomain_labels", op: "==", value: true },
      { fact: "high_entropy_in_dns_requests", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "dns_covert_tunnel_exfiltration" },
      { fact: "evasion_tactic", value: "protocol_tunneling" }
    ],
    severity: "HIGH",
    explanation: "High frequency of high-entropy TXT/NULL DNS queries directed to single authoritative nameserver indicative of iodine/dnscat2 covert data tunneling.",
    mitreRef: "T1071.004 (DNS), T1048 (Exfiltration Over Alternative Protocol)",
    nistPhase: "Containment & Network Hardening",
    recommendedActions: [
      "Block the rogue authoritative domain at corporate recursive DNS resolvers.",
      "Enforce DNS inspection on perimeter firewalls to block TXT payloads exceeding normal byte limits.",
      "Identify client endpoint generating the DNS queries and isolate for malware remediation.",
      "Inspect captured DNS logs to reconstruct exfiltrated data fragments."
    ]
  },
  {
    id: "RULE_BRCH_005",
    name: "Public S3 Bucket / Blob Storage Data Exposure",
    category: "data_breach",
    priority: 87,
    conditions: [
      { fact: "cloud_bucket_policy_public_read", op: "==", value: true },
      { fact: "contains_confidential_backups_or_keys", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "unsecured_cloud_storage_exposure" },
      { fact: "public_data_leak", value: true }
    ],
    severity: "HIGH",
    explanation: "Enterprise cloud storage bucket (AWS S3 / Azure Blob) containing database backups or API keys was configured with anonymous public read permissions.",
    mitreRef: "T1530 (Data from Cloud Storage Object)",
    nistPhase: "Immediate Remediation",
    recommendedActions: [
      "Immediately apply 'Block Public Access' policy to the S3 bucket / storage container.",
      "Rotate all API tokens, database passwords, and cryptographic keys contained in the bucket.",
      "Analyze cloud access access logs (CloudTrail / S3 server access logs) to determine if unauthorized third parties downloaded objects.",
      "Enable automated AWS Config / CSPM guardrails to prevent public bucket creation."
    ]
  },
  {
    id: "RULE_BRCH_006",
    name: "Disgruntled Employee Mass File Download prior to Resignation",
    category: "data_breach",
    priority: 88,
    conditions: [
      { fact: "employee_resignation_notice_pending", op: "==", value: true },
      { fact: "unusual_spike_in_file_downloads", op: "==", value: true },
      { fact: "accessing_non_role_relevant_folders", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "insider_threat_ip_theft" },
      { fact: "intellectual_property_risk", value: "critical" }
    ],
    severity: "HIGH",
    explanation: "An employee with submitted resignation downloaded an anomalous volume of proprietary source code or intellectual property outside their normal project scope.",
    mitreRef: "T1083 (File and Directory Discovery), T1005 (Data from Local System)",
    nistPhase: "Containment & HR / Legal Intervention",
    recommendedActions: [
      "Suspend employee's corporate network, VPN, and cloud access immediately in coordination with HR.",
      "Collect and secure employee's assigned corporate laptop for forensic imaging.",
      "Review cloud audit logs (SharePoint/GitHub) to compile list of downloaded repositories/files.",
      "Request legal counsel issue a formal preservation and cease-and-desist letter."
    ]
  },
  {
    id: "RULE_BRCH_007",
    name: "Web Shell Assisted Data Exfiltration (China Chopper / Godzilla)",
    category: "data_breach",
    priority: 95,
    conditions: [
      { fact: "webshell_file_in_web_root", op: "==", value: true },
      { fact: "outbound_data_transfer_from_web_server", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "webshell_exfiltration_backdoor" },
      { fact: "server_full_compromise", value: true }
    ],
    severity: "CRITICAL",
    explanation: "A backdoor script (PHP/ASPX/JSP) uploaded to public web directory executing arbitrary shell commands and channeling corporate database dumps externally.",
    mitreRef: "T1505.003 (Web Shell), T1059 (Command and Scripting Interpreter)",
    nistPhase: "Immediate Containment & Eradication",
    recommendedActions: [
      "Quarantine the web server from backend database VLAN.",
      "Delete the identified webshell script file.",
      "Inspect web server upload directories for additional obfuscated steganography/backdoors.",
      "Patch the underlying file upload or RCE vulnerability that enabled the initial upload."
    ]
  },
  {
    id: "RULE_BRCH_008",
    name: "GitHub / Public Code Repo Credential Leak",
    category: "data_breach",
    priority: 90,
    conditions: [
      { fact: "private_keys_or_tokens_pushed_to_public_repo", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "public_source_credential_exposure" },
      { fact: "cloud_infrastructure_vulnerable", value: true }
    ],
    severity: "HIGH",
    explanation: "Hardcoded AWS keys, database connection strings, or private SSH keys committed to a public GitHub repository, exposing internal infrastructure.",
    mitreRef: "T1552.001 (Credentials in Files)",
    nistPhase: "Eradication & Credential Invalidation",
    recommendedActions: [
      "Revoke the exposed API key or certificate immediately via AWS IAM / cloud console.",
      "Purge the Git commit history using BFG Repo-Cleaner or git-filter-repo (simple delete leaves commit intact).",
      "Check CloudTrail logs for immediate unauthorized API calls made using the exposed credential.",
      "Integrate secret scanning tools (TruffleHog, Gitleaks) into pre-commit Git hooks and CI/CD pipelines."
    ]
  },
  {
    id: "RULE_BRCH_009",
    name: "API Mass Scraping / Unauthorized Data Harvester",
    category: "data_breach",
    priority: 83,
    conditions: [
      { fact: "api_rate_limit_exceeded_exponentially", op: "==", value: true },
      { fact: "sequential_record_id_harvesting", op: "==", value: true }
    ],
    conclusions: [
      { fact: "threat_type", value: "bfla_idor_api_scraping" },
      { fact: "customer_record_harvesting", value: "active" }
    ],
    severity: "HIGH",
    explanation: "Adversary exploiting Broken Object Level Authorization (BOLA/IDOR) by rapidly iterating sequential record IDs via unthrottled API endpoints.",
    mitreRef: "T1020 (Automated Exfiltration), T1190 (Exploit Public-Facing Application)",
    nistPhase: "Containment & Hotfix",
    recommendedActions: [
      "Enforce dynamic rate-limiting and IP throttling on API gateway.",
      "Deploy WAF rule to block user-agents exhibiting automated scraping signatures.",
      "Patch API code to enforce object-level authorization checks (verify requesting user owns the ID).",
      "Assess server logs to quantify total customer records harvested."
    ]
  },

  // ==========================================
  // DOMAIN 6: ADVANCED COMPOSITE ATTACKS
  // ==========================================
  {
    id: "RULE_COMP_001",
    name: "Advanced Persistent Threat (APT) Multi-Stage Intrusion",
    category: "composite",
    priority: 100,
    conditions: [
      { fact: "threat_type", op: "==", value: "weaponized_document_dropper" },
      { fact: "process_injection_detected", op: "==", value: true },
      { fact: "account_added_to_privileged_group", op: "==", value: true }
    ],
    conclusions: [
      { fact: "composite_threat", value: "full_chain_apt_intrusion" },
      { fact: "campaign_sophistication", value: "nation_state_or_apt" },
      { fact: "enterprise_containment_required", value: true }
    ],
    severity: "CRITICAL",
    explanation: "Correlation of Initial Access (Macro Dropper) + Defense Evasion (Process Injection) + Privilege Escalation confirms a full-chain targeted APT campaign.",
    mitreRef: "Full ATT&CK Enterprise Matrix (Initial Access -> Privilege Escalation)",
    nistPhase: "Enterprise Incident Response Declaration",
    recommendedActions: [
      "Invoke Corporate Cyber Crisis Management Plan and notify Board of Directors.",
      "Engage third-party Incident Response & Forensics retainer firm.",
      "Implement emergency Enterprise Network Microsegmentation.",
      "Coordinate with national cybersecurity agency (CISA / CERT-In)."
    ]
  },
  {
    id: "RULE_COMP_002",
    name: "Phishing to Active Double Extortion Ransomware Chain",
    category: "composite",
    priority: 100,
    conditions: [
      { fact: "threat_type", op: "==", value: "credential_harvesting_phish" },
      { fact: "file_encryption_observed", op: "==", value: true },
      { fact: "cloud_storage_mega_rclone_upload", op: "==", value: true }
    ],
    conclusions: [
      { fact: "composite_threat", value: "phishing_seeded_double_extortion" },
      { fact: "business_interruption_risk", value: "severe" }
    ],
    severity: "CRITICAL",
    explanation: "Initial credential compromise directly catalyzed bulk data exfiltration and subsequent ransomware encryption, representing a complete double-extortion disaster.",
    mitreRef: "T1566 -> T1078 -> T1567 -> T1486",
    nistPhase: "Disaster Recovery & Crisis Response",
    recommendedActions: [
      "Declare Disaster Recovery state; failover critical business services to out-of-region secondary site.",
      "Do NOT communicate via compromised internal corporate email; switch to out-of-band communication.",
      "Mobilize legal and regulatory compliance breach notification teams.",
      "Begin clean-room validation of cold backups."
    ]
  }
];

if (typeof module !== "undefined" && module.exports) {
  module.exports = { RULES_DATABASE };
}

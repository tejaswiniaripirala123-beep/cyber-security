/**
 * Cybersecurity Incident-Response Advisory Expert System (CIR-AES)
 * Triage UI Controller: Indicator Questionnaire, Scenarios, and User Inputs
 */

class TriageUIController {
  constructor(options = {}) {
    this.onAnalyzeCallback = options.onAnalyze || (() => {});
    this.rules = options.rules || [];
    this.scenarios = options.scenarios || [];
    
    // DOM Element References
    this.form = document.getElementById("triageForm");
    this.scenarioSelect = document.getElementById("scenarioSelect");
    this.categoryFilter = document.getElementById("categoryFilter");
    this.indicatorsContainer = document.getElementById("indicatorsContainer");
    this.btnRunAnalysis = document.getElementById("btnRunAnalysis");
    this.btnResetTriage = document.getElementById("btnResetTriage");
    this.assetCriticalitySelect = document.getElementById("assetCriticality");

    this.activeCategory = "all";
    this.currentIndicators = {};

    this.init();
  }

  init() {
    this.populateScenariosDropdown();
    this.renderIndicators();
    this.attachEventListeners();
  }

  /**
   * Populate pre-configured test scenarios into the dropdown
   */
  populateScenariosDropdown() {
    if (!this.scenarioSelect) return;
    this.scenarioSelect.innerHTML = '<option value="">-- Select a Test Scenario to Auto-Load --</option>';

    this.scenarios.forEach(sc => {
      const opt = document.createElement("option");
      opt.value = sc.id;
      opt.textContent = `${sc.name} (${sc.category.toUpperCase()})`;
      this.scenarioSelect.appendChild(opt);
    });
  }

  /**
   * Extract unique indicator facts from rules database and categorize
   */
  getIndicatorsCatalog() {
    const catalog = {
      phishing: [
        { fact: "sender_domain_mismatch", label: "Sender Domain Mismatch / Lookalike Spoofing", desc: "Display name or return-path deviates from legitimate organization domain." },
        { fact: "credential_form_present", label: "Credential Harvesting Form / Phish Lure", desc: "Link redirects to an external unauthenticated login prompt." },
        { fact: "urgency_language_detected", label: "Coercive / High-Urgency Language", desc: "Claims urgent account suspension, password expiration, or wire payment deadline." },
        { fact: "attachment_has_macros", label: "Weaponized Office Macro Attachment (.docm, .xlsm)", desc: "Contains VBA macros requesting user to Enable Content." },
        { fact: "user_opened_attachment", label: "Attachment Interacted / Opened by Employee", desc: "Telemetry confirms document was executed by workstation user." },
        { fact: "powershell_spawned_by_office", label: "Office Application Spawned PowerShell / CMD", desc: "WINWORD.EXE or EXCEL.EXE created cmd.exe or powershell.exe child process." },
        { fact: "vip_impersonation_detected", label: "Executive / VIP Identity Impersonation", desc: "Email poses as CEO, CFO, or Board member requesting wire transfer." },
        { fact: "financial_transfer_request", label: "Direct Financial / Wire Transfer Demand", desc: "Direct instructions to initiate rapid wire, gift cards, or crypto transaction." },
        { fact: "spf_dkim_dmarc_failed", label: "SPF / DKIM / DMARC Authentication Failures", desc: "Cryptographic email sender validation headers failed or were missing." },
        { fact: "qr_code_embedded_in_body", label: "Embedded QR Code Phish (Quishing)", desc: "Directs mobile device to external unmonitored authentication portal." },
        { fact: "mfa_reset_lure", label: "MFA Token Reset / Re-enrollment Lure", desc: "Pretends corporate authenticator configuration requires immediate re-registration." },
        { fact: "sender_is_internal_account", label: "Sender is Internal Compromised Account", desc: "Phishing mail sent from legitimate employee address to company distrolists." },
        { fact: "mass_internal_recipients", label: "Mass Blast to Multiple Internal Recipients", desc: "High volume of recipients across internal departments." },
        { fact: "suspicious_external_link", label: "Contains Unvetted External Hyperlink", desc: "Directs traffic through URL shorteners or dynamic redirection chains." },
        { fact: "communication_channel_smishing_vishing", label: "Out-of-Band SMS or Telephony (Vishing/Smishing)", desc: "Attack vector initiated through SMS message or phone call." },
        { fact: "it_support_impersonation", label: "Helpdesk / IT Support Impersonation", desc: "Caller or texter claims to be Corporate IT requesting password or OTP." },
        { fact: "reverse_proxy_aitm_indicators", label: "Adversary-in-the-Middle (AiTM) Reverse Proxy", desc: "Evilginx/Muraena proxy capturing live session tokens during login." },
        { fact: "session_cookie_stolen", label: "Web Session Authentication Cookie Compromised", desc: "Stolen ESTSAUTH, Okta, or Google session cookie used from foreign IP." },
        { fact: "attachment_is_container_iso_zip", label: "Container Archive Attachment (ISO/ZIP/VHD)", desc: "Contains encapsulated disk image or archive to evade MOTW." },
        { fact: "contains_executable_or_lnk", label: "Contains Executable, LNK Shortcut, or Script", desc: "Shortcut or script embedded inside container payload." },
        { fact: "unknown_external_sender", label: "First-time External Sender Domain", desc: "Zero organizational email history with originating sender address." }
      ],
      malware: [
        { fact: "regular_beaconing_intervals", label: "Periodic Heartbeat / C2 Beaconing Telemetry", desc: "Systematic outbound HTTP/DNS traffic at fixed intervals with jitter." },
        { fact: "destination_ip_threat_intel_match", label: "Destination IP Matched to Threat Intelligence", desc: "Target IP/domain matches AlienVault OTX, VirusTotal, or AbuseIPDB feeds." },
        { fact: "unusual_outbound_port", label: "Outbound Connection on Non-Standard Port", desc: "Communication over ports 4444, 8080, 1337, or ephemeral high ports." },
        { fact: "registry_run_key_modified", label: "Registry Run Key Persistence Configured", desc: "Value added to HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run." },
        { fact: "binary_in_temp_or_appdata", label: "Binary Executed from %TEMP% or %APPDATA%", desc: "Process launched from user-writable temporary staging directories." },
        { fact: "unsigned_binary_detected", label: "Unsigned / Untrusted Binary Signature", desc: "File lacks valid Authenticode digital certificate from verified publisher." },
        { fact: "sustained_100_percent_cpu_gpu", label: "Sustained 100% CPU / GPU Exhaustion", desc: "System hardware locked at peak load indicative of cryptomining." },
        { fact: "stratum_protocol_traffic_detected", label: "Stratum / Mining Pool Protocol Outbound", desc: "Network traffic contains JSON-RPC stratum cryptocurrency mining requests." },
        { fact: "certutil_or_bitsadmin_downloading", label: "Living-off-the-Land Binary (Certutil/Bitsadmin) Abuse", desc: "Native Windows binary invoked with URL parameter to fetch remote file." },
        { fact: "target_is_remote_external_url", label: "Command Targets Remote External URL", desc: "Command line arguments point to external staging host or pastebin." },
        { fact: "process_injection_detected", label: "Process Injection / Memory Hollowing Detected", desc: "WriteProcessMemory or CreateRemoteThread invoked against remote PID." },
        { fact: "target_process_is_lsass_or_explorer", label: "Injected Target is LSASS.exe or Explorer.exe", desc: "Target of memory injection is sensitive security process or shell host." },
        { fact: "unbacked_executable_memory_region", label: "Unbacked Executable Memory Region (VirtualAlloc)", desc: "PAGE_EXECUTE_READWRITE memory allocated without corresponding file on disk." },
        { fact: "cobalt_strike_pipe_or_watermark", label: "Cobalt Strike / Metasploit Framework Signature", desc: "Named pipe matches \\\\.\\pipe\\msagent_* or known C2 malleable profile." },
        { fact: "sleep_obfuscation_detected", label: "Sleep Obfuscation / Ekko Memory Evasion", desc: "Thread memory encrypted or hidden during periodic sleep cycles." },
        { fact: "scheduled_task_created", label: "Suspicious Scheduled Task Registered", desc: "schtasks /create detected via Windows Security Event ID 4698." },
        { fact: "powershell_encoded_command", label: "PowerShell -EncodedCommand (Base64)", desc: "Obfuscated command line executing encoded script block." },
        { fact: "browser_credential_store_accessed", label: "Browser Credential / SQLite Store Queried", desc: "Non-browser process opened Chrome/Edge/Firefox 'Login Data' file." },
        { fact: "telegram_or_discord_webhook_exfil", label: "Outbound Exfiltration via Telegram / Discord API", desc: "Process sending data payloads to discord.com/api/webhooks or Telegram bot." },
        { fact: "usb_device_mounted", label: "Removable USB Mass Storage Mounted", desc: "Unmanaged USB drive connected to workstation." },
        { fact: "suspicious_autorun_inf_or_lnk", label: "Autorun.inf or Hidden LNK Shortcuts on Drive", desc: "Presence of shortcut worm or disguised folder executable." }
      ],
      ransomware: [
        { fact: "file_encryption_observed", label: "High-Velocity Bulk File Renaming / Encryption", desc: "Rapid mass modifications with unknown extensions (.locked, .crypt, .wnry)." },
        { fact: "vss_shadow_copies_deleted", label: "Volume Shadow Copies Purged (vssadmin delete)", desc: "Command vssadmin delete shadows /all /quiet or bcdedit executed." },
        { fact: "ransom_note_detected", label: "Ransom Extortion Note Dropped in Directories", desc: "Presence of README_TO_RESTORE.txt, RESTORE_FILES.html across shares." },
        { fact: "multiple_directories_affected", label: "Multiple Folders and Network Shares Traversed", desc: "Modifications span across multiple local and SMB shared drives." },
        { fact: "canary_honeypot_file_modified", label: "Tripwire / Canary Decoy File Modified", desc: "Decoy file placed in share was altered, confirming ransomware traversal." },
        { fact: "antivirus_service_terminated", label: "Antivirus / EDR Service Forcefully Stopped", desc: "Defender, CrowdStrike, or SentinelOne service terminated unexpectedly." },
        { fact: "event_log_cleared", label: "Windows Security Event Logs Cleared (Event ID 1102)", desc: "wevtutil cl security invoked to eliminate audit trail." },
        { fact: "psexec_or_wmi_lateral_movement", label: "PsExec / Remote WMI Lateral Movement Active", desc: "Administrative remote tool executing scripts across network hosts." },
        { fact: "batch_file_or_script_dropped", label: "Staging Batch Script (.bat, .ps1, .vbs) Dropped", desc: "Automated encryption runner batch file staged in Admin$ or C$\\temp." },
        { fact: "target_is_domain_controller_or_backup", label: "Target Host is Domain Controller or Backup Storage", desc: "Ransomware staging observed on Tier-0 or immutable backup infrastructure." },
        { fact: "large_archive_creation_7zip_rar", label: "Mass Archiving of Confidential Files (7-Zip/RAR)", desc: "Multi-part compressed archives created prior to file encryption." },
        { fact: "cloud_storage_mega_rclone_upload", label: "Outbound Data Transfer to Mega.nz or Rclone Endpoint", desc: "Data staging tool transmitting archives to offshore cloud storage." },
        { fact: "subsequent_file_encryption", label: "Encryption Began Immediately Following Exfiltration", desc: "Classic double extortion playbook sequence." },
        { fact: "bcdedit_safemode_configured", label: "Reboot Configured for Windows Safe Mode (bcdedit)", desc: "System set to reboot into Safe Mode to bypass EDR driver protection." },
        { fact: "bitlocker_manage_bde_unauthorized", label: "Unauthorized manage-bde BitLocker Invocation", desc: "Legitimate disk encryption turned on with attacker-controlled password." },
        { fact: "tpm_protectors_removed", label: "TPM Key Protectors Removed from Volume", desc: "Protectors wiped, withholding encryption recovery keys." }
      ],
      suspicious_login: [
        { fact: "geographical_velocity_impossible", label: "Impossible Travel / Velocity Anomaly", desc: "Logins from international locations physically impossible to travel between." },
        { fact: "login_from_different_countries", label: "Logins Succeeded from Multiple Divergent Countries", desc: "e.g. United States and Russia within 30 minutes." },
        { fact: "time_difference_under_one_hour", label: "Session Timestamp Interval Under 60 Minutes", desc: "Confirms impossible transit window." },
        { fact: "repeated_mfa_denials_followed_by_success", label: "Repeated MFA Push Rejections Preceding Approval", desc: "Multiple push prompts spammed until user accepted to cease buzzing." },
        { fact: "high_frequency_mfa_push_burst", label: "High-Frequency Burst of MFA Notifications", desc: "Over 5 push attempts within 2 minutes." },
        { fact: "single_ip_targeting_multiple_accounts", label: "Single IP Address Spraying Multiple Accounts", desc: "One remote IP submitting credentials across dozens of user accounts." },
        { fact: "high_failure_rate_common_passwords", label: "High Authentication Failure Rate (Password Spray)", desc: "Dictionary attempts with seasonal passwords (e.g. Fall2026!)." },
        { fact: "account_added_to_privileged_group", label: "Account Added to Domain Admins or Global Admins", desc: "Privilege escalation detected via Event ID 4728." },
        { fact: "change_outside_change_window", label: "Privilege Change Occurred Outside Change Window", desc: "Unscheduled modification without authorized change ticket." },
        { fact: "initiating_account_non_standard", label: "Initiating Account is Non-Standard Administrator", desc: "Service account or compromised contractor initiated group modification." },
        { fact: "source_ip_is_tor_or_anonymizer", label: "Source IP Belongs to Tor Exit Node / Commercial VPN", desc: "Traffic originated from anonymizing network infrastructure." },
        { fact: "login_time_abnormal_off_hours", label: "Logon Event Occurred During Off-Hours (e.g. 03:00 AM)", desc: "Activity outside regular working hours and historical user baseline." },
        { fact: "account_is_non_interactive_service_account", label: "Target Account is Non-Interactive Service Account", desc: "Dedicated SQL/App account configured with service logon only." },
        { fact: "interactive_gui_or_rdp_logon", label: "Interactive RDP / Desktop Session Initiated", desc: "Interactive logon type 2 or 10 initiated by non-human account." },
        { fact: "kerberos_ticket_lifetime_unrealistic", label: "Kerberos TGT Ticket Lifetime Unrealistic (10 Years)", desc: "Ticket lifetime exceeds domain policy, signature of Golden Ticket." },
        { fact: "ticket_encryption_type_rc4_downgrade", label: "Kerberos Encryption Downgrade to RC4-HMAC", desc: "Cryptographic downgrade to 0x17 RC4 for ticket forgery." },
        { fact: "account_status_dormant_or_terminated", label: "Account Belongs to Terminated / Inactive Employee", desc: "Account was deactivated or unaccessed for > 90 days." },
        { fact: "successful_authentication_event", label: "Successful Authentication Recorded for Inactive Account", desc: "Access granted despite employee departure." }
      ],
      data_breach: [
        { fact: "unusual_outbound_data_volume_gigabytes", label: "Massive Outbound Data Egress Volume (> 5GB)", desc: "NetFlow reports sustained high-volume data stream outward." },
        { fact: "destination_is_unapproved_cloud_storage", label: "Egress Destination is Unapproved Cloud Repo", desc: "Mega.nz, Dropbox, WeTransfer, Anonfiles, or Telegram." },
        { fact: "sensitive_file_types_in_stream", label: "Sensitive File Types (.sql, .csv, .docx, .pem) in Stream", desc: "Archives containing database dumps or source code." },
        { fact: "database_full_dump_executed", label: "Full Database Dump Utility Invoked (mysqldump/pg_dump)", desc: "Native command executed extracting entire schema tables." },
        { fact: "executed_from_web_server_context", label: "Database Dump Executed from Web Server Context", desc: "Command executed by www-data, apache, or IIS_IUSRS identity." },
        { fact: "contains_pii_or_financial_records", label: "Export Contains Customer PII, SSNs, or Financial Data", desc: "Sensitive regulatory data fields identified in query payload." },
        { fact: "dlp_regex_ssn_credit_card_match", label: "Data Loss Prevention (DLP) Pattern Match (SSN / CCN)", desc: "Sensor triggered on PCI-DSS cardholder or PII patterns." },
        { fact: "channel_is_external_email_or_usb", label: "Transmission Channel is External Email or USB Drive", desc: "Personal webmail attachment or unencrypted flash drive transfer." },
        { fact: "high_volume_dns_txt_queries", label: "Anomalous Volume of DNS TXT / NULL Queries", desc: "Sustained high frequency of queries to single authoritative nameserver." },
        { fact: "abnormally_long_subdomain_labels", label: "Abnormally Long Subdomain Labels (> 50 Characters)", desc: "Subdomains containing base64/hex payload chunks for DNS tunneling." },
        { fact: "high_entropy_in_dns_requests", label: "High Shannon Entropy in Requested Domain Names", desc: "Randomized character distributions matching dnscat2 or iodine." },
        { fact: "cloud_bucket_policy_public_read", label: "Cloud S3 / Blob Storage Configured with Public Read", desc: "ACL set to AllUsers or public read anonymous access." },
        { fact: "contains_confidential_backups_or_keys", label: "Exposed Storage Contains DB Backups or Private Keys", desc: "Unsecured repository contains critical organizational secrets." },
        { fact: "employee_resignation_notice_pending", label: "Employee Resignation Notice Formally Submitted", desc: "Staff member in final notice period before departure." },
        { fact: "unusual_spike_in_file_downloads", label: "Anomalous Bulk File Download Spike from Intranet", desc: "User downloading thousands of files from SharePoint/Confluence." },
        { fact: "accessing_non_role_relevant_folders", label: "Accessing Folders Outside Normal Job Function", desc: "Sales staff downloading source code repositories or HR files." },
        { fact: "webshell_file_in_web_root", label: "Web Shell Script Detected in Web Root", desc: "Presence of disguised .php, .aspx, or .jsp backdoor command handler." },
        { fact: "outbound_data_transfer_from_web_server", label: "Sustained Outbound Data Transfer from Web Server", desc: "Public web host communicating externally with foreign IPs." },
        { fact: "private_keys_or_tokens_pushed_to_public_repo", label: "Private AWS Keys / SSH Keys Pushed to Public GitHub", desc: "Cloud credentials inadvertently committed to public repository." },
        { fact: "api_rate_limit_exceeded_exponentially", label: "API Rate Limit Exceeded by Factor of 100x", desc: "High-speed sequential API calls targeting customer record endpoints." },
        { fact: "sequential_record_id_harvesting", label: "Sequential Iteration of Record Identifiers (BOLA / IDOR)", desc: "Requesting IDs 1001, 1002, 1003 in rapid succession." }
      ]
    };

    return catalog;
  }

  /**
   * Render checkbox groups organized by category
   */
  renderIndicators() {
    if (!this.indicatorsContainer) return;
    const catalog = this.getIndicatorsCatalog();
    this.indicatorsContainer.innerHTML = "";

    const categories = [
      { key: "phishing", label: "Phishing & Social Engineering", icon: "📧" },
      { key: "malware", label: "Malware & Command & Control", icon: "🦠" },
      { key: "ransomware", label: "Ransomware Outbreak", icon: "🔒" },
      { key: "suspicious_login", label: "Suspicious Login & Identity Anomalies", icon: "👤" },
      { key: "data_breach", label: "Data Breach & Exfiltration", icon: "💾" }
    ];

    categories.forEach(cat => {
      const isVisible = this.activeCategory === "all" || this.activeCategory === cat.key;
      const groupEl = document.createElement("div");
      groupEl.className = `indicator-group-panel ${isVisible ? "" : "hidden"}`;
      groupEl.setAttribute("data-cat-panel", cat.key);

      const items = catalog[cat.key] || [];

      groupEl.innerHTML = `
        <div class="indicator-group-header">
          <span class="group-icon">${cat.icon}</span>
          <div class="group-header-text">
            <h4>${cat.label}</h4>
            <span class="indicator-count">${items.length} Production Indicators</span>
          </div>
          <button type="button" class="btn-group-toggle" data-toggle-target="group_${cat.key}">Collapse / Expand</button>
        </div>
        <div class="indicator-grid" id="group_${cat.key}">
          ${items.map(item => `
            <label class="indicator-checkbox-card" for="ind_${item.fact}">
              <div class="checkbox-wrapper">
                <input type="checkbox" id="ind_${item.fact}" name="indicator" value="${item.fact}" data-category="${cat.key}">
                <span class="custom-checkbox"></span>
              </div>
              <div class="indicator-content">
                <div class="indicator-title">${item.label}</div>
                <div class="indicator-desc">${item.desc}</div>
                <div class="indicator-fact-badge"><code>Fact: ${item.fact}</code></div>
              </div>
            </label>
          `).join("")}
        </div>
      `;

      this.indicatorsContainer.appendChild(groupEl);
    });

    // Attach collapsible listeners
    document.querySelectorAll(".btn-group-toggle").forEach(btn => {
      btn.addEventListener("click", () => {
        const targetId = btn.getAttribute("data-toggle-target");
        const grid = document.getElementById(targetId);
        if (grid) {
          grid.classList.toggle("collapsed");
        }
      });
    });
  }

  /**
   * Filter visible indicator categories
   */
  filterCategory(categoryKey) {
    this.activeCategory = categoryKey;
    const panels = document.querySelectorAll("[data-cat-panel]");
    panels.forEach(p => {
      const panelCat = p.getAttribute("data-cat-panel");
      if (categoryKey === "all" || panelCat === categoryKey) {
        p.classList.remove("hidden");
      } else {
        p.classList.add("hidden");
      }
    });

    // Update filter buttons styling
    document.querySelectorAll(".category-pill").forEach(pill => {
      if (pill.getAttribute("data-filter") === categoryKey) {
        pill.classList.add("active");
      } else {
        pill.classList.remove("active");
      }
    });
  }

  /**
   * Load pre-configured test scenario
   */
  loadScenario(scenarioId) {
    if (!scenarioId) return;
    const scenario = this.scenarios.find(s => s.id === scenarioId);
    if (!scenario) return;

    this.resetForm();

    // Set asset criticality
    if (this.assetCriticalitySelect && scenario.assetCriticality) {
      this.assetCriticalitySelect.value = scenario.assetCriticality;
    }

    // Set incident metadata fields
    const hostInput = document.getElementById("targetHostname");
    const ipInput = document.getElementById("sourceIp");
    const notesInput = document.getElementById("incidentNotes");

    if (hostInput) hostInput.value = `CORP-${scenario.category.toUpperCase()}-SRV01`;
    if (ipInput) ipInput.value = scenario.category === "benign" ? "10.0.12.44 (Internal Subnet)" : "185.220.101.5 (External Threat Feed)";
    if (notesInput) notesInput.value = `[AUTO-LOADED TEST SCENARIO: ${scenario.name}]\n${scenario.description}`;

    // Filter to scenario's category for clean viewing
    if (scenario.category !== "benign") {
      this.filterCategory(scenario.category);
    } else {
      this.filterCategory("all");
    }

    // Check relevant indicator checkboxes
    for (const [factKey, value] of Object.entries(scenario.facts)) {
      if (value === true) {
        const chk = document.getElementById(`ind_${factKey}`);
        if (chk) {
          chk.checked = true;
          chk.closest(".indicator-checkbox-card").classList.add("selected-card");
        }
      }
    }

    // Trigger analysis immediately for convenience
    this.collectAndTriggerAnalysis();
  }

  /**
   * Collect all checked indicators and trigger engine
   */
  collectAndTriggerAnalysis() {
    const facts = {};
    const checkedBoxes = document.querySelectorAll('input[name="indicator"]:checked');

    checkedBoxes.forEach(chk => {
      facts[chk.value] = true;
    });

    // Read metadata
    const assetCriticality = this.assetCriticalitySelect ? this.assetCriticalitySelect.value : "HIGH";
    const incidentContext = {
      hostname: document.getElementById("targetHostname")?.value || "UNKNOWN-HOST",
      sourceIp: document.getElementById("sourceIp")?.value || "0.0.0.0",
      analyst: document.getElementById("analystName")?.value || "SOC Tier-1 Analyst",
      notes: document.getElementById("incidentNotes")?.value || "",
      timestamp: new Date().toISOString()
    };

    if (typeof this.onAnalyzeCallback === "function") {
      this.onAnalyzeCallback(facts, assetCriticality, incidentContext);
    }
  }

  resetForm() {
    if (this.form) this.form.reset();
    document.querySelectorAll(".indicator-checkbox-card").forEach(c => c.classList.remove("selected-card"));
    if (this.scenarioSelect) this.scenarioSelect.value = "";
    this.filterCategory("all");
  }

  attachEventListeners() {
    // Category pill filter clicks
    document.querySelectorAll(".category-pill").forEach(pill => {
      pill.addEventListener("click", () => {
        const filterVal = pill.getAttribute("data-filter");
        this.filterCategory(filterVal);
      });
    });

    // Scenario select change
    if (this.scenarioSelect) {
      this.scenarioSelect.addEventListener("change", (e) => {
        this.loadScenario(e.target.value);
      });
    }

    // Run Analysis Button
    if (this.btnRunAnalysis) {
      this.btnRunAnalysis.addEventListener("click", (e) => {
        e.preventDefault();
        this.collectAndTriggerAnalysis();
      });
    }

    // Reset Button
    if (this.btnResetTriage) {
      this.btnResetTriage.addEventListener("click", (e) => {
        e.preventDefault();
        this.resetForm();
      });
    }

    // Visual selection highlighting on checkbox change
    if (this.indicatorsContainer) {
      this.indicatorsContainer.addEventListener("change", (e) => {
        if (e.target && e.target.type === "checkbox") {
          const card = e.target.closest(".indicator-checkbox-card");
          if (card) {
            if (e.target.checked) card.classList.add("selected-card");
            else card.classList.remove("selected-card");
          }
        }
      });
    }
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { TriageUIController };
}

/**
 * Cybersecurity Incident-Response Advisory Expert System (CIR-AES)
 * Playbook UI Controller: NIST SP 800-61 Rev 2 Response Checklist and CLI Execution Scripts
 */

class PlaybookUIController {
  constructor() {
    this.container = document.getElementById("playbookContainer");
    this.progressBadge = document.getElementById("playbookProgressBadge");
    this.checkedActions = new Set();
    this.totalActions = 0;

    this.init();
  }

  init() {
    // Initial empty or placeholder state
    this.renderEmptyState();
  }

  renderEmptyState() {
    if (!this.container) return;
    this.container.innerHTML = `
      <div class="empty-playbook-card">
        <div class="empty-icon">📋</div>
        <h4>No Active Incident Triage Loaded</h4>
        <p>Run the Expert Analysis in the Triage Console or load a Test Scenario to generate a NIST SP 800-61 tailored response checklist and remediation CLI commands.</p>
      </div>
    `;
    if (this.progressBadge) this.progressBadge.textContent = "0% Complete";
  }

  /**
   * Render dynamic playbook based on inference results
   */
  renderPlaybook(inferenceResult) {
    if (!this.container) return;

    const playbook = inferenceResult.playbookByPhase || {};
    this.checkedActions.clear();
    this.totalActions = 0;

    const phaseIcons = {
      "Immediate Containment": "🛑",
      "Detection & Analysis": "🔍",
      "Eradication": "🧹",
      "Recovery": "🔄",
      "Post-Incident Activity": "📝"
    };

    let totalItems = 0;
    for (const phase in playbook) {
      totalItems += playbook[phase].length;
    }
    this.totalActions = totalItems;

    if (totalItems === 0) {
      this.container.innerHTML = `
        <div class="empty-playbook-card">
          <div class="empty-icon">✅</div>
          <h4>No Remediation Actions Required</h4>
          <p>The system did not detect active indicators of compromise. Standard baseline monitoring continues.</p>
        </div>
      `;
      if (this.progressBadge) this.progressBadge.textContent = "100% Secure";
      return;
    }

    let html = `
      <div class="playbook-header-banner">
        <div class="playbook-title-block">
          <h3>NIST SP 800-61 Rev 2 Response Playbook</h3>
          <p>Actionable tactical checklist synthesized specifically for the detected threat vectors.</p>
        </div>
        <div class="playbook-tracker">
          <span class="tracker-label">Remediation Checklist:</span>
          <span class="tracker-pill" id="playbookProgressCounter">0 / ${this.totalActions} Steps Completed</span>
        </div>
      </div>
      <div class="phases-accordion">
    `;

    for (const [phaseName, items] of Object.entries(playbook)) {
      if (items.length === 0) continue;

      const icon = phaseIcons[phaseName] || "🛡️";

      html += `
        <div class="phase-card">
          <div class="phase-card-header">
            <div class="phase-title">
              <span class="phase-icon">${icon}</span>
              <h4>Phase: ${phaseName}</h4>
            </div>
            <span class="phase-item-count">${items.length} Action Items</span>
          </div>

          <div class="phase-card-body">
            <ul class="action-checklist">
              ${items.map((item, idx) => {
                const actionId = `act_${phaseName.replace(/\s+/g, '_')}_${idx}`;
                return `
                  <li class="action-item-row" id="row_${actionId}">
                    <label class="action-checkbox-wrapper" for="${actionId}">
                      <input type="checkbox" id="${actionId}" class="chk-action" data-action-text="${encodeURIComponent(item.action)}">
                      <span class="action-custom-checkbox"></span>
                    </label>
                    <div class="action-body">
                      <div class="action-text">${item.action}</div>
                      <div class="action-meta">
                        <span class="source-rule">Source: <strong>${item.sourceRule}</strong></span>
                        <span class="source-sev sev-${item.severity.toLowerCase()}">${item.severity}</span>
                      </div>
                    </div>
                  </li>
                `;
              }).join("")}
            </ul>
          </div>
        </div>
      `;
    }

    // Add Forensic Remediation CLI Commands Generator
    html += this.generateCLICommandsSection(inferenceResult);

    html += `</div>`;
    this.container.innerHTML = html;

    this.attachChecklistListeners();
    this.updateProgress();
  }

  generateCLICommandsSection(inferenceResult) {
    const memory = inferenceResult.workingMemory || {};
    const isWindows = true;

    let cliSnippet = `# =======================================================
# EMERGENCY INCIDENT RESPONSE COMMANDS (PowerShell)
# Target Host Isolation & Forensic Preservation
# =======================================================

# 1. Immediate Host Network Isolation
Disable-NetAdapter -Name "Ethernet*" -Confirm:$false
Write-Host "[+] Host isolated from network to prevent lateral movement." -ForegroundColor Red

# 2. Capture Volatile Network Connections and Process Memory
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Export-Csv -Path "C:\\IR_Preservation_Connections.csv" -NoTypeInformation
Get-Process | Sort-Object CPU -Descending | Select-Object -First 25 | Format-Table Id, ProcessName, Path, WorkingSet

# 3. Kill Potentially Malicious Script Run-Spaces
Get-Process | Where-Object {$_.ProcessName -in @("powershell", "cmd", "wscript", "cscript") -and $_.StartTime -gt (Get-Date).AddHours(-2)} | Stop-Process -Force -ErrorAction SilentlyContinue
`;

    if (memory.file_encryption_observed || memory.vss_shadow_copies_deleted) {
      cliSnippet += `
# 4. Ransomware Specific Safeguards
# Verify remaining Volume Shadow Copies (Do not reboot!)
vssadmin list shadows
Get-Service -Name "LanmanServer" | Stop-Service -Force # Halts active SMB sharing
Write-Host "[!] Ransomware halt procedures executed. Preserve RAM for crypto key extraction." -ForegroundColor Yellow
`;
    }

    if (memory.geographical_velocity_impossible || memory.repeated_mfa_denials_followed_by_success) {
      cliSnippet += `
# 5. Identity & Token Revocation (Microsoft Graph / Entra ID)
# Revoke active OAuth refresh tokens
Revoke-MgUserSignInSession -UserId "compromised_user@corp.internal"
Update-MgUser -UserId "compromised_user@corp.internal" -AccountEnabled:$false
Write-Host "[+] User session revoked and account disabled." -ForegroundColor Green
`;
    }

    return `
      <div class="cli-terminal-card">
        <div class="terminal-bar">
          <div class="terminal-dots">
            <span class="dot dot-red"></span>
            <span class="dot dot-yellow"></span>
            <span class="dot dot-green"></span>
          </div>
          <span class="terminal-title">PowerShell / IR Tactical Containment Snippet</span>
          <button type="button" class="btn-copy-cli" id="btnCopyCLI">Copy Script</button>
        </div>
        <div class="terminal-body">
          <pre><code id="cliSnippetCode">${cliSnippet}</code></pre>
        </div>
      </div>
    `;
  }

  attachChecklistListeners() {
    const checkboxes = this.container.querySelectorAll(".chk-action");
    checkboxes.forEach(chk => {
      chk.addEventListener("change", (e) => {
        const row = e.target.closest(".action-item-row");
        if (e.target.checked) {
          this.checkedActions.add(e.target.id);
          row.classList.add("action-completed");
        } else {
          this.checkedActions.delete(e.target.id);
          row.classList.remove("action-completed");
        }
        this.updateProgress();
      });
    });

    const copyBtn = document.getElementById("btnCopyCLI");
    if (copyBtn) {
      copyBtn.addEventListener("click", () => {
        const code = document.getElementById("cliSnippetCode")?.innerText || "";
        navigator.clipboard.writeText(code).then(() => {
          copyBtn.textContent = "Copied to Clipboard!";
          setTimeout(() => { copyBtn.textContent = "Copy Script"; }, 2500);
        });
      });
    }
  }

  updateProgress() {
    const completed = this.checkedActions.size;
    const total = this.totalActions;
    const pct = total > 0 ? Math.round((completed / total) * 100) : 0;

    const counter = document.getElementById("playbookProgressCounter");
    if (counter) {
      counter.textContent = `${completed} / ${total} Steps Completed (${pct}%)`;
    }

    if (this.progressBadge) {
      this.progressBadge.textContent = `${pct}% Complete`;
      if (pct === 100) this.progressBadge.classList.add("all-done");
      else this.progressBadge.classList.remove("all-done");
    }
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { PlaybookUIController };
}

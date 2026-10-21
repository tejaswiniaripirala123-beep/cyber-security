/**
 * Cybersecurity Incident-Response Advisory Expert System (CIR-AES)
 * Report Generator UI Controller: Formal Enterprise Incident Report & PDF Export
 */

class ReportGeneratorUIController {
  constructor() {
    this.container = document.getElementById("incidentReportContainer");
    this.btnPrintReport = document.getElementById("btnPrintReport");
    this.btnExportJson = document.getElementById("btnExportJson");
    this.currentReportData = null;

    this.init();
  }

  init() {
    if (this.btnPrintReport) {
      this.btnPrintReport.addEventListener("click", () => this.triggerPrint());
    }
    if (this.btnExportJson) {
      this.btnExportJson.addEventListener("click", () => this.exportJson());
    }

    this.renderPlaceholder();
  }

  renderPlaceholder() {
    if (!this.container) return;
    this.container.innerHTML = `
      <div class="report-placeholder-card">
        <div class="empty-icon">📄</div>
        <h4>No Incident Report Generated Yet</h4>
        <p>Run an analysis in the Expert Advisory Engine or load a test scenario to compile an official Incident Response Audit Report ready for PDF export.</p>
      </div>
    `;
  }

  generateCaseId() {
    const rand = Math.floor(1000 + Math.random() * 9000);
    return `INC-2026-${rand}`;
  }

  generateReport(inferenceResult, riskAssessment, incidentContext = {}) {
    if (!this.container) return;

    const caseId = this.generateCaseId();
    const timestamp = new Date().toLocaleString();
    const severity = inferenceResult.overallSeverity || "LOW";
    const threatName = (inferenceResult.primaryThreat || "Benign Activity").replace(/_/g, " ").toUpperCase();
    const firedRules = inferenceResult.firedRules || [];

    this.currentReportData = {
      caseId,
      timestamp,
      severity,
      threatName,
      incidentContext,
      inferenceResult,
      riskAssessment
    };

    let reportHtml = `
      <div class="official-report-document" id="printableReportArea">
        <!-- Report Header -->
        <div class="report-doc-header">
          <div class="header-branding">
            <div class="shield-badge">CIR-AES</div>
            <div class="branding-text">
              <h2>CYBERSECURITY INCIDENT RESPONSE ADVISORY SYSTEM</h2>
              <p class="subtitle">Deterministic Rule-Based Reasoning Engine • College Capstone Project</p>
            </div>
          </div>
          <div class="header-metadata-box">
            <div class="meta-row"><strong>CASE ID:</strong> <span>${caseId}</span></div>
            <div class="meta-row"><strong>DATE:</strong> <span>${timestamp}</span></div>
            <div class="meta-row"><strong>STATUS:</strong> <span class="badge-status-triaged">TRIAGED / ADVISORY READY</span></div>
            <div class="meta-row"><strong>SEVERITY:</strong> <span class="badge-rep-sev sev-${severity.toLowerCase()}">${severity}</span></div>
          </div>
        </div>

        <hr class="report-divider">

        <!-- Section 1: Executive Summary -->
        <div class="report-section">
          <h3 class="section-title">1. EXECUTIVE SUMMARY</h3>
          <p class="section-text">
            On <strong>${timestamp}</strong>, the automated Cybersecurity Incident-Response Advisory Expert System (CIR-AES) performed a deterministic forward-chaining rule-based triage on telemetry submitted for host <code>${incidentContext.hostname || 'CORP-HOST01'}</code> (Source IP: <code>${incidentContext.sourceIp || '0.0.0.0'}</code>).
          </p>
          <div class="summary-highlight-grid">
            <div class="highlight-box">
              <span class="hl-label">Classified Threat Vector</span>
              <span class="hl-val">${threatName}</span>
            </div>
            <div class="highlight-box">
              <span class="hl-label">Composite Risk Rating</span>
              <span class="hl-val">${riskAssessment.score} / 100 (${riskAssessment.level})</span>
            </div>
            <div class="highlight-box">
              <span class="hl-label">Target Response SLA</span>
              <span class="hl-val">${riskAssessment.slaTarget}</span>
            </div>
            <div class="highlight-box">
              <span class="hl-label">Rules Evaluated / Fired</span>
              <span class="hl-val">${inferenceResult.executionStats.rulesFiredCount} Fired (${inferenceResult.executionStats.durationMs}ms)</span>
            </div>
          </div>
          <p class="section-text"><strong>Advisory Rationale:</strong> ${riskAssessment.rationale}</p>
        </div>

        <!-- Section 2: Scope & System Context -->
        <div class="report-section">
          <h3 class="section-title">2. INCIDENT SCOPE & TELEMETRY PROFILE</h3>
          <table class="report-data-table">
            <tbody>
              <tr>
                <td class="tbl-lbl" style="width: 25%;">Target Asset Hostname</td>
                <td><code>${incidentContext.hostname || 'CORP-HOST01'}</code></td>
                <td class="tbl-lbl" style="width: 25%;">Asset Criticality Tier</td>
                <td><strong>${riskAssessment.assetMultiplier > 1.2 ? 'TIER-1 CRITICAL INFRASTRUCTURE' : 'TIER-2 STANDARD ASSET'} (Weight: ×${riskAssessment.assetMultiplier})</strong></td>
              </tr>
              <tr>
                <td class="tbl-lbl">Origin / Attacker Indicator</td>
                <td><code>${incidentContext.sourceIp || '10.0.0.1'}</code></td>
                <td class="tbl-lbl">Investigating Lead</td>
                <td>${incidentContext.analyst || 'SOC Incident Responder'}</td>
              </tr>
              <tr>
                <td class="tbl-lbl">Operator Field Notes</td>
                <td colspan="3">${incidentContext.notes ? incidentContext.notes.replace(/\n/g, '<br>') : 'Telemetry submitted through CIR-AES automated triage console.'}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Section 3: CIA Triad Impact & Regulatory Exposure -->
        <div class="report-section">
          <h3 class="section-title">3. CIA TRIAD IMPACT & COMPLIANCE EVALUATION</h3>
          <div class="report-cia-container">
            <div class="cia-bar-unit">
              <div class="cia-unit-header">Confidentiality: <strong>${riskAssessment.ciaImpact.confidentiality}%</strong></div>
              <div class="unit-bar"><div class="unit-bar-fill c-bar" style="width: ${riskAssessment.ciaImpact.confidentiality}%;"></div></div>
            </div>
            <div class="cia-bar-unit">
              <div class="cia-unit-header">Data Integrity: <strong>${riskAssessment.ciaImpact.integrity}%</strong></div>
              <div class="unit-bar"><div class="unit-bar-fill i-bar" style="width: ${riskAssessment.ciaImpact.integrity}%;"></div></div>
            </div>
            <div class="cia-bar-unit">
              <div class="cia-unit-header">System Availability: <strong>${riskAssessment.ciaImpact.availability}%</strong></div>
              <div class="unit-bar"><div class="unit-bar-fill a-bar" style="width: ${riskAssessment.ciaImpact.availability}%;"></div></div>
            </div>
          </div>
          <div class="compliance-notice-box">
            <p><strong>Regulatory Compliance Assessment:</strong> ${riskAssessment.regulatoryRisk}</p>
            <p><strong>Estimated Financial Loss Exposure:</strong> ${riskAssessment.financialExposureIndex}</p>
          </div>
        </div>

        <!-- Section 4: Production Rules Fired (Audit Trail) -->
        <div class="report-section">
          <h3 class="section-title">4. EXPERT SYSTEM INFERENCE AUDIT (FIRED PRODUCTION RULES)</h3>
          <p class="section-text">The inference engine matched the following production rules in forward-chaining cycles:</p>
          
          <table class="report-data-table full-width">
            <thead>
              <tr>
                <th style="width: 15%;">Rule ID</th>
                <th style="width: 30%;">Rule Name & Domain</th>
                <th style="width: 30%;">Matched Premise Conditions (IF)</th>
                <th style="width: 25%;">Inferred Consequents (THEN)</th>
              </tr>
            </thead>
            <tbody>
              ${firedRules.length > 0 ? firedRules.map(r => `
                <tr>
                  <td><strong>${r.id}</strong><br><span class="badge-mini sev-${r.severity.toLowerCase()}">${r.severity}</span></td>
                  <td>
                    <strong>${r.name}</strong><br>
                    <small>Category: ${r.category.toUpperCase()} | Priority: ${r.priority}</small><br>
                    <small><em>${r.explanation}</em></small>
                  </td>
                  <td>
                    <ul class="report-cond-list">
                      ${r.matchedConditions.map(c => `<li><code>${c.condition.fact} == ${c.condition.value}</code></li>`).join("")}
                    </ul>
                  </td>
                  <td>
                    <ul class="report-concl-list">
                      ${r.conclusions.map(c => `<li><code>${c.fact} = ${c.value}</code></li>`).join("")}
                    </ul>
                  </td>
                </tr>
              `).join("") : `
                <tr><td colspan="4" style="text-align: center; color: #64748b;">No production rules triggered during analysis session.</td></tr>
              `}
            </tbody>
          </table>
        </div>

        <!-- Section 5: NIST SP 800-61 Tactical Action Plan -->
        <div class="report-section">
          <h3 class="section-title">5. STANDARDIZED RESPONSE ACTION PLAN (NIST SP 800-61 REV 2)</h3>
          ${Object.entries(inferenceResult.playbookByPhase || {}).map(([phase, items]) => {
            if (items.length === 0) return '';
            return `
              <div class="report-phase-subblock">
                <h4 class="phase-subheading">Phase: ${phase} (${items.length} Directives)</h4>
                <ol class="report-ordered-actions">
                  ${items.map(item => `
                    <li>
                      <strong>${item.action}</strong>
                      <span class="item-ref">(Prescribed by ${item.sourceRule})</span>
                    </li>
                  `).join("")}
                </ol>
              </div>
            `;
          }).join("")}
        </div>

        <!-- Section 6: Chain of Custody & Sign-Off Block -->
        <div class="report-section sign-off-block">
          <h3 class="section-title">6. INVESTIGATION SIGN-OFF & CHAIN OF CUSTODY</h3>
          <div class="sign-off-grid">
            <div class="sign-box">
              <div class="sign-label">Triaged By Lead Analyst:</div>
              <div class="sign-line">${incidentContext.analyst || 'SOC Senior Specialist'}</div>
              <div class="sign-caption">Lead Incident Responder Signature / Timestamp</div>
            </div>
            <div class="sign-box">
              <div class="sign-label">Peer Reviewed & Approved By:</div>
              <div class="sign-line">Cyber Incident Response Commander (CIRT)</div>
              <div class="sign-caption">Information Security Officer / CISO</div>
            </div>
          </div>
          <div class="report-disclaimer">
            <em>Disclaimer: This advisory report was generated deterministically by the Rule-Based Expert System (CIR-AES). Actions recommended align with NIST SP 800-61 guidelines. Real-world execution should be performed in accordance with corporate legal policies.</em>
          </div>
        </div>
      </div>
    `;

    this.container.innerHTML = reportHtml;
  }

  triggerPrint() {
    if (!this.currentReportData) {
      alert("Please run an incident analysis first before printing the report.");
      return;
    }
    window.print();
  }

  exportJson() {
    if (!this.currentReportData) {
      alert("Please run an incident analysis first before exporting data.");
      return;
    }

    const jsonString = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(this.currentReportData, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", jsonString);
    downloadAnchor.setAttribute("download", `${this.currentReportData.caseId}_IR_Advisory_Report.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { ReportGeneratorUIController };
}

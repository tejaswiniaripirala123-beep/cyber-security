/**
 * Cybersecurity Incident-Response Advisory Expert System (CIR-AES)
 * Explanation UI Controller: XAI Facility, Inference Trace, and Knowledge Base Explorer
 */

class ExplanationUIController {
  constructor(options = {}) {
    this.rulesDatabase = options.rules || [];
    this.engine = options.engine;
    
    // DOM Elements
    this.summaryBanner = document.getElementById("analysisSummaryBanner");
    this.riskCard = document.getElementById("riskAssessmentCard");
    this.traceContainer = document.getElementById("inferenceTraceContainer");
    this.rulesExplorerContainer = document.getElementById("rulesExplorerContainer");
    this.rulesFilterInput = document.getElementById("rulesFilterInput");
    this.rulesCategorySelect = document.getElementById("rulesCategorySelect");
    this.modalExplanation = document.getElementById("modalExplanation");
    this.modalContent = document.getElementById("modalExplanationContent");
    this.modalClose = document.getElementById("modalClose");

    this.currentResult = null;
    this.currentRisk = null;

    this.init();
  }

  init() {
    this.renderRulesExplorer(this.rulesDatabase);
    this.attachEventListeners();
  }

  /**
   * Render complete analysis results
   */
  displayResults(inferenceResult, riskAssessment, incidentContext = {}) {
    this.currentResult = inferenceResult;
    this.currentRisk = riskAssessment;

    this.renderSummaryBanner(inferenceResult, riskAssessment, incidentContext);
    this.renderRiskCard(riskAssessment);
    this.renderInferenceTrace(inferenceResult);

    // Scroll smoothly to results view
    const resultsAnchor = document.getElementById("analysisResultsSection");
    if (resultsAnchor) {
      resultsAnchor.scrollIntoView({ behavior: "smooth" });
    }
  }

  renderSummaryBanner(result, risk, context) {
    if (!this.summaryBanner) return;

    const firedCount = result.firedRules.length;
    const severity = result.overallSeverity || "LOW";
    const threatName = (result.primaryThreat || "Benign Activity").replace(/_/g, " ").toUpperCase();
    const duration = result.executionStats.durationMs || 0.8;
    const cycles = result.executionStats.cycles || 1;

    let badgeClass = "badge-low";
    let glowClass = "glow-low";
    if (severity === "CRITICAL") { badgeClass = "badge-critical"; glowClass = "glow-critical"; }
    else if (severity === "HIGH") { badgeClass = "badge-high"; glowClass = "glow-high"; }
    else if (severity === "MEDIUM") { badgeClass = "badge-medium"; glowClass = "glow-medium"; }

    this.summaryBanner.innerHTML = `
      <div class="summary-hero-card ${glowClass}">
        <div class="summary-header">
          <div class="summary-title-group">
            <span class="severity-pill ${badgeClass}">SEVERITY: ${severity}</span>
            <span class="priority-pill">${risk.incidentPriority}</span>
            <span class="timestamp-pill"><i class="icon-clock"></i> ${new Date().toLocaleTimeString()}</span>
          </div>
          <div class="engine-telemetry-badge">
            <span>Inference Time: <strong>${duration} ms</strong></span>
            <span>Cycles: <strong>${cycles}</strong></span>
            <span>Rules Fired: <strong>${firedCount}</strong></span>
          </div>
        </div>

        <div class="summary-body">
          <div class="threat-classification">
            <div class="label-tiny">PRIMARY CLASSIFIED THREAT</div>
            <h2 class="threat-heading">${threatName}</h2>
            <p class="threat-lead">${risk.rationale}</p>
          </div>

          <div class="risk-gauge-container">
            <div class="risk-radial-meter">
              <svg viewBox="0 0 100 100" class="gauge-svg">
                <circle class="gauge-bg" cx="50" cy="50" r="42" />
                <circle class="gauge-fill ${badgeClass}" cx="50" cy="50" r="42" 
                  stroke-dasharray="264" 
                  stroke-dashoffset="${264 - (264 * (risk.score / 100))}" />
              </svg>
              <div class="gauge-center-text">
                <div class="gauge-number">${risk.score}</div>
                <div class="gauge-label">RISK / 100</div>
              </div>
            </div>
            <div class="gauge-subtext">
              <span class="sla-text">Target SLA: <strong>${risk.slaTarget}</strong></span>
            </div>
          </div>
        </div>

        <div class="summary-footer">
          <div class="meta-tag"><strong>Target Host:</strong> ${context.hostname || 'CORP-HOST01'}</div>
          <div class="meta-tag"><strong>Attacker/Origin IP:</strong> ${context.sourceIp || '10.0.0.1'}</div>
          <div class="meta-tag"><strong>Assigned Analyst:</strong> ${context.analyst || 'SOC Lead'}</div>
          <div class="action-buttons-group">
            <button type="button" class="btn-action-primary" id="btnJumpToPlaybook">View Response Playbook</button>
            <button type="button" class="btn-action-secondary" id="btnJumpToReport">Generate Incident Report</button>
          </div>
        </div>
      </div>
    `;

    // Hook jump buttons
    document.getElementById("btnJumpToPlaybook")?.addEventListener("click", () => {
      document.getElementById("playbookSection")?.scrollIntoView({ behavior: "smooth" });
    });
    document.getElementById("btnJumpToReport")?.addEventListener("click", () => {
      if (window.app && window.app.navigation) {
        window.app.navigation.navigateTo("incident-report");
      }
    });
  }

  renderRiskCard(risk) {
    if (!this.riskCard) return;

    this.riskCard.innerHTML = `
      <div class="risk-breakdown-card">
        <div class="card-section-header">
          <h3><span class="icon-shield">🛡️</span> Quantitative Risk Assessment & CIA Impact</h3>
          <span class="asset-multiplier-pill">Asset Weight: ×${risk.assetMultiplier}</span>
        </div>

        <div class="cia-triad-grid">
          <div class="cia-meter-item">
            <div class="cia-label-row">
              <span>Confidentiality (C)</span>
              <strong>${risk.ciaImpact.confidentiality}%</strong>
            </div>
            <div class="progress-bar-track">
              <div class="progress-bar-fill c-fill" style="width: ${risk.ciaImpact.confidentiality}%"></div>
            </div>
          </div>

          <div class="cia-meter-item">
            <div class="cia-label-row">
              <span>Integrity (I)</span>
              <strong>${risk.ciaImpact.integrity}%</strong>
            </div>
            <div class="progress-bar-track">
              <div class="progress-bar-fill i-fill" style="width: ${risk.ciaImpact.integrity}%"></div>
            </div>
          </div>

          <div class="cia-meter-item">
            <div class="cia-label-row">
              <span>Availability (A)</span>
              <strong>${risk.ciaImpact.availability}%</strong>
            </div>
            <div class="progress-bar-track">
              <div class="progress-bar-fill a-fill" style="width: ${risk.ciaImpact.availability}%"></div>
            </div>
          </div>
        </div>

        <div class="risk-details-columns">
          <div class="risk-info-box">
            <div class="box-title">⚖️ Regulatory & Legal Exposure</div>
            <div class="box-desc">${risk.regulatoryRisk}</div>
          </div>
          <div class="risk-info-box">
            <div class="box-title">💵 Estimated Financial Exposure</div>
            <div class="box-desc">${risk.financialExposureIndex}</div>
          </div>
        </div>
      </div>
    `;
  }

  renderInferenceTrace(result) {
    if (!this.traceContainer) return;

    if (result.firedRules.length === 0) {
      this.traceContainer.innerHTML = `
        <div class="empty-trace-alert">
          <div class="empty-icon">ℹ️</div>
          <h4>No Malicious Rules Triggered (Negative Control / Clean System)</h4>
          <p>The Forward Chaining engine evaluated all rules against current working memory. No production premises were fully satisfied. The system is operating normally without active attack indicators.</p>
        </div>
      `;
      return;
    }

    let traceHtml = `
      <div class="trace-header">
        <h3><span class="icon-trace">⚡</span> Forward-Chaining Inference Execution Trace (XAI)</h3>
        <p class="trace-sub">Deterministic step-by-step record of rules evaluated, premise satisfactions, and asserted conclusions.</p>
      </div>
      <div class="timeline-stepper">
    `;

    result.inferenceTrace.forEach((step, idx) => {
      traceHtml += `
        <div class="timeline-step-item">
          <div class="timeline-marker">Step ${step.step}</div>
          <div class="step-card">
            <div class="step-card-header">
              <div class="rule-title-group">
                <span class="rule-id-badge">${step.ruleId}</span>
                <h4 class="rule-name">${step.ruleName}</h4>
              </div>
              <div class="rule-meta-pills">
                <span class="pill-category">${step.category.toUpperCase()}</span>
                <span class="pill-priority">Priority: ${step.priority}</span>
                <span class="pill-cycle">Cycle: ${step.cycle}</span>
              </div>
            </div>

            <div class="step-rationale">
              <strong>Inference Rationale:</strong> ${step.explanation}
            </div>

            <div class="step-premises-box">
              <div class="box-label">Matched Antecedent Conditions (IF):</div>
              <ul class="conditions-list">
                ${step.matchedConditions.map(c => `
                  <li class="condition-matched">
                    <span class="check-icon">✓</span>
                    <code>${c.condition.fact} ${c.condition.op} ${JSON.stringify(c.condition.value)}</code>
                    <span class="condition-status">(Matched in Working Memory)</span>
                  </li>
                `).join("")}
              </ul>
            </div>

            <div class="step-conclusions-box">
              <div class="box-label">Asserted Consequents into Working Memory (THEN):</div>
              <div class="conclusions-pills">
                ${step.conclusionsAsserted.map(c => `
                  <span class="conclusion-pill">
                    <strong>+ Assert Fact:</strong> <code>${c.fact} = ${JSON.stringify(c.value)}</code>
                  </span>
                `).join("")}
              </div>
            </div>

            <div class="step-mitre-row">
              <span class="mitre-tag"><strong>MITRE ATT&CK:</strong> ${step.mitreRef}</span>
              <span class="nist-tag"><strong>NIST SP 800-61 Phase:</strong> ${step.nistPhase}</span>
              <button type="button" class="btn-inspect-rule" data-rule-id="${step.ruleId}">Deep Inspect Rule</button>
            </div>
          </div>
        </div>
      `;
    });

    traceHtml += `</div>`;
    this.traceContainer.innerHTML = traceHtml;

    // Attach inspect listeners
    document.querySelectorAll(".btn-inspect-rule").forEach(btn => {
      btn.addEventListener("click", () => {
        const ruleId = btn.getAttribute("data-rule-id");
        this.openRuleDetailModal(ruleId);
      });
    });
  }

  /**
   * Render filterable Knowledge Base table
   */
  renderRulesExplorer(rulesList) {
    if (!this.rulesExplorerContainer) return;

    if (rulesList.length === 0) {
      this.rulesExplorerContainer.innerHTML = `<p class="no-records">No rules found matching query.</p>`;
      return;
    }

    let html = `
      <div class="rules-table-container">
        <table class="rules-table">
          <thead>
            <tr>
              <th>Rule ID</th>
              <th>Rule Name & Domain</th>
              <th>Priority</th>
              <th>Severity</th>
              <th>Antecedents (IF)</th>
              <th>Consequents (THEN)</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
    `;

    rulesList.forEach(r => {
      const categoryColor = {
        phishing: "cat-phish",
        malware: "cat-malware",
        ransomware: "cat-ransom",
        suspicious_login: "cat-login",
        data_breach: "cat-breach",
        composite: "cat-comp"
      }[r.category] || "cat-default";

      html += `
        <tr>
          <td><span class="rule-id-code">${r.id}</span></td>
          <td>
            <div class="rule-cell-name">${r.name}</div>
            <span class="rule-cat-tag ${categoryColor}">${r.category.toUpperCase()}</span>
          </td>
          <td><strong>${r.priority}</strong></td>
          <td><span class="sev-tag sev-${r.severity.toLowerCase()}">${r.severity}</span></td>
          <td>
            <ul class="mini-conditions-list">
              ${r.conditions.map(c => `<li><code>${c.fact} ${c.op} ${c.value}</code></li>`).join("")}
            </ul>
          </td>
          <td>
            <ul class="mini-conclusions-list">
              ${r.conclusions.map(c => `<li><code>${c.fact} = ${c.value}</code></li>`).join("")}
            </ul>
          </td>
          <td>
            <button type="button" class="btn-table-inspect" data-rule-id="${r.id}">Inspect</button>
          </td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
      </div>
    `;

    this.rulesExplorerContainer.innerHTML = html;

    // Attach inspect listeners
    document.querySelectorAll(".btn-table-inspect").forEach(btn => {
      btn.addEventListener("click", () => {
        const ruleId = btn.getAttribute("data-rule-id");
        this.openRuleDetailModal(ruleId);
      });
    });
  }

  /**
   * Filter the knowledge base by text search and domain category
   */
  filterRulesExplorer() {
    const query = (this.rulesFilterInput?.value || "").toLowerCase().trim();
    const category = this.rulesCategorySelect?.value || "all";

    const filtered = this.rulesDatabase.filter(r => {
      const matchCat = category === "all" || r.category === category;
      const matchQuery = !query || 
        r.id.toLowerCase().includes(query) ||
        r.name.toLowerCase().includes(query) ||
        r.explanation.toLowerCase().includes(query) ||
        r.conditions.some(c => c.fact.toLowerCase().includes(query));

      return matchCat && matchQuery;
    });

    this.renderRulesExplorer(filtered);
  }

  /**
   * Open XAI Detail Modal for Why / Why Not inspection
   */
  openRuleDetailModal(ruleId) {
    if (!this.modalExplanation || !this.modalContent) return;

    const rule = this.rulesDatabase.find(r => r.id === ruleId);
    if (!rule) return;

    let whyAnalysis = null;
    let whyNotAnalysis = null;

    if (this.engine) {
      whyAnalysis = this.engine.explainWhy(ruleId);
      whyNotAnalysis = this.engine.explainWhyNot(ruleId);
    }

    const isFired = whyAnalysis && whyAnalysis.fired;

    this.modalContent.innerHTML = `
      <div class="modal-rule-header">
        <div class="modal-badge-row">
          <span class="rule-id-code">${rule.id}</span>
          <span class="status-indicator-pill ${isFired ? 'status-fired' : 'status-unfired'}">
            ${isFired ? '✓ FIRED IN CURRENT SESSION' : '○ NOT FIRED'}
          </span>
          <span class="sev-tag sev-${rule.severity.toLowerCase()}">${rule.severity}</span>
        </div>
        <h3 class="modal-rule-title">${rule.name}</h3>
        <p class="modal-rule-domain">Domain: <strong>${rule.category.toUpperCase()}</strong> | Saliency Priority: <strong>${rule.priority}/100</strong></p>
      </div>

      <div class="modal-rule-body">
        <div class="modal-section">
          <h4>Expert Rationale & Logic</h4>
          <p class="modal-text">${rule.explanation}</p>
        </div>

        <div class="modal-section">
          <h4>Antecedent Conditions (IF Premise)</h4>
          <div class="conditions-eval-box">
            ${rule.conditions.map(c => {
              let valInMem = undefined;
              if (this.engine && this.engine.workingMemory) {
                valInMem = this.engine.workingMemory.get(c.fact);
              }
              const conditionPassed = valInMem === c.value;
              return `
                <div class="cond-eval-row ${conditionPassed ? 'cond-passed' : 'cond-failed'}">
                  <span class="eval-icon">${conditionPassed ? '✓' : '✗'}</span>
                  <div class="cond-expr">
                    <code>${c.fact} ${c.op} ${JSON.stringify(c.value)}</code>
                  </div>
                  <div class="cond-mem-status">
                    Working Memory Value: <strong>${valInMem !== undefined ? JSON.stringify(valInMem) : 'UNSET (false)'}</strong>
                  </div>
                </div>
              `;
            }).join("")}
          </div>
        </div>

        <div class="modal-section">
          <h4>Inferred Consequents (THEN Action)</h4>
          <div class="conclusions-list-box">
            ${rule.conclusions.map(c => `
              <div class="concl-row">
                <span class="arrow-icon">➔</span>
                <code>Assert fact: ${c.fact} = ${JSON.stringify(c.value)}</code>
              </div>
            `).join("")}
          </div>
        </div>

        <div class="modal-section">
          <h4>Recommended Incident Response Mitigation Steps</h4>
          <ol class="mitigation-steps-list">
            ${rule.recommendedActions.map(act => `<li>${act}</li>`).join("")}
          </ol>
        </div>

        <div class="modal-section-grid">
          <div><strong>MITRE ATT&CK Mapping:</strong> ${rule.mitreRef}</div>
          <div><strong>NIST SP 800-61 Phase:</strong> ${rule.nistPhase}</div>
        </div>
      </div>
    `;

    this.modalExplanation.classList.remove("hidden");
    this.modalExplanation.setAttribute("aria-hidden", "false");
  }

  closeModal() {
    if (!this.modalExplanation) return;
    this.modalExplanation.classList.add("hidden");
    this.modalExplanation.setAttribute("aria-hidden", "true");
  }

  attachEventListeners() {
    // Search input for knowledge base
    if (this.rulesFilterInput) {
      this.rulesFilterInput.addEventListener("input", () => this.filterRulesExplorer());
    }

    // Category select filter
    if (this.rulesCategorySelect) {
      this.rulesCategorySelect.addEventListener("change", () => this.filterRulesExplorer());
    }

    // Modal close button
    if (this.modalClose) {
      this.modalClose.addEventListener("click", () => this.closeModal());
    }

    // Close modal on backdrop click
    if (this.modalExplanation) {
      this.modalExplanation.addEventListener("click", (e) => {
        if (e.target === this.modalExplanation) {
          this.closeModal();
        }
      });
    }

    // Close on Escape key
    window.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && this.modalExplanation && !this.modalExplanation.classList.contains("hidden")) {
        this.closeModal();
      }
    });
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { ExplanationUIController };
}

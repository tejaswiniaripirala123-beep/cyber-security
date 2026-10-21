/**
 * Cybersecurity Incident-Response Advisory Expert System (CIR-AES)
 * Quantitative Risk Assessment Engine
 * 
 * Computes multi-dimensional risk scores (0-100) based on:
 * - Base Technical Threat Severity (from matched rules)
 * - Asset Criticality Multiplier (Critical Infrastructure, Core DB, User PC)
 * - CIA Triad Impact Vectors (Confidentiality, Integrity, Availability)
 * - Threat Velocity & Exposure Horizon
 * - Regulatory / Compliance Exposure (GDPR, HIPAA, PCI-DSS)
 */

class RiskCalculator {
  static ASSET_WEIGHTS = {
    "CRITICAL": 1.5, // Domain Controllers, Core DBs, Production Cloud Infrastructure
    "HIGH": 1.25,    // Executive Workstations, File Servers, Source Code Repos
    "MEDIUM": 1.0,   // Standard Employee Workstations, Internal Intranet
    "LOW": 0.75      // Test Labs, Isolated Sandbox Environments
  };

  static SEVERITY_BASE = {
    "CRITICAL": 95,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
    "INFORMATIONAL": 10
  };

  /**
   * Computes comprehensive risk evaluation
   * @param {Object} inferenceResult Output from ForwardChainingEngine
   * @param {string} assetCriticality Selected asset tier (CRITICAL, HIGH, MEDIUM, LOW)
   * @param {Object} incidentContext Additional metadata
   */
  static calculate(inferenceResult, assetCriticality = "HIGH", incidentContext = {}) {
    const firedRules = inferenceResult.firedRules || [];
    const memory = inferenceResult.workingMemory || {};

    if (firedRules.length === 0) {
      return {
        score: 12,
        level: "LOW",
        badgeClass: "risk-low",
        slaTarget: "Standard Queue (24 - 48 Hours)",
        ciaImpact: { confidentiality: 10, integrity: 10, availability: 10 },
        regulatoryRisk: "Negligible",
        financialExposureIndex: "Minimal (< $5,000)",
        rationale: "No critical malicious production rules triggered. Activity matches benign administrative operations or low-risk ambient noise."
      };
    }

    // 1. Calculate Rule-Weighted Threat Score
    let maxRuleBase = 20;
    let ruleSum = 0;

    for (const rule of firedRules) {
      const base = this.SEVERITY_BASE[rule.severity] || 30;
      if (base > maxRuleBase) maxRuleBase = base;
      ruleSum += base * (rule.priority / 100);
    }

    const averageRuleScore = ruleSum / firedRules.length;
    // Composite base blends maximum triggered severity with depth of matched indicators
    const compositeBase = (maxRuleBase * 0.7) + (averageRuleScore * 0.3);

    // 2. Asset Criticality Multiplier
    const assetMultiplier = this.ASSET_WEIGHTS[assetCriticality.toUpperCase()] || 1.0;

    // 3. CIA Triad Impact Heuristics
    let cImpact = 20; // Confidentiality
    let iImpact = 20; // Integrity
    let aImpact = 20; // Availability

    // Check memory indicators for CIA vector weighting
    if (memory.data_breach_confirmed || memory.pii_or_financial_records || memory.credential_form_present || memory.browser_credential_store_accessed) {
      cImpact += 65;
    }
    if (memory.file_encryption_observed || memory.registry_run_key_modified || memory.account_added_to_privileged_group || memory.process_injection_detected) {
      iImpact += 60;
    }
    if (memory.file_encryption_observed || memory.vss_shadow_copies_deleted || memory.antivirus_service_terminated || memory.sustained_100_percent_cpu_gpu) {
      aImpact += 70;
    }

    cImpact = Math.min(100, cImpact);
    iImpact = Math.min(100, iImpact);
    aImpact = Math.min(100, aImpact);

    // 4. Raw Numerical Risk Score
    let rawScore = (compositeBase * 0.6 + ((cImpact + iImpact + aImpact) / 3) * 0.4) * (assetMultiplier * 0.85);
    let finalScore = Math.min(100, Math.max(5, Math.round(rawScore)));

    // 5. Categorical Risk Classification & SLA
    let level = "LOW";
    let badgeClass = "risk-low";
    let slaTarget = "Within 24 Hours";
    let incidentPriority = "P4 (Low)";

    if (finalScore >= 85) {
      level = "CRITICAL";
      badgeClass = "risk-critical";
      slaTarget = "Immediate (< 15 Minutes)";
      incidentPriority = "P1 (Critical Sev-1)";
    } else if (finalScore >= 65) {
      level = "HIGH";
      badgeClass = "risk-high";
      slaTarget = "Urgent (< 1 Hour)";
      incidentPriority = "P2 (High Sev-2)";
    } else if (finalScore >= 40) {
      level = "MEDIUM";
      badgeClass = "risk-medium";
      slaTarget = "Expedited (< 4 Hours)";
      incidentPriority = "P3 (Medium Sev-3)";
    }

    // 6. Regulatory & Financial Exposure Mapping
    let regulatoryRisk = "Standard internal telemetry; no mandatory statutory reporting triggered.";
    let financialExposureIndex = "Low ($5,000 - $25,000 Operational Remediation)";

    if (cImpact >= 75 && (memory.pii_or_financial_records || memory.sensitive_file_types_in_stream)) {
      regulatoryRisk = "MANDATORY STATUTORY BREACH REPORTING: High likelihood of GDPR Article 33 / HIPAA / PCI-DSS compliance triggers. 72-hour notification clock active.";
      financialExposureIndex = "Severe ($250,000 - $2,500,000+ Potential fines & forensic audit)";
    } else if (level === "CRITICAL" && (memory.file_encryption_observed || memory.threat_type === "active_destructive_ransomware")) {
      regulatoryRisk = "Critical business interruption risk; potential SEC material cybersecurity disclosure requirements.";
      financialExposureIndex = "Catastrophic ($500,000 - $5,000,000+ Downtime & restoration)";
    }

    return {
      score: finalScore,
      level,
      badgeClass,
      incidentPriority,
      slaTarget,
      assetMultiplier,
      ciaImpact: {
        confidentiality: cImpact,
        integrity: iImpact,
        availability: aImpact
      },
      regulatoryRisk,
      financialExposureIndex,
      rationale: `Computed from ${firedRules.length} triggered rule(s) across target asset class '${assetCriticality}'. Maximum observed threat severity is ${inferenceResult.overallSeverity} with primary impact on ${cImpact >= iImpact && cImpact >= aImpact ? 'Confidentiality' : (iImpact >= aImpact ? 'Data Integrity' : 'System Availability')}.`
    };
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { RiskCalculator };
}

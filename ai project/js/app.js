/**
 * Cybersecurity Incident-Response Advisory Expert System (CIR-AES)
 * Application Entry Point & Orchestrator
 */

class App {
  constructor() {
    this.engine = null;
    this.navigation = null;
    this.triageUI = null;
    this.explanationUI = null;
    this.playbookUI = null;
    this.reportUI = null;
    this.activeAnalysis = null;
  }

  init() {
    console.log("[CIR-AES] Initializing Cybersecurity Incident-Response Advisory Expert System...");

    // 1. Instantiate Core Engine
    this.engine = new ForwardChainingEngine(RULES_DATABASE);

    // 2. Instantiate Navigation
    this.navigation = new NavigationController();

    // 3. Instantiate Explanation UI (Rules Explorer, Trace, XAI Modals)
    this.explanationUI = new ExplanationUIController({
      rules: RULES_DATABASE,
      engine: this.engine
    });

    // 4. Instantiate Playbook UI (Checklist, NIST phases, CLI scripts)
    this.playbookUI = new PlaybookUIController();

    // 5. Instantiate Report Generator
    this.reportUI = new ReportGeneratorUIController();

    // 6. Instantiate Triage UI (Questionnaire, Indicators, Scenario loader)
    this.triageUI = new TriageUIController({
      rules: RULES_DATABASE,
      scenarios: TEST_SCENARIOS,
      onAnalyze: (facts, assetCriticality, context) => {
        this.runAnalysis(facts, assetCriticality, context);
      }
    });

    // 7. Setup Interactive Architecture Diagram Nodes
    this.setupArchitectureInteractions();

    // 8. Setup Live Clock & Stats Telemetry
    this.setupTelemetryDisplay();

    // 9. Load Scenario 2 by default so the user immediately sees a rich triage on arrival
    setTimeout(() => {
      this.triageUI.loadScenario("SCENARIO_2");
    }, 400);

    console.log("[CIR-AES] System operational. 40+ Production Rules loaded into Knowledge Base.");
  }

  /**
   * Main Pipeline: Runs Forward Chaining -> Calculates Risk -> Renders UI Modules
   */
  runAnalysis(facts, assetCriticality, incidentContext) {
    console.log("[CIR-AES] Executing Forward-Chaining Inference Cycle on input facts:", facts);

    // Forward Chaining Execution
    const inferenceResult = this.engine.infer(facts);

    // Quantitative Risk Evaluation
    const riskAssessment = RiskCalculator.calculate(inferenceResult, assetCriticality, incidentContext);

    this.activeAnalysis = {
      facts,
      assetCriticality,
      incidentContext,
      inferenceResult,
      riskAssessment
    };

    // Update UI components
    this.explanationUI.displayResults(inferenceResult, riskAssessment, incidentContext);
    this.playbookUI.renderPlaybook(inferenceResult);
    this.reportUI.generateReport(inferenceResult, riskAssessment, incidentContext);

    // Update global dashboard telemetry pills
    this.updateDashboardCounters(inferenceResult, riskAssessment);
  }

  setupArchitectureInteractions() {
    const archNodes = document.querySelectorAll(".arch-node");
    const archInfoBox = document.getElementById("archNodeInfoBox");

    if (!archNodes || !archInfoBox) return;

    const descriptions = {
      "node-input": "<strong>User & Telemetry Input:</strong> Ingests network indicators, system alerts, user symptoms, IOCs (IP/Hash), and target asset criticality tier.",
      "node-memory": "<strong>Working Memory (Fact Base):</strong> Dynamic in-memory repository of asserted facts and newly derived intermediate conclusions with full provenance tracking.",
      "node-kb": "<strong>Knowledge Base (Rule Repository):</strong> Production memory storing 40+ verified IF-THEN cybersecurity response rules categorized across 5 incident domains.",
      "node-matcher": "<strong>Pattern Matcher:</strong> Continuously compares Working Memory against Rule Antecedents (IF conditions) to identify executable candidate rules.",
      "node-agenda": "<strong>Conflict Resolution (Agenda):</strong> Evaluates satisfied candidate rules using Saliency Priority (1-100) and Specificity metrics to determine firing order.",
      "node-engine": "<strong>Inference Engine (Recognize-Act):</strong> Executes forward-chaining cycles, asserts conclusions, avoids refraction, and halts upon quiescence.",
      "node-xai": "<strong>Explanation Facility (XAI):</strong> Provides transparent 'Why' and 'Why-Not' deduction traces, condition audits, and MITRE ATT&CK technique mapping.",
      "node-playbook": "<strong>Response Advisor & Report:</strong> Generates phase-tailored NIST SP 800-61 containment playbooks, CLI remediation scripts, and printable audit reports."
    };

    archNodes.forEach(node => {
      node.addEventListener("mouseenter", () => {
        const nodeId = node.id;
        if (descriptions[nodeId]) {
          archInfoBox.innerHTML = descriptions[nodeId];
          archInfoBox.classList.add("active-highlight");
        }
      });
      node.addEventListener("click", () => {
        const nodeId = node.id;
        if (descriptions[nodeId]) {
          archInfoBox.innerHTML = descriptions[nodeId];
          archInfoBox.classList.add("active-highlight");
        }
      });
    });
  }

  setupTelemetryDisplay() {
    const clockEl = document.getElementById("systemClock");
    if (clockEl) {
      const updateClock = () => {
        const now = new Date();
        clockEl.textContent = now.toLocaleDateString() + " " + now.toLocaleTimeString();
      };
      updateClock();
      setInterval(updateClock, 1000);
    }
  }

  updateDashboardCounters(result, risk) {
    const heroFired = document.getElementById("dashFiredRules");
    const heroRisk = document.getElementById("dashRiskScore");
    const heroSev = document.getElementById("dashSeverity");

    if (heroFired) heroFired.textContent = result.executionStats.rulesFiredCount;
    if (heroRisk) heroRisk.textContent = `${risk.score}/100`;
    if (heroSev) {
      heroSev.textContent = result.overallSeverity;
      heroSev.className = `stat-highlight sev-${result.overallSeverity.toLowerCase()}`;
    }
  }
}

// Bootstrap application on DOM ready
document.addEventListener("DOMContentLoaded", () => {
  window.app = new App();
  window.app.init();
});

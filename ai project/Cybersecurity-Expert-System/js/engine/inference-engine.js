/**
 * Cybersecurity Incident-Response Advisory Expert System (CIR-AES)
 * Core Inference Engine: Forward-Chaining Production System with Explanation Facility
 * 
 * Implements classical AI Expert System principles:
 * - Working Memory (Dynamic Fact Base)
 * - Knowledge Base (Production Rules: IF-THEN)
 * - Pattern Matcher (Antecedent Evaluation)
 * - Conflict Resolution (Priority / Saliency & Specificity)
 * - Recognize-Act Inference Cycle
 * - Explanation Facility (Trace, Why, Why-Not)
 */

class WorkingMemory {
  constructor(initialFacts = {}) {
    this.facts = new Map();
    this.provenance = new Map(); // tracks whether fact was 'asserted_user' or inferred by 'rule_id'

    for (const [key, value] of Object.entries(initialFacts)) {
      this.set(key, value, "initial_assertion");
    }
  }

  set(factKey, value, source = "user") {
    this.facts.set(factKey, value);
    if (!this.provenance.has(factKey)) {
      this.provenance.set(factKey, {
        source,
        timestamp: new Date().toISOString(),
        value
      });
    }
  }

  get(factKey) {
    return this.facts.get(factKey);
  }

  has(factKey) {
    return this.facts.has(factKey);
  }

  getAll() {
    const obj = {};
    for (const [k, v] of this.facts.entries()) {
      obj[k] = v;
    }
    return obj;
  }

  getProvenance(factKey) {
    return this.provenance.get(factKey);
  }
}

class ForwardChainingEngine {
  constructor(rulesDatabase = []) {
    this.rules = [...rulesDatabase];
    this.workingMemory = new WorkingMemory();
    this.firedRules = new Set();
    this.inferenceTrace = [];
    this.unfiredRulesAnalysis = [];
    this.executionStats = {
      startTime: 0,
      endTime: 0,
      cycles: 0,
      rulesFiredCount: 0
    };
  }

  /**
   * Evaluates a single condition against current working memory
   */
  evaluateCondition(condition, memory) {
    const { fact, op, value } = condition;
    const currentVal = memory.get(fact);

    if (currentVal === undefined) {
      // If not present in memory, only != false or undefined checks could pass
      return op === "!=" ? currentVal !== value : false;
    }

    switch (op) {
      case "==":
      case "=":
        return currentVal === value;
      case "!=":
        return currentVal !== value;
      case ">":
        return currentVal > value;
      case "<":
        return currentVal < value;
      case ">=":
        return currentVal >= value;
      case "<=":
        return currentVal <= value;
      case "contains":
        return Array.isArray(currentVal) ? currentVal.includes(value) : String(currentVal).includes(value);
      case "in":
        return Array.isArray(value) ? value.includes(currentVal) : false;
      default:
        return currentVal === value;
    }
  }

  /**
   * Main forward chaining inference loop
   */
  infer(inputFacts = {}) {
    this.executionStats.startTime = performance.now();
    this.workingMemory = new WorkingMemory(inputFacts);
    this.firedRules.clear();
    this.inferenceTrace = [];
    this.unfiredRulesAnalysis = [];

    let cycleCount = 0;
    const maxCycles = 50; // Safety guard against infinite looping
    let newFactAsserted = true;

    while (newFactAsserted && cycleCount < maxCycles) {
      cycleCount++;
      newFactAsserted = false;

      // 1. MATCH PHASE: find all candidate rules whose premises match current memory
      const candidateRules = [];

      for (const rule of this.rules) {
        // Non-refraction: Do not re-fire an already fired rule
        if (this.firedRules.has(rule.id)) {
          continue;
        }

        const conditionResults = rule.conditions.map(c => ({
          condition: c,
          satisfied: this.evaluateCondition(c, this.workingMemory),
          currentValue: this.workingMemory.get(c.fact)
        }));

        const isFullySatisfied = conditionResults.every(r => r.satisfied);

        if (isFullySatisfied) {
          candidateRules.push({
            rule,
            conditionResults,
            specificity: rule.conditions.length
          });
        }
      }

      // 2. CONFLICT RESOLUTION:
      // Sort candidates by:
      // a) Priority / Saliency (descending)
      // b) Specificity (more premises = more specific, descending)
      candidateRules.sort((a, b) => {
        if (b.rule.priority !== a.rule.priority) {
          return b.rule.priority - a.rule.priority;
        }
        return b.specificity - a.specificity;
      });

      // 3. ACT PHASE: Fire candidates and assert new facts
      for (const candidate of candidateRules) {
        const { rule, conditionResults } = candidate;
        this.firedRules.add(rule.id);

        const assertedInThisRule = [];

        for (const conclusion of rule.conclusions) {
          const currentVal = this.workingMemory.get(conclusion.fact);
          // If conclusion fact doesn't exist or has changed, record new fact
          if (currentVal !== conclusion.value) {
            this.workingMemory.set(conclusion.fact, conclusion.value, rule.id);
            assertedInThisRule.push({
              fact: conclusion.fact,
              value: conclusion.value,
              previous: currentVal
            });
            newFactAsserted = true;
          }
        }

        // Record to audit / explanation trace
        this.inferenceTrace.push({
          step: this.inferenceTrace.length + 1,
          cycle: cycleCount,
          ruleId: rule.id,
          ruleName: rule.name,
          category: rule.category,
          priority: rule.priority,
          severity: rule.severity,
          matchedConditions: conditionResults,
          conclusionsAsserted: assertedInThisRule,
          explanation: rule.explanation,
          mitigation: rule.recommendedActions,
          nistPhase: rule.nistPhase,
          mitreRef: rule.mitreRef,
          timestamp: new Date().toISOString()
        });
      }
    }

    // 4. WHY-NOT ANALYSIS for unfired rules (for XAI transparent inspection)
    for (const rule of this.rules) {
      if (!this.firedRules.has(rule.id)) {
        const missingConditions = [];
        const satisfiedConditions = [];

        for (const condition of rule.conditions) {
          const satisfied = this.evaluateCondition(condition, this.workingMemory);
          const currentVal = this.workingMemory.get(condition.fact);

          if (satisfied) {
            satisfiedConditions.push({ condition, currentVal });
          } else {
            missingConditions.push({
              condition,
              expectedValue: condition.value,
              currentValue: currentVal === undefined ? "UNSET (False)" : currentVal
            });
          }
        }

        this.unfiredRulesAnalysis.push({
          ruleId: rule.id,
          ruleName: rule.name,
          category: rule.category,
          priority: rule.priority,
          satisfiedCount: satisfiedConditions.length,
          totalCount: rule.conditions.length,
          missingConditions
        });
      }
    }

    this.executionStats.endTime = performance.now();
    this.executionStats.cycles = cycleCount;
    this.executionStats.rulesFiredCount = this.firedRules.size;
    this.executionStats.durationMs = +(this.executionStats.endTime - this.executionStats.startTime).toFixed(2);

    return this.generateInferenceResult();
  }

  /**
   * Synthesizes the final advisory payload
   */
  generateInferenceResult() {
    const memoryDump = this.workingMemory.getAll();
    const firedRulesList = this.inferenceTrace.map(t => ({
      id: t.ruleId,
      name: t.ruleName,
      category: t.category,
      severity: t.severity,
      priority: t.priority,
      explanation: t.explanation,
      mitigation: t.mitigation,
      nistPhase: t.nistPhase,
      mitreRef: t.mitreRef,
      matchedConditions: t.matchedConditions,
      conclusions: t.conclusionsAsserted
    }));

    // Aggregate severity from highest fired rule or fallback
    const severityHierarchy = { "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0 };
    let maxSeverity = "LOW";
    let highestScore = 1;

    for (const r of firedRulesList) {
      const score = severityHierarchy[r.severity] || 0;
      if (score > highestScore) {
        highestScore = score;
        maxSeverity = r.severity;
      }
    }

    // Determine primary classified threat
    const primaryThreat = memoryDump.threat_type || memoryDump.composite_threat || "Unspecified / Low-Risk Activity";

    // Deduplicate mitigation actions and group by NIST Phase
    const playbookByPhase = {
      "Immediate Containment": [],
      "Detection & Analysis": [],
      "Eradication": [],
      "Recovery": [],
      "Post-Incident Activity": []
    };

    const seenActions = new Set();

    for (const r of firedRulesList) {
      if (r.mitigation && Array.isArray(r.mitigation)) {
        for (const action of r.mitigation) {
          if (!seenActions.has(action)) {
            seenActions.add(action);
            // Categorize into phase
            const phase = r.nistPhase || "Immediate Containment";
            let targetGroup = "Immediate Containment";
            if (phase.includes("Containment")) targetGroup = "Immediate Containment";
            else if (phase.includes("Eradication")) targetGroup = "Eradication";
            else if (phase.includes("Recovery")) targetGroup = "Recovery";
            else if (phase.includes("Analysis") || phase.includes("Detection")) targetGroup = "Detection & Analysis";

            if (!playbookByPhase[targetGroup]) {
              playbookByPhase[targetGroup] = [];
            }
            playbookByPhase[targetGroup].push({
              action,
              sourceRule: r.id,
              severity: r.severity
            });
          }
        }
      }
    }

    return {
      success: true,
      executionStats: this.executionStats,
      primaryThreat,
      overallSeverity: maxSeverity,
      workingMemory: memoryDump,
      firedRules: firedRulesList,
      unfiredRules: this.unfiredRulesAnalysis,
      inferenceTrace: this.inferenceTrace,
      playbookByPhase
    };
  }

  /**
   * Explanation Facility: "WHY" method
   */
  explainWhy(ruleId) {
    const traceItem = this.inferenceTrace.find(t => t.ruleId === ruleId);
    if (!traceItem) {
      return {
        fired: false,
        explanation: `Rule ${ruleId} did not fire in this session.`
      };
    }
    return {
      fired: true,
      ruleId: traceItem.ruleId,
      ruleName: traceItem.ruleName,
      priority: traceItem.priority,
      reason: traceItem.explanation,
      matchedConditions: traceItem.matchedConditions,
      assertedFacts: traceItem.conclusionsAsserted
    };
  }

  /**
   * Explanation Facility: "WHY NOT" method
   */
  explainWhyNot(ruleId) {
    const unfired = this.unfiredRulesAnalysis.find(u => u.ruleId === ruleId);
    if (!unfired) {
      return {
        fired: true,
        explanation: `Rule ${ruleId} actually fired successfully.`
      };
    }
    return {
      fired: false,
      ruleId: unfired.ruleId,
      ruleName: unfired.ruleName,
      missingConditions: unfired.missingConditions,
      satisfiedRatio: `${unfired.satisfiedCount} / ${unfired.totalCount} conditions met`
    };
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { WorkingMemory, ForwardChainingEngine };
}

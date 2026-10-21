# System Architecture Specification
## Cybersecurity Incident-Response Advisory Expert System (CIR-AES)

---

## 1. Architectural Overview

The CIR-AES system implements a classical **Production System Architecture** as formalized by Newell and Simon (1972) and Giarratano & Riley (2005). The system decouples domain knowledge (the Knowledge Base) from the reasoning logic (the Forward-Chaining Inference Engine) and the operational data (Working Memory).

```
+-----------------------------------------------------------------------------------+
|                                 CIR-AES APPLICATION                              |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  +--------------------+         +--------------------+         +----------------+ |
|  |   Working Memory   |  <--->  |  Inference Engine  |  <--->  | Knowledge Base | |
|  |  (Fact Repository) |         |  (Forward Chaining)|         | (40+ IR Rules) | |
|  +--------------------+         +--------------------+         +----------------+ |
|            ^                              |                            |          |
|            |                              v                            v          |
|  +--------------------+         +--------------------+         +----------------+ |
|  |  Telemetry Intake  |         |   XAI Explanation  |         | NIST Playbook  | |
|  |  (Indicators/IOCs) |         |  (Why / Why-Not)   |         | & Report Gen   | |
|  +--------------------+         +--------------------+         +----------------+ |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

---

## 2. Core Subsystems

### 2.1 Working Memory (`WorkingMemory` Class)
- **Data Structure:** Key-value map storing asserted propositions and ground facts.
- **Fact Provenance:** Each asserted fact records its origin (`initial_assertion`, `user_input`, or the specific `rule_id` that inferred it) and an ISO 8601 timestamp.
- **Operations:**
  - `set(factKey, value, source)`: Inserts or updates a fact.
  - `get(factKey)`: Retrieves the current value of a fact.
  - `has(factKey)`: Checks if a fact is currently present.
  - `getAll()`: Dumps a snapshot of all active facts.

### 2.2 Knowledge Base (`RULES_DATABASE`)
- **Schema:** Declarative JSON production rules with the following structure:
  ```typescript
  interface ProductionRule {
    id: string;               // e.g., "RULE_RAN_001"
    name: string;             // Human-readable title
    category: string;         // "phishing" | "malware" | "ransomware" | "suspicious_login" | "data_breach" | "composite"
    priority: number;         // 1 to 100 (Saliency weight for conflict resolution)
    conditions: Condition[];  // Antecedent premises (conjunction: AND)
    conclusions: Consequent[];// Asserted facts upon firing
    severity: string;         // "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    explanation: string;      // Domain justification for explainability
    mitreRef: string;         // MITRE ATT&CK technique IDs
    nistPhase: string;        // Response lifecycle mapping
    recommendedActions: string[]; // Specific containment directives
  }
  ```

### 2.3 Forward-Chaining Inference Engine (`ForwardChainingEngine` Class)
The engine executes the classical **Recognize-Act Cycle**:
1. **Match Phase:** Evaluates all unfired rules against current Working Memory facts using the condition evaluator.
2. **Conflict Resolution:** When multiple candidate rules are satisfied, sorts candidates using:
   $$\text{Rank}(R) = (\text{Priority}(R) \times 1000) + \text{ConditionCount}(R)$$
3. **Act Phase:** The candidate with the highest rank fires:
   - Derives new facts and asserts them into Working Memory.
   - Marks the rule as fired (`firedRules.add(rule.id)`) to enforce non-refraction.
   - Records the event into `InferenceTrace`.
4. **Quiescence Check:** Repeats until no new facts are asserted or the cycle cap (`maxCycles = 50`) is reached.

---

## 3. Explanation Facility (XAI) Design

The Explanation Facility enables transparent introspection into system decisions:

### 3.1 "Why Did Rule $X$ Fire?"
1. Locates the execution step in the `InferenceTrace`.
2. Retrieves the exact state of Working Memory at the moment of firing.
3. Renders a verified checklist showing how each antecedent condition was satisfied.

### 3.2 "Why Did Rule $Y$ NOT Fire?"
1. Queries the `unfiredRulesAnalysis` repository.
2. Identifies all antecedent conditions that evaluated to `false` or were missing in Working Memory.
3. Reports the exact expected value versus the observed value (e.g., `Expected: vss_shadow_copies_deleted == true; Observed: UNSET (false)`).

---

## 4. Quantitative Risk Assessment Formulation

```
+---------------------------------------------------------------------------------+
|                               RISK EVALUATION MATRIX                            |
+---------------------------------------------------------------------------------+
|  Input: Matched Rules, Asset Tier (0 to 3), CIA Impact Heuristics               |
|                                                                                 |
|  Step 1: Compute Base Threat Score from Fired Rules                             |
|          BaseScore = 0.70 * MaxRuleBase + 0.30 * WeightedAverageRuleScore       |
|                                                                                 |
|  Step 2: Calculate CIA Triad Impact Vectors (0-100)                             |
|          Confidentiality, Integrity, Availability calculated from indicators    |
|                                                                                 |
|  Step 3: Apply Asset Criticality Multiplier                                     |
|          Tier-0 (DC/DB): x1.50 | Tier-1 (Server/Exec): x1.25                    |
|          Tier-2 (Workstation): x1.00 | Tier-3 (Lab): x0.75                      |
|                                                                                 |
|  Step 4: Categorical Mapping & SLA Target Formulation                           |
|          Score >= 85: CRITICAL (Sev-1, < 15 min SLA)                            |
|          Score >= 65: HIGH (Sev-2, < 1 hr SLA)                                  |
|          Score >= 40: MEDIUM (Sev-3, < 4 hr SLA)                                |
|          Score < 40:  LOW (Sev-4, 24 hr SLA)                                    |
+---------------------------------------------------------------------------------+
```

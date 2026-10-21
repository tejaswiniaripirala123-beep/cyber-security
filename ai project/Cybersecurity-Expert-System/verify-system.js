const { RULES_DATABASE } = require('./js/data/rules-database.js');
const { TEST_SCENARIOS } = require('./js/data/test-scenarios.js');
const { ForwardChainingEngine } = require('./js/engine/inference-engine.js');
const { RiskCalculator } = require('./js/engine/risk-calculator.js');

console.log('=== CIR-AES AUTOMATED VERIFICATION SUITE ===');
console.log('Total Production Rules Loaded:', RULES_DATABASE.length);
console.log('Total Test Scenarios Loaded:', TEST_SCENARIOS.length);

// 1. Verify Rule ID uniqueness and format
const ruleIds = new Set();
let ruleErrors = 0;
for (const r of RULES_DATABASE) {
  if (ruleIds.has(r.id)) {
    console.error('DUPLICATE RULE ID:', r.id);
    ruleErrors++;
  }
  ruleIds.add(r.id);
  if (!r.conditions || r.conditions.length === 0) {
    console.error('RULE HAS NO CONDITIONS:', r.id);
    ruleErrors++;
  }
  if (!r.conclusions || r.conclusions.length === 0) {
    console.error('RULE HAS NO CONCLUSIONS:', r.id);
    ruleErrors++;
  }
}
if (ruleErrors === 0) {
  console.log('[PASS] All', RULES_DATABASE.length, 'rules have unique IDs and valid antecedent/consequent structures.');
}

// 2. Instantiate Forward Chaining Engine
const engine = new ForwardChainingEngine(RULES_DATABASE);

// 3. Test each scenario
let allScenariosPassed = true;
TEST_SCENARIOS.forEach((scenario, index) => {
  const result = engine.infer(scenario.facts);
  const risk = RiskCalculator.calculate(result, scenario.assetCriticality, { hostname: 'TEST-HOST' });

  const firedIds = result.firedRules.map(r => r.id);
  const expectedRulesMatched = scenario.expectedRules.every(id => firedIds.includes(id));
  const expectedSevMatched = scenario.expectedSeverity === result.overallSeverity;

  console.log('\n--- Testing ' + scenario.name + ' ---');
  console.log('Cycles: ' + result.executionStats.cycles + ' | Latency: ' + result.executionStats.durationMs + 'ms | Fired Rules: ' + firedIds.length);
  console.log('Triggered Rules:', firedIds);
  console.log('Primary Threat:', result.primaryThreat);
  console.log('Severity: ' + result.overallSeverity + ' | Risk Score: ' + risk.score + ' (' + risk.level + ')');

  if (expectedRulesMatched && expectedSevMatched) {
    console.log('[PASS] Scenario ' + (index + 1) + ' passed completely.');
  } else {
    console.error('[FAIL] Scenario ' + (index + 1) + ' mismatch. Expected rules:', scenario.expectedRules, 'Got:', firedIds);
    allScenariosPassed = false;
  }
});

// 4. Test XAI Explainability on Scenario 2
engine.infer(TEST_SCENARIOS[1].facts); // Run scenario 2
const whyTrace = engine.explainWhy('RULE_RAN_001');
console.log('\n--- Testing XAI Explain Facility (Why RULE_RAN_001 fired) ---');
console.log('Why trace generated:', whyTrace.fired, '| Rule:', whyTrace.ruleName);
console.log('Matched conditions count:', whyTrace.matchedConditions?.length);

const whyNotTrace = engine.explainWhyNot('RULE_PHISH_001');
console.log('--- Testing XAI Explain Facility (Why RULE_PHISH_001 did not fire) ---');
console.log('Why-not analysis generated:', !whyNotTrace.fired, '| Missing conditions count:', whyNotTrace.missingConditions?.length);

console.log('\n===========================================');
if (allScenariosPassed && ruleErrors === 0) {
  console.log('ALL VERIFICATION CHECKS PASSED SUCCESSFULLY (100% ACCURACY)!');
} else {
  console.error('SOME CHECKS FAILED!');
  process.exit(1);
}

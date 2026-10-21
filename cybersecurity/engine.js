/**
 * engine.js — Rule-Based Reasoning Engine
 * Cybersecurity Incident-Response Advisory Expert System
 */

// ─── Knowledge Base: Questions per Incident Type ───────────────────────────

const QUESTIONS = {
  phishing: [
    { id: 'q1', text: 'Did you receive an unexpected email asking for credentials or personal info?', key: 'unexpectedEmail' },
    { id: 'q2', text: 'Did you click on any link or download an attachment from that email?', key: 'clickedLink' },
    { id: 'q3', text: 'Has your account shown any unauthorized login attempts?', key: 'unauthorizedLogin' },
    { id: 'q4', text: 'Did the email sender address look suspicious or misspelled?', key: 'suspiciousSender' },
    { id: 'q5', text: 'Were you directed to a fake login page that looked like a legitimate site?', key: 'fakePage' },
  ],
  malware: [
    { id: 'q1', text: 'Is your system running unusually slowly or crashing frequently?', key: 'slowSystem' },
    { id: 'q2', text: 'Have you noticed unfamiliar programs or processes running?', key: 'unknownProcesses' },
    { id: 'q3', text: 'Did you recently install software from an untrusted source?', key: 'untrustedSoftware' },
    { id: 'q4', text: 'Are your antivirus alerts triggering frequently?', key: 'avAlerts' },
    { id: 'q5', text: 'Have any files been modified or deleted without your action?', key: 'filesModified' },
  ],
  ransomware: [
    { id: 'q1', text: 'Are your files showing unusual extensions (e.g., .locked, .encrypted)?', key: 'unusualExtensions' },
    { id: 'q2', text: 'Is there a ransom note displayed on your screen or in folders?', key: 'ransomNote' },
    { id: 'q3', text: 'Are you unable to open your documents, images, or other files?', key: 'cantOpenFiles' },
    { id: 'q4', text: 'Did you recently open an email attachment or visit a suspicious website?', key: 'recentSuspiciousAction' },
    { id: 'q5', text: 'Has your desktop background changed to a ransom demand message?', key: 'desktopChanged' },
  ],
  suspiciousLogin: [
    { id: 'q1', text: 'Have you received alerts about logins from unfamiliar locations or devices?', key: 'unfamiliarLogin' },
    { id: 'q2', text: 'Are there account activities you do not recognize?', key: 'unrecognizedActivity' },
    { id: 'q3', text: 'Were there multiple failed login attempts before a successful one?', key: 'multipleFailedLogins' },
    { id: 'q4', text: 'Has your password been changed without your authorization?', key: 'passwordChanged' },
    { id: 'q5', text: 'Are you receiving 2FA codes you did not request?', key: 'unexpected2FA' },
  ],
  dataBreach: [
    { id: 'q1', text: 'Have you been notified that your data appeared in a breach database?', key: 'breachNotification' },
    { id: 'q2', text: 'Have sensitive files or records been accessed or exported without authorization?', key: 'unauthorizedAccess' },
    { id: 'q3', text: 'Is there unusual outbound network traffic from your systems?', key: 'unusualTraffic' },
    { id: 'q4', text: 'Are there logs showing access by unknown user accounts?', key: 'unknownAccounts' },
    { id: 'q5', text: 'Have customers or employees reported receiving spam from your domain?', key: 'spamReports' },
  ],
};

// ─── Rules: IF conditions THEN result ──────────────────────────────────────

const RULES = {
  phishing: [
    {
      id: 'R-PH-01',
      conditions: { unexpectedEmail: true, clickedLink: true, fakePage: true },
      label: 'High-Confidence Phishing Attack',
      severity: 'Critical',
      explanation: 'IF unexpected credential email received AND link clicked AND redirected to fake page THEN Critical Phishing confirmed.',
      steps: [
        'Immediately change all passwords for affected accounts.',
        'Enable Multi-Factor Authentication (MFA) on all accounts.',
        'Report the phishing email to your IT/security team.',
        'Contact your bank if financial credentials were entered.',
        'Run a full antivirus scan on the affected device.',
        'Monitor accounts for unauthorized transactions.',
        'Report the phishing URL to Google Safe Browsing or your email provider.',
      ],
    },
    {
      id: 'R-PH-02',
      conditions: { unexpectedEmail: true, suspiciousSender: true },
      label: 'Suspected Phishing Attempt',
      severity: 'High',
      explanation: 'IF unexpected credential email AND suspicious sender address THEN Phishing attempt suspected.',
      steps: [
        'Do NOT click any links or download attachments.',
        'Report the email as phishing in your email client.',
        'Verify with the supposed sender through a separate communication channel.',
        'Alert your IT department or security team.',
        'Check if others in your organization received the same email.',
      ],
    },
    {
      id: 'R-PH-03',
      conditions: { unauthorizedLogin: true },
      label: 'Phishing — Account Compromise Detected',
      severity: 'Critical',
      explanation: 'IF unauthorized login attempts detected after suspected phishing THEN account compromise likely.',
      steps: [
        'Immediately reset all account passwords.',
        'Revoke active sessions from all devices.',
        'Enable MFA if not already enabled.',
        'Review account activity logs for unauthorized changes.',
        'Notify affected parties if sensitive data was accessed.',
      ],
    },
  ],
  malware: [
    {
      id: 'R-ML-01',
      conditions: { unknownProcesses: true, filesModified: true },
      label: 'Active Malware Infection',
      severity: 'Critical',
      explanation: 'IF unknown processes running AND files modified without user action THEN active malware infection detected.',
      steps: [
        'Isolate the infected machine from the network immediately.',
        'Run a full scan using updated antivirus/anti-malware software.',
        'Identify and terminate malicious processes via Task Manager.',
        'Document all observed symptoms for forensic analysis.',
        'Restore affected files from clean backup if available.',
        'Reinstall the operating system if infection is severe.',
        'Report the incident to your IT/security team.',
      ],
    },
    {
      id: 'R-ML-02',
      conditions: { untrustedSoftware: true, avAlerts: true },
      label: 'Malware from Untrusted Software',
      severity: 'High',
      explanation: 'IF untrusted software installed AND antivirus alerts triggered THEN malware from untrusted source.',
      steps: [
        'Uninstall the suspicious software immediately.',
        'Run a full antivirus scan and quarantine threats.',
        'Check startup programs and browser extensions for malware.',
        'Reset browser settings if browser-based malware suspected.',
        'Change passwords after cleaning the system.',
      ],
    },
    {
      id: 'R-ML-03',
      conditions: { slowSystem: true, avAlerts: true },
      label: 'Possible Malware — System Compromise',
      severity: 'Medium',
      explanation: 'IF system running slowly AND AV alerts triggering THEN possible malware activity.',
      steps: [
        'Update antivirus definitions and run a full scan.',
        'Check Task Manager for unusual CPU or memory usage.',
        'Review recently installed programs.',
        'Consider professional malware removal if scan is inconclusive.',
      ],
    },
  ],
  ransomware: [
    {
      id: 'R-RW-01',
      conditions: { ransomNote: true, cantOpenFiles: true, unusualExtensions: true },
      label: 'Confirmed Ransomware Attack',
      severity: 'Critical',
      explanation: 'IF ransom note displayed AND files inaccessible AND unusual extensions found THEN Ransomware attack confirmed.',
      steps: [
        'Immediately disconnect the device from all networks (Wi-Fi, LAN).',
        'Do NOT pay the ransom — it does not guarantee file recovery.',
        'Photograph the ransom note for documentation.',
        'Report to law enforcement (e.g., FBI IC3, local authorities).',
        'Identify the ransomware variant using tools like ID Ransomware.',
        'Restore files from offline/clean backups.',
        'Engage a professional incident response team.',
        'Reimage the system after full forensic analysis.',
      ],
    },
    {
      id: 'R-RW-02',
      conditions: { cantOpenFiles: true, unusualExtensions: true },
      label: 'Likely Ransomware — File Encryption Detected',
      severity: 'Critical',
      explanation: 'IF files cannot be opened AND unusual file extensions found THEN file encryption/ransomware likely.',
      steps: [
        'Disconnect from network immediately.',
        'Do not attempt to decrypt files without expert guidance.',
        'Check for ransom notes in encrypted folders.',
        'Contact your IT security team or a cybersecurity firm.',
        'Restore from clean backup if available.',
      ],
    },
    {
      id: 'R-RW-03',
      conditions: { recentSuspiciousAction: true, unusualExtensions: true },
      label: 'Ransomware — Entry via Suspicious Action',
      severity: 'High',
      explanation: 'IF suspicious email/website visited AND unusual extensions found THEN ransomware entry vector identified.',
      steps: [
        'Isolate the system from the network.',
        'Run antivirus in safe mode.',
        'Identify the attack vector and close it.',
        'Report to IT security team.',
        'Begin restoration from backup.',
      ],
    },
  ],
  suspiciousLogin: [
    {
      id: 'R-SL-01',
      conditions: { passwordChanged: true, unfamiliarLogin: true },
      label: 'Account Takeover Detected',
      severity: 'Critical',
      explanation: 'IF password changed without authorization AND login from unfamiliar location THEN account takeover confirmed.',
      steps: [
        'Use account recovery to regain access immediately.',
        "Contact the service provider's security team.",
        'Revoke all active sessions for the account.',
        'Enable MFA after regaining access.',
        'Review all account activity and changes made by attacker.',
        'Change passwords for linked accounts.',
        'Monitor financial accounts for unauthorized activity.',
      ],
    },
    {
      id: 'R-SL-02',
      conditions: { multipleFailedLogins: true, unfamiliarLogin: true },
      label: 'Brute Force / Credential Stuffing Attack',
      severity: 'High',
      explanation: 'IF multiple failed logins AND login from unfamiliar location THEN brute force or credential stuffing attack.',
      steps: [
        'Enable account lockout after failed attempts.',
        'Enable MFA on the account immediately.',
        'Change the account password to a strong, unique one.',
        'Review access logs for the timeline of the attack.',
        'Consider blocking suspicious IP ranges.',
      ],
    },
    {
      id: 'R-SL-03',
      conditions: { unexpected2FA: true },
      label: 'Unauthorized Access Attempt — 2FA Bypass',
      severity: 'High',
      explanation: 'IF 2FA codes received without user request THEN attacker attempting to bypass 2FA.',
      steps: [
        'Do not share or enter any unsolicited 2FA codes.',
        'Change your account password immediately.',
        'Review linked phone numbers and email addresses.',
        'Report to the service provider.',
        'Enable hardware security keys if available.',
      ],
    },
  ],
  dataBreach: [
    {
      id: 'R-DB-01',
      conditions: { unauthorizedAccess: true, unusualTraffic: true },
      label: 'Active Data Exfiltration Detected',
      severity: 'Critical',
      explanation: 'IF unauthorized data access AND unusual outbound network traffic THEN active data exfiltration in progress.',
      steps: [
        'Immediately block suspicious outbound connections using firewall rules.',
        'Preserve network logs for forensic analysis.',
        'Identify what data was accessed and exfiltrated.',
        'Notify affected individuals per data protection regulations (GDPR, HIPAA).',
        'Engage legal counsel and a data breach response team.',
        'Report to relevant regulatory authorities within required timeframes.',
        'Issue public statement if required by law.',
      ],
    },
    {
      id: 'R-DB-02',
      conditions: { breachNotification: true, unknownAccounts: true },
      label: 'Data Breach via Unauthorized Account Access',
      severity: 'High',
      explanation: 'IF breach database notification AND unknown account access logs found THEN data breach through unauthorized accounts.',
      steps: [
        'Disable or remove unknown user accounts immediately.',
        'Audit all user access privileges.',
        'Reset credentials for all potentially compromised accounts.',
        'Identify the scope of data accessed.',
        'Notify affected users and regulatory bodies.',
      ],
    },
    {
      id: 'R-DB-03',
      conditions: { spamReports: true, unknownAccounts: true },
      label: 'Data Breach — Email/Contact List Exposed',
      severity: 'Medium',
      explanation: 'IF spam sent from your domain AND unknown accounts found THEN contact list or email system likely breached.',
      steps: [
        'Secure email server and mail relay configurations.',
        'Remove unauthorized accounts.',
        'Notify contacts that spam was sent from your domain.',
        'Check for mail forwarding rules set by attacker.',
        'Report to your email service provider.',
      ],
    },
  ],
};

// ─── Severity Ordering ─────────────────────────────────────────────────────

const SEVERITY_ORDER = { Critical: 4, High: 3, Medium: 2, Low: 1 };

// ─── Default Low-Severity Response ────────────────────────────────────────

const DEFAULT_RESPONSE = {
  matchedRules: [],
  severity: 'Low',
  label: 'No Immediate Threat Detected',
  explanation: 'Based on your answers, no specific rules were triggered. Continue monitoring and apply general security best practices.',
  steps: [
    'Keep your operating system and software up to date.',
    'Use strong, unique passwords for every account.',
    'Enable Multi-Factor Authentication wherever possible.',
    'Regularly back up important data to an offline or cloud location.',
    'Stay vigilant and report anything suspicious to your IT team.',
  ],
};

// ─── RuleEngine ────────────────────────────────────────────────────────────

const RuleEngine = {
  /**
   * Run the reasoning engine.
   * @param {string} incidentType - Key from QUESTIONS (e.g. 'phishing')
   * @param {Object} answers - Map of { key: true|false }
   * @returns {Object} result with matchedRules, severity, label, steps
   */
  evaluate(incidentType, answers) {
    const rules = RULES[incidentType];
    if (!rules) {
      return Object.assign({}, DEFAULT_RESPONSE);
    }

    const matchedRules = [];

    for (const rule of rules) {
      const conditionKeys = Object.keys(rule.conditions);
      const allMatch = conditionKeys.every(
        (key) => answers[key] === rule.conditions[key]
      );
      if (allMatch) {
        matchedRules.push(rule);
      }
    }

    if (matchedRules.length === 0) {
      return Object.assign({}, DEFAULT_RESPONSE);
    }

    // Find the highest severity among matched rules
    let topSeverity = 'Low';
    for (const rule of matchedRules) {
      if ((SEVERITY_ORDER[rule.severity] || 0) > (SEVERITY_ORDER[topSeverity] || 0)) {
        topSeverity = rule.severity;
      }
    }

    // Primary rule = the one with the highest severity (first found wins ties)
    const primaryRule = matchedRules.find((r) => r.severity === topSeverity);

    // Merge steps from all matched rules (deduplicated)
    const allSteps = [];
    const seen = new Set();
    for (const rule of matchedRules) {
      for (const step of rule.steps) {
        if (!seen.has(step)) {
          seen.add(step);
          allSteps.push(step);
        }
      }
    }

    return {
      matchedRules,
      severity: topSeverity,
      label: primaryRule.label,
      explanation: primaryRule.explanation,
      steps: allSteps,
    };
  },

  /** Returns question list for a given incident type */
  getQuestions(incidentType) {
    return QUESTIONS[incidentType] || [];
  },

  /** Returns all rules for a given incident type */
  getRules(incidentType) {
    return RULES[incidentType] || [];
  },

  /** Returns all incident type keys */
  getIncidentTypes() {
    return Object.keys(QUESTIONS);
  },
};

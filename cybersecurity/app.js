/**
 * app.js — UI Logic, Navigation, Forms, History
 * Cybersecurity Incident-Response Advisory Expert System
 */

'use strict';

// ─── Sample History Records ────────────────────────────────────────────────

const HISTORY = [
  {
    id: 'INC-001',
    date: '2026-10-15',
    type: 'Phishing',
    severity: 'Critical',
    status: 'Resolved',
    analyst: 'SOC Analyst',
    summary: 'Employee received credential phishing email. Credentials were entered on a fake login page.',
    steps: ['Password reset', 'MFA enabled', 'Email provider reported', 'AV scan completed'],
  },
  {
    id: 'INC-002',
    date: '2026-10-12',
    type: 'Ransomware',
    severity: 'Critical',
    status: 'Escalated',
    analyst: 'IR Team Lead',
    summary: 'Multiple workstations encrypted with .locked extension. Ransom note found.',
    steps: ['Network isolated', 'Law enforcement notified', 'Backups restored', 'IR team engaged'],
  },
  {
    id: 'INC-003',
    date: '2026-10-10',
    type: 'Malware Infection',
    severity: 'High',
    status: 'Resolved',
    analyst: 'Malware Analyst',
    summary: 'Malware installed via cracked software download. AV detected multiple threats.',
    steps: ['Software removed', 'Full AV scan', 'Password changed', 'System reimaged'],
  },
  {
    id: 'INC-004',
    date: '2026-10-08',
    type: 'Suspicious Login',
    severity: 'High',
    status: 'Resolved',
    analyst: 'Identity Security Team',
    summary: 'Multiple failed logins followed by successful login from foreign IP.',
    steps: ['Account locked', 'Password reset', 'MFA enforced', 'IP blocked'],
  },
  {
    id: 'INC-005',
    date: '2026-10-05',
    type: 'Data Breach',
    severity: 'Critical',
    status: 'Under Investigation',
    analyst: 'Data Protection Officer',
    summary: 'Unusual outbound traffic detected. Unknown accounts found in access logs.',
    steps: ['Firewall rules updated', 'Accounts disabled', 'Legal notified', 'Forensics in progress'],
  },
  {
    id: 'INC-006',
    date: '2026-10-01',
    type: 'Phishing',
    severity: 'High',
    status: 'Resolved',
    analyst: 'Threat Intelligence Team',
    summary: 'Suspicious email with spoofed sender detected. No credentials entered.',
    steps: ['Email reported', 'Team alerted', 'Sender blocked'],
  },
  {
    id: 'INC-007',
    date: '2026-09-28',
    type: 'Malware Infection',
    severity: 'Medium',
    status: 'Resolved',
    analyst: 'Malware Analyst',
    summary: 'System slowdown and AV alerts. Adware detected and removed.',
    steps: ['Adware quarantined', 'Browser reset', 'AV updated'],
  },
  {
    id: 'INC-008',
    date: '2026-09-25',
    type: 'Data Breach',
    severity: 'Medium',
    status: 'Resolved',
    analyst: 'Data Protection Officer',
    summary: 'Spam sent from company domain. Email account compromised via weak password.',
    steps: ['Password reset', 'Spam filter updated', 'Contacts notified'],
  },
];

// ─── Incident Type Display Metadata ───────────────────────────────────────

const INCIDENT_META = {
  phishing: {
    label: 'Phishing',
    icon: '🎣',
    desc: 'Deceptive emails or messages designed to steal credentials or personal information.',
  },
  malware: {
    label: 'Malware Infection',
    icon: '🦠',
    desc: 'Malicious software that damages, disrupts, or gains unauthorized access to systems.',
  },
  ransomware: {
    label: 'Ransomware',
    icon: '🔒',
    desc: 'Malware that encrypts files and demands payment for decryption keys.',
  },
  suspiciousLogin: {
    label: 'Suspicious Login',
    icon: '🔑',
    desc: 'Unauthorized or anomalous login activity detected on user accounts.',
  },
  dataBreach: {
    label: 'Data Breach',
    icon: '💾',
    desc: 'Unauthorized access to or exfiltration of sensitive organizational data.',
  },
};

// ─── Application State ─────────────────────────────────────────────────────

const state = {
  currentSection: 'home',
  assessment: {
    step: 1,
    selectedType: null,
    answers: {},
  },
};

// ─── DOM Helpers ───────────────────────────────────────────────────────────

function $(id) {
  return document.getElementById(id);
}

function show(el) {
  if (el) el.classList.remove('hidden');
}

function hide(el) {
  if (el) el.classList.add('hidden');
}

function severityClass(severity) {
  const map = {
    Critical: 'severity-critical',
    High: 'severity-high',
    Medium: 'severity-medium',
    Low: 'severity-low',
  };
  return map[severity] || 'severity-low';
}

function statusClass(status) {
  const map = {
    Resolved: 'status-resolved',
    Escalated: 'status-escalated',
    'Under Investigation': 'status-investigating',
  };
  return map[status] || '';
}

// ─── Navigation ────────────────────────────────────────────────────────────

function navigateTo(sectionId) {
  // Hide all sections
  document.querySelectorAll('.section').forEach((s) => s.classList.remove('active'));

  // Show target section
  const target = $('section-' + sectionId);
  if (target) target.classList.add('active');

  // Update active nav link
  document.querySelectorAll('.nav-link').forEach((link) => {
    link.classList.toggle('active', link.dataset.section === sectionId);
  });

  state.currentSection = sectionId;

  // Auto-close sidebar on mobile
  const sidebar = $('sidebar');
  if (window.innerWidth <= 768 && sidebar) {
    sidebar.classList.remove('open');
  }

  // Scroll to top
  window.scrollTo(0, 0);
}

// ─── Mobile Sidebar Toggle ─────────────────────────────────────────────────

function initSidebar() {
  const hamburger = $('hamburger');
  const sidebar = $('sidebar');
  const overlay = $('sidebar-overlay');

  if (hamburger && sidebar) {
    hamburger.addEventListener('click', () => {
      sidebar.classList.toggle('open');
      if (overlay) overlay.classList.toggle('active');
    });
  }

  if (overlay) {
    overlay.addEventListener('click', () => {
      if (sidebar) sidebar.classList.remove('open');
      overlay.classList.remove('active');
    });
  }
}

// ─── Assessment Wizard ─────────────────────────────────────────────────────

function initAssessment() {
  // Render type selection cards
  renderTypeCards();

  // Wire up Next/Back buttons
  const btnNext1 = $('btn-next-step1');
  const btnNext2 = $('btn-next-step2');
  const btnBack2 = $('btn-back-step2');
  const btnRestart = $('btn-restart');
  const btnStartAssessment = $('btn-start-assessment');

  if (btnNext1) btnNext1.addEventListener('click', goToStep2);
  if (btnNext2) btnNext2.addEventListener('click', goToStep3);
  if (btnBack2) btnBack2.addEventListener('click', goToStep1);
  if (btnRestart) btnRestart.addEventListener('click', resetAssessment);
  if (btnStartAssessment) {
    btnStartAssessment.addEventListener('click', () => {
      navigateTo('assessment');
    });
  }
}

function renderTypeCards() {
  const container = $('type-cards');
  if (!container) return;

  container.innerHTML = '';
  const types = RuleEngine.getIncidentTypes();

  types.forEach((typeKey) => {
    const meta = INCIDENT_META[typeKey];
    const card = document.createElement('label');
    card.className = 'type-card';
    card.setAttribute('for', 'type-' + typeKey);
    card.innerHTML = `
      <input type="radio" name="incident-type" id="type-${typeKey}" value="${typeKey}" />
      <div class="type-card-inner">
        <div class="type-icon">${meta.icon}</div>
        <div class="type-label">${meta.label}</div>
        <div class="type-desc">${meta.desc}</div>
      </div>
    `;
    container.appendChild(card);
  });

  // Update card selected state on radio change
  container.addEventListener('change', (e) => {
    container.querySelectorAll('.type-card').forEach((c) => c.classList.remove('selected'));
    if (e.target.type === 'radio') {
      e.target.closest('.type-card').classList.add('selected');
      state.assessment.selectedType = e.target.value;
    }
  });
}

function goToStep1() {
  state.assessment.step = 1;
  state.assessment.selectedType = null;
  state.assessment.answers = {};
  updateProgressBar(1);
  showStep(1);
}

function goToStep2() {
  // Validate type selection
  const selected = document.querySelector('input[name="incident-type"]:checked');
  if (!selected) {
    showAlert('Please select an incident type before continuing.', 'warning');
    return;
  }

  state.assessment.selectedType = selected.value;
  state.assessment.step = 2;

  // Render questions
  renderQuestions(state.assessment.selectedType);

  updateProgressBar(2);
  showStep(2);
}

function goToStep3() {
  // Validate all questions answered
  const questions = RuleEngine.getQuestions(state.assessment.selectedType);
  const answers = {};
  let allAnswered = true;

  questions.forEach((q) => {
    const yesEl = document.querySelector(`input[name="${q.key}"][value="yes"]`);
    const noEl = document.querySelector(`input[name="${q.key}"][value="no"]`);
    if (yesEl && yesEl.checked) {
      answers[q.key] = true;
    } else if (noEl && noEl.checked) {
      answers[q.key] = false;
    } else {
      allAnswered = false;
    }
  });

  if (!allAnswered) {
    showAlert('Please answer all questions before proceeding.', 'warning');
    return;
  }

  state.assessment.answers = answers;
  state.assessment.step = 3;

  // Run engine
  const result = RuleEngine.evaluate(state.assessment.selectedType, answers);

  // Render results
  renderResults(result);

  updateProgressBar(3);
  showStep(3);
}

function showStep(stepNum) {
  [1, 2, 3].forEach((n) => {
    const el = $('step-' + n);
    if (el) el.classList.toggle('active-step', n === stepNum);
  });
}

function updateProgressBar(stepNum) {
  const fill = $('progress-fill');
  const steps = document.querySelectorAll('.progress-step');

  const pct = ((stepNum - 1) / 2) * 100;
  if (fill) fill.style.width = pct + '%';

  steps.forEach((s, i) => {
    const num = i + 1;
    s.classList.toggle('completed', num < stepNum);
    s.classList.toggle('current', num === stepNum);
  });
}

function renderQuestions(typeKey) {
  const container = $('questions-container');
  if (!container) return;

  const meta = INCIDENT_META[typeKey];
  const questions = RuleEngine.getQuestions(typeKey);

  const header = $('questions-header');
  if (header) {
    header.textContent = `${meta.icon} ${meta.label} — Diagnostic Questions`;
  }

  container.innerHTML = '';
  questions.forEach((q, idx) => {
    const item = document.createElement('div');
    item.className = 'question-item';
    item.innerHTML = `
      <div class="question-text">
        <span class="question-num">Q${idx + 1}</span>
        ${q.text}
      </div>
      <div class="question-options">
        <label class="option-btn yes-option">
          <input type="radio" name="${q.key}" value="yes" />
          <span>✔ Yes</span>
        </label>
        <label class="option-btn no-option">
          <input type="radio" name="${q.key}" value="no" />
          <span>✘ No</span>
        </label>
      </div>
    `;
    container.appendChild(item);
  });

  // Highlight selected option labels
  container.addEventListener('change', (e) => {
    if (e.target.type === 'radio') {
      const name = e.target.name;
      container.querySelectorAll(`input[name="${name}"]`).forEach((input) => {
        input.closest('.option-btn').classList.remove('selected');
      });
      e.target.closest('.option-btn').classList.add('selected');
    }
  });
}

function renderResults(result) {
  const container = $('results-container');
  if (!container) return;

  const typeKey = state.assessment.selectedType;
  const meta = INCIDENT_META[typeKey];
  const sevClass = severityClass(result.severity);

  // Build matched rules HTML
  let rulesHtml = '';
  if (result.matchedRules && result.matchedRules.length > 0) {
    rulesHtml = result.matchedRules
      .map(
        (r) => `
        <div class="rule-item">
          <div class="rule-id">${r.id}</div>
          <div class="rule-label">${r.label}</div>
          <div class="rule-explanation">${r.explanation}</div>
        </div>
      `
      )
      .join('');
  } else {
    rulesHtml = '<p class="no-rules">No specific rules matched. Showing default guidance.</p>';
  }

  // Build steps HTML
  const stepsHtml = result.steps
    .map((step, i) => `<li><span class="step-num">${i + 1}</span>${step}</li>`)
    .join('');

  container.innerHTML = `
    <div class="results-header">
      <div class="results-icon">${meta.icon}</div>
      <div class="results-title-block">
        <h2>${result.label}</h2>
        <div class="results-meta">
          <span class="incident-type-badge">${meta.label}</span>
          <span class="severity-badge ${sevClass}">${result.severity}</span>
        </div>
      </div>
    </div>

    <div class="results-grid">
      <div class="result-card">
        <h3>🔍 Matched Rules</h3>
        <div class="matched-rules">
          ${rulesHtml}
        </div>
      </div>

      <div class="result-card">
        <h3>📋 Recommended Response Steps</h3>
        <ol class="response-steps">
          ${stepsHtml}
        </ol>
      </div>
    </div>
  `;
}

function resetAssessment() {
  state.assessment = { step: 1, selectedType: null, answers: {} };

  // Uncheck all type radios
  document.querySelectorAll('input[name="incident-type"]').forEach((r) => {
    r.checked = false;
  });
  document.querySelectorAll('.type-card').forEach((c) => c.classList.remove('selected'));

  updateProgressBar(1);
  showStep(1);
}

// ─── Alert Toast ───────────────────────────────────────────────────────────

function showAlert(message, type) {
  const existing = document.querySelector('.toast-alert');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.className = `toast-alert toast-${type}`;
  toast.innerHTML = `<span>${message}</span><button onclick="this.parentElement.remove()">✕</button>`;
  document.body.appendChild(toast);

  setTimeout(() => {
    if (toast.parentElement) toast.remove();
  }, 4000);
}

// ─── Incident History ──────────────────────────────────────────────────────

function initHistory() {
  renderHistoryTable(HISTORY);

  const filterEl = $('history-filter');
  if (filterEl) {
    filterEl.addEventListener('change', () => {
      const val = filterEl.value;
      const filtered = val ? HISTORY.filter((h) => h.type === val) : HISTORY;
      renderHistoryTable(filtered);
    });
  }
}

function renderHistoryTable(records) {
  const tbody = $('history-tbody');
  if (!tbody) return;

  if (records.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-row">No records match the selected filter.</td></tr>';
    return;
  }

  tbody.innerHTML = records
    .map(
      (rec) => `
    <tr>
      <td><span class="inc-id">${rec.id}</span></td>
      <td>${rec.date}</td>
      <td>${rec.type}</td>
      <td><span class="severity-badge ${severityClass(rec.severity)}">${rec.severity}</span></td>
      <td><span class="status-badge ${statusClass(rec.status)}">${rec.status}</span></td>
      <td>
        <button class="btn-view" onclick="openModal('${rec.id}')">👁 View</button>
      </td>
    </tr>
  `
    )
    .join('');
}

function openModal(incidentId) {
  const rec = HISTORY.find((h) => h.id === incidentId);
  if (!rec) return;

  const modal = $('incident-modal');
  const modalContent = $('modal-content-inner');

  if (!modal || !modalContent) return;

  const sevClass = severityClass(rec.severity);
  const statClass = statusClass(rec.status);

  const stepsHtml = rec.steps.map((s, i) => `<li><span class="step-num">${i + 1}</span>${s}</li>`).join('');

  modalContent.innerHTML = `
    <div class="modal-header-info">
      <span class="inc-id">${rec.id}</span>
      <span class="severity-badge ${sevClass}">${rec.severity}</span>
      <span class="status-badge ${statClass}">${rec.status}</span>
    </div>
    <div class="modal-grid">
      <div class="modal-row"><span class="modal-label">Date:</span><span>${rec.date}</span></div>
      <div class="modal-row"><span class="modal-label">Type:</span><span>${rec.type}</span></div>
      <div class="modal-row"><span class="modal-label">Analyst:</span><span>${rec.analyst}</span></div>
    </div>
    <div class="modal-summary">
      <strong>Summary:</strong>
      <p>${rec.summary}</p>
    </div>
    <div class="modal-steps">
      <strong>Response Actions Taken:</strong>
      <ol>${stepsHtml}</ol>
    </div>
  `;

  modal.classList.add('active');
  document.body.classList.add('modal-open');
}

function closeModal() {
  const modal = $('incident-modal');
  if (modal) modal.classList.remove('active');
  document.body.classList.remove('modal-open');
}

// ─── Initialisation ────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  // Set up navigation links
  document.querySelectorAll('.nav-link').forEach((link) => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const section = link.dataset.section;
      if (section) navigateTo(section);
    });
  });

  // Initialise modules
  initSidebar();
  initAssessment();
  initHistory();

  // Modal close button
  const modalClose = $('modal-close');
  if (modalClose) modalClose.addEventListener('click', closeModal);

  // Close modal on backdrop click
  const modal = $('incident-modal');
  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeModal();
    });
  }

  // Show home by default
  navigateTo('home');
  showStep(1);
  updateProgressBar(1);
});

# Cybersecurity Incident-Response Advisory Expert System (CIR-AES)
### College Capstone Project: Rule-Based Artificial Intelligence in Cybersecurity

---

## 📌 Project Overview

The **Cybersecurity Incident-Response Advisory Expert System (CIR-AES)** is a college capstone engineering project that implements an Explainable AI (XAI) production system using **forward-chaining rule-based reasoning**.

The system automates incident triage, severity classification, and response formulation across five major enterprise cyber attack categories:
1. **Phishing & Social Engineering** (Spear phishing, weaponized Office macros, BEC financial fraud, AiTM reverse proxies).
2. **Malware Infection & Command-and-Control** (LotL binary abuse, process hollowing/LSASS injection, C2 beaconing, infostealers).
3. **Ransomware Outbreak** (Mass file encryption, volume shadow copy deletion, honeypot canary trips, double-extortion staging).
4. **Suspicious Login & Identity Anomalies** (Impossible travel velocity, MFA push fatigue bombing, password spraying, Kerberos Golden Tickets).
5. **Data Breach & Unauthorized Exfiltration** (Mass cloud egress via Rclone, database dumps, DNS tunneling, DLP triggers, public S3 exposure).

The system aligns directly with **NIST SP 800-61 Rev. 2** (Computer Security Incident Handling Guide) and the **MITRE ATT&CK Matrix**.

---

## 🚀 Simple Instructions to Run on Windows

This project is 100% self-contained using vanilla HTML5, CSS3, and modern JavaScript. It **does NOT require paid APIs, API keys, database setup, or software installations**.

### Method 1: Direct Double-Click (Easiest - 5 Seconds!)
1. Open Windows File Explorer and navigate to the project folder:
   ```
   C:\Users\TEJASWINI\OneDrive\Desktop\ai project
   ```
2. Double-click on **`index.html`**.
3. It will immediately open in your default browser (Microsoft Edge, Google Chrome, or Mozilla Firefox).
4. That's it! The full expert system, rule engine, and incident report generator are now running locally.

---

### Method 2: Running via Windows PowerShell (Local Web Server)
If you prefer running through a local HTTP server:
1. Open **Windows PowerShell** in this project folder.
2. Run either of the following commands:
   ```powershell
   # Using Python (if Python is installed)
   python -m http.server 8000
   ```
   *or*
   ```powershell
   # Using Node.js npx (if Node is installed)
   npx serve .
   ```
3. Open your browser and go to:
   ```
   http://localhost:8000
   ```

---

## 🧪 Quick 1-Minute Demonstration Guide (For Presentation / Viva)

1. **Launch the Engine:**
   - Click the **⚡ Launch Expert Engine** button in the navigation bar.
2. **Auto-Load a Test Scenario:**
   - In the left sidebar, click the **Quick Test Scenarios** dropdown.
   - Select **Scenario 2: Active Ransomware Outbreak on Financial Database Cluster**.
   - Notice that the relevant attack symptoms (mass encryption, shadow copies purged, ransom note, canary tripped) are instantly checked.
3. **Inspect the Forward Chaining Inference:**
   - Scroll down to the **Forward-Chaining Inference Execution Trace (XAI)**.
   - Observe how the engine executed multi-cycle reasoning, firing rules `RULE_RAN_001`, `RULE_RAN_002`, `RULE_RAN_003`, and `RULE_RAN_004` based on priority.
   - Click the **Deep Inspect Rule** button to see the exact boolean premise check (`IF vss_shadow_copies_deleted == true`).
4. **Examine the NIST SP 800-61 Response Playbook:**
   - View the categorized containment steps. Check off completed items in the interactive checklist.
   - Click **Copy Script** to copy the generated emergency PowerShell containment commands.
5. **Generate & Print Formal Incident Audit Report:**
   - Click **Incident Report** in the top navigation bar.
   - Click **🖨️ Print / Save as PDF**. The browser will open the print preview with crisp enterprise styling formatted for 8.5x11 / A4 PDF export!

---

## 📁 Project Directory Structure

```
ai project/
├── index.html                      # Main application interface with all views
├── README.md                       # Windows setup and quick start guide
├── Cybersecurity-Expert-System.zip # Complete packaged project archive
├── css/
│   ├── style.css                   # Cyber dark-blue theme, typography, layout
│   ├── expert-engine.css           # Triage console, radial meter, XAI stepper
│   └── print-report.css            # Dedicated @media print / PDF styles
├── js/
│   ├── app.js                      # Application entry point & orchestrator
│   ├── data/
│   │   ├── rules-database.js       # 40+ Production IF-THEN rules repository
│   │   └── test-scenarios.js       # 6 Pre-configured verification scenarios
│   ├── engine/
│   │   ├── inference-engine.js     # Forward-chaining engine, memory, XAI trace
│   │   └── risk-calculator.js      # Quantitative risk algorithm & CIA Triad
│   └── ui/
│       ├── navigation.js           # Multi-section view router
│       ├── triage-ui.js            # Questionnaire, category pills, indicators
│       ├── explanation-ui.js       # XAI banner, radial gauge, rules explorer
│       ├── playbook-ui.js          # NIST checklist & copyable CLI generator
│       └── report-generator.js     # Enterprise incident report & PDF export
└── docs/
    ├── PROJECT_REPORT.md           # Formal college capstone academic report
    ├── ARCHITECTURE.md             # System architecture & engine specification
    └── TEST_CASES.md               # Test matrix, specifications, and results
```

---

## 🛡️ Key Features & Academic Grading Checklist

| Feature | Description | Implementation File |
|---|---|---|
| **1. Home Page** | Cyber telemetry simulation, project hero, core capabilities | [`index.html`](file:///c:/Users/TEJASWINI/OneDrive/Desktop/ai%20project/index.html) |
| **2. Academic Core** | Abstract, Problem Statement, Objectives, Scope, Methodology | [`index.html#academic`](file:///c:/Users/TEJASWINI/OneDrive/Desktop/ai%20project/index.html#academic), [`docs/PROJECT_REPORT.md`](file:///c:/Users/TEJASWINI/OneDrive/Desktop/ai%20project/docs/PROJECT_REPORT.md) |
| **3. 5 Incident Domains** | Phishing, Malware, Ransomware, Suspicious Login, Data Breach | [`js/data/rules-database.js`](file:///c:/Users/TEJASWINI/OneDrive/Desktop/ai%20project/js/data/rules-database.js) |
| **4. Working Rule Engine** | Forward-chaining recognize-act cycle, priority conflict resolution | [`js/engine/inference-engine.js`](file:///c:/Users/TEJASWINI/OneDrive/Desktop/ai%20project/js/engine/inference-engine.js) |
| **5. Risk Assessment** | 0–100 score, CIA Triad breakdown, NIST SP 800-61 phase playbook | [`js/engine/risk-calculator.js`](file:///c:/Users/TEJASWINI/OneDrive/Desktop/ai%20project/js/engine/risk-calculator.js), [`js/ui/playbook-ui.js`](file:///c:/Users/TEJASWINI/OneDrive/Desktop/ai%20project/js/ui/playbook-ui.js) |
| **6. Architecture & KB** | Interactive 8-node visualizer, 40+ rules inspector, XAI Why/Why-Not | [`js/ui/explanation-ui.js`](file:///c:/Users/TEJASWINI/OneDrive/Desktop/ai%20project/js/ui/explanation-ui.js), [`docs/ARCHITECTURE.md`](file:///c:/Users/TEJASWINI/OneDrive/Desktop/ai%20project/docs/ARCHITECTURE.md) |
| **7. Incident Reports** | Printable executive report with `@media print` PDF styling & JSON export | [`js/ui/report-generator.js`](file:///c:/Users/TEJASWINI/OneDrive/Desktop/ai%20project/js/ui/report-generator.js), [`css/print-report.css`](file:///c:/Users/TEJASWINI/OneDrive/Desktop/ai%20project/css/print-report.css) |
| **8. Test Cases** | 6 standardized scenarios, empirical evaluation matrix, 100% accuracy | [`js/data/test-scenarios.js`](file:///c:/Users/TEJASWINI/OneDrive/Desktop/ai%20project/js/data/test-scenarios.js), [`docs/TEST_CASES.md`](file:///c:/Users/TEJASWINI/OneDrive/Desktop/ai%20project/docs/TEST_CASES.md) |
| **9. Modern Dark Design** | Slate/navy aesthetic, neon cyan glow, responsive flex/grid | [`css/style.css`](file:///c:/Users/TEJASWINI/OneDrive/Desktop/ai%20project/css/style.css), [`css/expert-engine.css`](file:///c:/Users/TEJASWINI/OneDrive/Desktop/ai%20project/css/expert-engine.css) |
| **10. Documentation & Zip** | Full project report, SRS, architecture specs, ZIP archive | [`Cybersecurity-Expert-System.zip`](file:///c:/Users/TEJASWINI/OneDrive/Desktop/ai%20project/Cybersecurity-Expert-System.zip) |

---

## 🔒 Ethics & Safety Disclaimer
*This project is an academic decision-support expert system designed solely for educational, defensive, and incident-response triage training. It does not perform invasive live network scanning, offensive penetration testing, or unauthorized system modifications. All inference logic runs client-side based on user-supplied telemetry indicators.*

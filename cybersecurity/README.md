# 🛡️ CyberShield — Cybersecurity Incident Response Expert System

> **Academic Project** | Knowledge-Based Systems / Artificial Intelligence  
> Built with: Pure HTML5, CSS3, Vanilla JavaScript — No installation required.

---

## 📌 Project Objective

An intelligent, rule-based expert system that guides users through cybersecurity incident identification and response. Users select an incident type, answer targeted yes/no diagnostic questions, and receive evidence-based severity classifications and remediation steps derived from a curated IF-THEN knowledge base.

---

## 🚀 How to Run Locally (Student Laptop)

### Method 1 — Double-Click (Simplest)
1. Navigate to the project folder on your Desktop: `cybersecurity\`
2. Double-click **`index.html`**
3. It will open in your default web browser (Chrome, Edge, or Firefox)
4. The website is fully functional — no internet connection required.

### Method 2 — Right-Click → Open With
1. Right-click `index.html`
2. Select **"Open with"** → **Google Chrome** / **Microsoft Edge** / **Firefox**

### Method 3 — From File Explorer Address Bar
1. Open the `cybersecurity` folder
2. Click the address bar and type the path, then press Enter:
   ```
   cybersecurity\index.html
   ```

### Method 4 — VS Code Live Server (Optional, for development)
1. Install the **Live Server** extension in VS Code
2. Open the `cybersecurity` folder in VS Code
3. Right-click `index.html` → **"Open with Live Server"**
4. The site opens at `http://127.0.0.1:5500/index.html`

> ⚠️ **Note:** No Node.js, npm, Python, or web server is required. This is a pure client-side application.

---

## 📁 Project Structure

```
cybersecurity/
├── index.html      ← Main HTML file (Single-Page Application)
├── style.css       ← All styles (dark navy theme, responsive)
├── engine.js       ← Rule-Based Reasoning Engine (IF-THEN rules)
├── app.js          ← UI Logic (navigation, forms, history, modals)
└── README.md       ← This file
```

---

## 🗂️ Features

| Feature | Description |
|---------|-------------|
| 🏠 **Dashboard** | Project overview, stat cards, "How It Works" guide |
| 🔎 **Incident Assessment** | 3-step wizard: select type → answer questions → view results |
| 📋 **Incident History** | 8 sample records with filter and detail modal |
| ℹ️ **About Project** | Knowledge-based agents, rule-based reasoning explained |
| 🧠 **Rule Engine** | 25+ IF-THEN rules across 5 incident domains |
| 🎨 **Responsive Design** | Dark navy theme, works on desktop and mobile |

---

## 🧠 Rule-Based Reasoning Engine

The engine (`engine.js`) implements forward-chaining reasoning:

```
IF   <condition_1> = TRUE
AND  <condition_2> = TRUE
THEN severity = "Critical"
     label    = "Confirmed Incident Type"
     steps    = [remediation actions...]
```

### Incident Types & Rules

| Incident Type | Questions | Rules | Max Severity |
|--------------|-----------|-------|-------------|
| Phishing | 5 | 3 | Critical |
| Malware Infection | 5 | 3 | Critical |
| Ransomware | 5 | 3 | Critical |
| Suspicious Login | 5 | 3 | Critical |
| Data Breach | 5 | 3 | Critical |

### Severity Scale

| Level | Color | Meaning |
|-------|-------|---------|
| 🔴 Critical | Red | Immediate action required |
| 🟠 High | Orange | Urgent response needed |
| 🔵 Medium | Blue | Monitor and investigate |
| 🟢 Low | Green | No immediate threat |

---

## 🖥️ Technology Stack

- **HTML5** — Semantic markup, ARIA accessibility attributes
- **CSS3** — Custom properties, Flexbox, Grid, animations
- **Vanilla JavaScript (ES6+)** — No frameworks, no dependencies
- **No external CDN** — Works completely offline

---

## 📖 How to Use the Assessment

1. Click **"Start Incident Assessment"** on the dashboard or click **Incident Assessment** in the sidebar
2. **Step 1:** Click on the card matching your incident type (Phishing, Malware, Ransomware, Suspicious Login, Data Breach)
3. Click **Next →**
4. **Step 2:** Answer all yes/no questions about your incident (click ✔ Yes or ✘ No for each)
5. Click **Analyse →**
6. **Step 3:** View your results:
   - Incident category and severity badge
   - Matched IF-THEN rules that fired
   - Numbered recommended response steps
7. Click **🔄 Start New Assessment** to reset and run another scenario

---

## ⚠️ Disclaimer

This system uses **predefined sample rules** for **educational purposes only**.  
It **cannot detect real attacks automatically**.  
For actual cybersecurity incidents, consult qualified information security professionals and your organization's incident response team.

---

## 👥 Project Information

| Field | Value |
|-------|-------|
| Project Title | CyberShield — Cybersecurity Incident Response Expert System |
| Course | Artificial Intelligence / Knowledge-Based Systems |
| AI Technique | Rule-Based Reasoning with Forward Chaining |
| Knowledge Base | 25+ IF-THEN rules across 5 cybersecurity domains |
| Academic Year | 2026 — Cybersecurity Domain |

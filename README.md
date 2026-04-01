# 🛡 PhishGuard AI

> **AI-Powered Phishing Detection Tool** — Analyse URLs, emails, and web pages in real time using machine learning and advanced heuristics.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.3+-black?style=flat-square&logo=flask)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.3+-orange?style=flat-square&logo=scikit-learn)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square&logo=docker)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## 📖 Project Overview

PhishGuard AI is a modular, production-structured cybersecurity tool that detects phishing attacks across three attack surfaces:

| Surface    | What it analyses |
|------------|-----------------|
| **URL**    | Domain structure, typosquatting, TLD, entropy, keywords, ML prediction |
| **Email**  | Header spoofing, urgency language, embedded URLs, sender reputation |
| **HTML**   | Forms, password fields, hidden inputs, suspicious JS, external submissions |

The tool blends a **trained Random Forest ML model** (24 features) with a rule-based scoring engine to produce a 0–100 risk score with a human-readable verdict:

| Score     | Verdict     |
|-----------|-------------|
| 0 – 29    | ✅ Safe      |
| 30 – 59   | ⚠️ Suspicious |
| 60 – 100  | 🚨 Phishing  |

---

## ✨ Features

### Core Detection
- 🔗 **URL Analysis** — length, HTTPS, special chars, IP-as-domain, suspicious TLDs
- 🔤 **Keyword Detection** — 30+ suspicious terms across URL, email, and HTML
- 🔍 **Typosquatting Detection** — fuzzy similarity check against 35 trusted brands
- 📧 **Email Header Analysis** — From/Reply-To mismatch, SPF/DKIM absence
- 🌐 **HTML Analysis** — forms, password fields, external actions, obfuscated JS
- 🤖 **ML Model** — Random Forest trained on real phishing/legitimate URL dataset

### Backend & API
- ⚡ Flask REST API with 7 endpoints
- 🔒 Per-IP rate limiting (30 req / 60 sec)
- 🗄️ SQLite scan history logging
- 📊 JSON and HTML report generation
- 📋 Full API documentation at `/api/docs`

### Frontend
- 🖥️ Dark cybersecurity-themed single-page UI
- 📊 Animated risk score ring with breakdown bars
- 🗂️ Feature detail table
- 📜 Scan history table

### CLI
- 🖥️ Terminal scanning with coloured output
- 🗃️ Batch URL scanning
- 📄 Report generation from CLI
- 🕐 Scan history viewer

---

## 🗂 Project Structure

```
phishing-detector/
├── app.py                  ← Flask backend + API endpoints
├── model.py                ← ML training & prediction
├── cli.py                  ← Command-line interface
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
│
├── utils/
│   ├── feature_extractor.py  ← URL / email / HTML feature extraction
│   ├── scanner.py            ← High-level scan engine (ML + rules)
│   └── reporter.py           ← JSON & HTML report generation
│
├── dataset/
│   └── data.csv             ← Training data (phishing + legitimate URLs)
│
├── models/                  ← Saved model files (auto-created)
│
├── templates/
│   └── index.html           ← Frontend UI
│
├── static/
│   ├── css/style.css
│   └── js/app.js
│
├── logs/                    ← App logs + SQLite scan history
└── reports/                 ← Generated scan reports
```

---

## 🚀 Installation

### Prerequisites
- Python 3.10+
- pip

### 1 — Clone & Setup

```bash
git clone https://github.com/arshad9061/phishing-detector.git
cd phishing-detector
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2 — Train the ML Model

```bash
python cli.py train
```

### 3 — Start the Web Server

```bash
python app.py
```

Open **http://localhost:5000** in your browser.

---

## 🔮 Future Improvements

- [ ] Real WHOIS domain age lookup
- [ ] VirusTotal API integration
- [ ] Browser extension (Chrome/Firefox)
- [ ] BERT/transformer-based email classifier
- [ ] Bulk CSV URL scanning
- [ ] WebSocket live scanning status
- [ ] User authentication & scan dashboard
- [ ] Threat intelligence feed integration
- [ ] PDF report generation

---

## ⚠️ Disclaimer

PhishGuard AI is a **security research and educational tool**. It is designed to help users identify potential phishing threats but should not be the sole basis for security decisions. Always use multiple layers of protection.


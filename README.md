# MEDJAY (SCAMMERSPHAGE)
A robust 4-pillar web security and threat intelligence platform designed to detect phishing, validate TLS trust chains, audit security headers, and aggregate community threat data in real time.

## Problem
In recent months, rising digital fraud, credential-harvesting attacks, and Certificate Authority (CA) trust failures (such as fraudulent certificate issuances and weak key generation like the eMudhra incident) have left everyday web users vulnerable to sophisticated spoofing and phishing kits. Existing tools isolate checks, making it difficult to get a unified trust assessment instantly.

## Solution
Medjay provides an all-in-one web security dashboard that assesses any URL across four independent pillars in seconds:
1. **AI Threat Analysis**: Evaluates Shannon entropy, domain randomness, raw IPs, and brand impersonation.
2. **Web Security Assessment**: Audits core browser security headers (HSTS, CSP, X-Frame-Options).
3. **Certificate Validation**: Verifies TLS versions, CA authenticity, expiration, and Certificate Transparency (CT) log chains.
4. **Collaborative Intelligence**: Cross-references global threat blacklists and local crowd-sourced SQLite community reports.

## Demo Links & Screenshot
* **Demo Video**: [Watch 2-Minute Walkthrough](#) *(Insert YouTube/Loom link here)*
* **Live App**: Local deployment (instructions below)

![Medjay Dashboard Preview](frontend/src/assets/preview.png) *(Note: Local app runs via FastAPI and Vite)*

## Tech Stack
* **Frontend**: React, Vite, Lucide Icons, Modern CSS (Dark-themed dashboard with dynamic charting and pagination).
* **Backend**: Python FastAPI, Uvicorn, Python Standard Libraries (`ssl`, `socket`, `urllib3`, `math`, `re`).
* **Database**: Built-in SQLite (`medjay.db`) for permanent scan history and community threat reporting.

## Architecture
Medjay follows a decoupled client-server architecture communicating via RESTful JSON APIs:
[React Frontend (Vite)] <---> (JSON / CORS) <---> [FastAPI Backend (Uvicorn)]
|
+-------------------------------+-------------------------------+
|                               |                               |
[threat_ai.py Engine]         [security_check.py TLS]        [database.py SQLite]

## Setup and Run Steps
To run Medjay locally on a clean machine:

### 1. Clone the Repository
```bash
git clone [https://github.com/YOUR-USERNAME/SCAMMERSPHAGE.git](https://github.com/YOUR-USERNAME/SCAMMERSPHAGE.git)
cd SCAMMERSPHAGE
Start the Backend Server
cd backend
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

pip install -r requirements.txt
uvicorn main:app --reload

Start the Frontend Application
cd frontend
npm install
npm run dev

Disclosures
Libraries & Frameworks: React, FastAPI, Vite, Lucide-react.

Templates: Built from scratch during the hackathon timeframe.

AI Tools: AI assistance used for code syntax optimization, feature extraction logic, and architectural structuring.




from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from threat_ai import analyze_phishing
from security_check import check_ssl_and_headers
from intel_feed import check_blacklists, report_malicious_domain
from database import init_db, log_scan, get_history_and_stats

app = FastAPI()

# Create medjay.db and tables on startup
init_db()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"status": "Medjay Backend API & SQLite DB Online"}

@app.get("/history")
def fetch_scan_history(page: int = 1, limit: int = 5):
    return get_history_and_stats(page=page, limit=limit)

@app.get("/scan")
def scan_website(url: str, save: bool = True):
    ai_res = analyze_phishing(url)
    sec_res = check_ssl_and_headers(url)
    intel_res = check_blacklists(url)

    total_penalty = (
        ai_res.get("score_impact", 0)
        + sec_res.get("score_impact", 0)
        + intel_res.get("score_impact", 0)
    )
    trust_score = max(0, 100 - total_penalty)
    status_label = "Safe" if trust_score >= 75 else "Suspicious" if trust_score >= 45 else "Unsafe"

    if save:
        log_scan(url, trust_score, status_label)

    db_state = get_history_and_stats()

    return {
        "url": url,
        "trustScore": trust_score,
        "statusLabel": status_label,
        "threatAnalysis": ai_res["status"],
        "webSecurity": sec_res["web_security"],
        "certificate": sec_res["certificate"],
        "collaborativeIntelligence": intel_res["status"],
        "history": db_state["history"],
        "stats": db_state["stats"]
    }

@app.post("/report")
def report_website(url: str):
    domain = report_malicious_domain(url)
    db_state = get_history_and_stats()
    return {
        "status": "success",
        "domain": domain,
        "history": db_state["history"],
        "stats": db_state["stats"]
    }
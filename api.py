"""
DeepIntel Backend API
Run with: uvicorn api:app --reload
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import time

from explainer import explain
from safe_alternative import suggest
from threat_intel import load_blocklists

app = FastAPI(title="DeepIntel API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load blocklists once at startup
@app.on_event("startup")
def startup():
    load_blocklists()

class AnalyzeRequest(BaseModel):
    url: str

@app.get("/")
def root():
    return {"status": "ok", "service": "DeepIntel API"}

@app.post("/analyze")
def analyze_url(req: AnalyzeRequest):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    # Add scheme if missing
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    start = time.time()
    result = explain(url)
    suggestion = suggest(url, result["risk_level"], result["prediction"])
    elapsed = round(time.time() - start, 3)

    return {
        "url":         result["url"],
        "prediction":  result["prediction"],
        "risk_level":  result["risk_level"],
        "score":       result["score"],
        "reasons":     result["reasons"],
        "ml_probs":    result["ml_probs"],
        "suggestion":  suggestion,
        "elapsed_ms":  int(elapsed * 1000),
    }
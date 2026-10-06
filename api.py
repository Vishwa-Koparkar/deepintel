"""
DeepIntel Backend API
Run with: uvicorn api:app --reload
"""

import os
import time
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

import feedback
from analyzer import DECIDER_LABEL, analyze, base_domain, has_threat_history, is_trusted_host, extract_features
from explainer import explain
from safe_alternative import suggest
from threat_intel import load_blocklists

app = FastAPI(title="DeepIntel API", version="1.1")

# Read-only analysis is open to any local client (dashboard opened from disk, extension).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # for dev; restrict to your extension ID for production
    allow_methods=["*"],
    allow_headers=["*"],
)

# The feedback database is personal. Any web page you visit can send requests to localhost, so the
# feedback endpoints only answer the extension and the dashboard served by this API.
_LOCAL_ORIGINS = ("http://localhost:", "http://127.0.0.1:")


def require_trusted_origin(request: Request):
    origin = request.headers.get("origin")
    if origin is None:          # curl, scripts and same-origin GETs send no Origin header
        return
    if origin.startswith("chrome-extension://") or origin.startswith(_LOCAL_ORIGINS):
        return
    raise HTTPException(status_code=403, detail="Feedback is only available from the DeepIntel extension and dashboard")


# Load blocklists once at startup
@app.on_event("startup")
def startup():
    load_blocklists()

class AnalyzeRequest(BaseModel):
    url: str

class FeedbackRequest(BaseModel):
    url: str = Field(..., max_length=feedback.MAX_URL)
    correct_label: str = Field(..., description="benign | phishing | malware")
    note: Optional[str] = Field(None, max_length=feedback.MAX_NOTE)

@app.get("/")
def root():
    return {"status": "ok", "service": "DeepIntel API"}

@app.get("/dashboard")
def dashboard():
    """Serves the dashboard from this origin so it can use the (origin-checked) feedback endpoints."""
    return FileResponse(os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html"))

def _with_scheme(url):
    url = url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url

@app.post("/analyze")
def analyze_url(req: AnalyzeRequest):
    url = _with_scheme(req.url)

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
        "confidence":  result["confidence"],
        "layers":      result["layers"],
        "drivers":     result["drivers"],
        "decided_by":  result["decided_by"],
        "decided_by_label": DECIDER_LABEL[result["decided_by"]],
        "trace":       result["trace"],
        "feedback":    result["feedback"],
        "ml_probs":    result["ml_probs"],
        "suggestion":  suggestion,
        "elapsed_ms":  int(elapsed * 1000),
    }

# ---------------------------------------------------------------------------
# Personal feedback (false positives / false negatives)
# ---------------------------------------------------------------------------
@app.post("/feedback", dependencies=[Depends(require_trusted_origin)])
def add_feedback(req: FeedbackRequest):
    if req.correct_label not in feedback.LABELS:
        raise HTTPException(status_code=422, detail=f"correct_label must be one of {list(feedback.LABELS)}")
    url = _with_scheme(req.url)

    # What we would have said WITHOUT any earlier correction, so the record shows what was actually wrong
    given = analyze(url, use_feedback=False)
    if req.correct_label == "benign" and given["threat_intel"]["flag"]:
        # A blocklist hit outranks a "safe" correction, so storing it would change nothing and would put a
        # known-bad URL labelled benign into the training data.
        raise HTTPException(status_code=409, detail="This site is on a threat blocklist (" + ", ".join(given["threat_intel"]["matched_lists"]) + "), so it can't be marked safe")
    host = feedback.normalize_url(url).split("/")[2].split(":")[0]
    scope = feedback.choose_scope(
        req.correct_label, host, base_domain(host),
        is_ip=bool(extract_features(url)["is_domain_ip"]),
        is_trusted_host=is_trusted_host(host),
        has_threat_history=has_threat_history(host),
    )
    try:
        row = feedback.add(url, req.correct_label, given["prediction"], scope, base_domain(host), req.note)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return row

@app.get("/feedback", dependencies=[Depends(require_trusted_origin)])
def list_feedback(limit: int = 200):
    return {"items": feedback.list_all(min(max(limit, 1), 1000)), "untrained": feedback.count_untrained()}

@app.delete("/feedback/{feedback_id}", dependencies=[Depends(require_trusted_origin)])
def delete_feedback(feedback_id: int):
    if not feedback.delete(feedback_id):
        raise HTTPException(status_code=404, detail="No such feedback entry")
    return {"deleted": feedback_id}

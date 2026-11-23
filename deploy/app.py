"""Read-only public wrapper for the local DeepIntel API."""

import os
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

# Set this before importing api/analyzer, including when launched directly with Uvicorn.
os.environ["DEEPINTEL_FEEDBACK"] = "0"

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator

from api import AnalyzeRequest as LocalAnalyzeRequest, analyze_url
from analyzer import load_model
from threat_intel import load_blocklists

ROOT = Path(__file__).resolve().parents[1]
MAX_BODY_BYTES = 16 * 1024
REQUESTS_PER_MINUTE = 60

app = FastAPI(title="DeepIntel public demo", version="1.0", description="Read-only URL text analysis demo")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://vishwa-koparkar.github.io"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 2048:
        raise ValueError("URL must contain 1–2048 characters")
    if value.lower().startswith("http://"):
        value = "http://" + value[7:]
    elif value.lower().startswith("https://"):
        value = "https://" + value[8:]
    elif "://" in value:
        raise ValueError("Only http and https URLs are accepted")
    else:
        value = "https://" + value
    parsed = urlsplit(value)
    try:
        valid_host = bool(parsed.hostname)
        parsed.port
    except ValueError:
        valid_host = False
    if parsed.scheme.lower() not in {"http", "https"} or not valid_host:
        raise ValueError("Enter a complete http or https URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs with embedded credentials are not accepted")
    if any(char.isspace() for char in parsed.netloc):
        raise ValueError("URL host cannot contain whitespace")
    return value


class PublicAnalyzeRequest(BaseModel):
    url: str = Field(..., strict=True, min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value):
        return normalize_url(value)


class PublicRequestGuard:
    """Bound request memory and cap total analysis requests per process."""

    def __init__(self, app):
        self.app = app
        self.lock = threading.Lock()
        self.window = -1
        self.count = 0

    def _allow(self, now):
        window = int(now // 60)
        with self.lock:
            if window != self.window:
                self.window, self.count = window, 0
            if self.count >= REQUESTS_PER_MINUTE:
                return False
            self.count += 1
            return True

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] != "/analyze" or scope["method"] != "POST":
            return await self.app(scope, receive, send)

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        length = headers.get(b"content-length", b"")
        try:
            too_large = int(length) > MAX_BODY_BYTES
        except ValueError:
            too_large = False
        if too_large:
            return await JSONResponse({"detail": "Request body too large"}, status_code=413)(scope, receive, send)

        # Avoid trusting caller-controlled forwarded-IP headers; this demo uses a shared global cap.
        if not self._allow(time.monotonic()):
            return await JSONResponse({"detail": "Rate limit exceeded; try again in a minute"}, status_code=429)(scope, receive, send)

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > MAX_BODY_BYTES:
                return await JSONResponse({"detail": "Request body too large"}, status_code=413)(scope, receive, send)
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


app.add_middleware(PublicRequestGuard)


@app.on_event("startup")
def startup():
    for name in ("best_model.pkl", "label_encoder.pkl"):
        if not (ROOT / "models" / name).is_file():
            raise RuntimeError(f"Required trusted model artifact is missing: models/{name}")
    load_blocklists()
    load_model()
    # Warm the complete text-only analysis path before the service reports ready.
    analyze_url(LocalAnalyzeRequest(url="https://example.com"))


@app.get("/")
def root():
    return {"service": "DeepIntel public demo", "read_only": True, "analyze": "/analyze", "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/demo-config")
def demo_config():
    return {"feedbackEnabled": False}


@app.get("/dashboard")
def dashboard():
    return FileResponse(ROOT / "dashboard.html")


@app.post("/analyze")
def analyze(request: PublicAnalyzeRequest):
    return analyze_url(LocalAnalyzeRequest(url=request.url))

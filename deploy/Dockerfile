FROM python:3.12-slim-bookworm

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DEEPINTEL_FEEDBACK=0 OMP_NUM_THREADS=2

RUN apt-get update && apt-get install --no-install-recommends -y libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

# Allowlist only the runtime code and public, read-only inputs. Personal data and training files stay out.
COPY analyzer.py api.py explainer.py feedback.py heuristic_scorer.py lookalike.py safe_alternative.py threat_intel.py /app/
COPY dashboard.html /app/dashboard.html
COPY data/dataset_clean.csv data/ti_openphish.txt data/ti_urlhaus_domains.txt /app/data/
COPY deploy/app.py /app/deploy/app.py
COPY deploy/artifacts/best_model.pkl deploy/artifacts/label_encoder.pkl /app/models/

EXPOSE 7860
CMD ["sh", "-c", "uvicorn deploy.app:app --host 0.0.0.0 --port ${PORT:-7860}"]

"""Train the existing recipe against committed splits without rewriting project data or models."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import joblib
from sklearn.preprocessing import LabelEncoder

ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='deepintel-browser-proof-') as scratch:
    work = Path(scratch)
    (work / 'data').mkdir()
    (work / 'models').mkdir()
    for name in ['train.csv', 'val.csv']:
        shutil.copy2(ROOT / 'data' / name, work / 'data' / name)
    joblib.dump(LabelEncoder().fit(['benign', 'malware', 'phishing']), work / 'models/label_encoder.pkl')
    env = {**os.environ, 'DEEPINTEL_FEEDBACK_DB': str(work / 'data/feedback.db'), 'OMP_NUM_THREADS': '2'}
    subprocess.run([sys.executable, str(ROOT / 'scripts/evaluation/tune_model.py')], cwd=work, env=env, check=True)
    subprocess.run([sys.executable, str(ROOT / 'browser-prototype/export.py'), str(work / 'models/best_model.pkl')], cwd=ROOT, env=env, check=True)

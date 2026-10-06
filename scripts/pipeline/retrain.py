"""
Single entry point for retraining: rebuild the feature/split files from the current dataset
(+ user corrections), then train. The scheduler and manual runs both use this so train.csv can
never be stale.

    python scripts/pipeline/retrain.py
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STEPS = [
    ("rebuild features + split", ["scripts/pipeline/rebuild_features.py"]),
    ("train model",              ["scripts/evaluation/tune_model.py"]),
]


def run(log=print):
    """Returns True only if every step succeeded and the new model was saved."""
    for name, cmd in STEPS:
        log(f"[retrain] {name}...")
        p = subprocess.run([sys.executable] + cmd, cwd=ROOT, capture_output=True, text=True,
                           env={**os.environ, "PYTHONPATH": ROOT})
        log(p.stdout)
        if p.returncode != 0:
            log(f"[retrain] '{name}' failed (exit {p.returncode}):\n{p.stderr[-2000:]}")
            return False
    return True


if __name__ == "__main__":
    sys.exit(0 if run() else 1)

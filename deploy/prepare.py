"""Copy locally trained, trusted model artifacts into the public image build context."""

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "models"
DEST = ROOT / "deploy" / "artifacts"
ARTIFACTS = ("best_model.pkl", "label_encoder.pkl")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="replace staged model artifacts")
    args = parser.parse_args()

    missing = [name for name in ARTIFACTS if not (SOURCE / name).is_file()]
    if missing:
        raise SystemExit(
            "Missing trusted model artifact(s): " + ", ".join(missing)
            + ". Initialize models/label_encoder.pkl and run scripts/pipeline/retrain.py first."
        )
    existing = [name for name in ARTIFACTS if (DEST / name).exists()]
    if existing and not args.force:
        raise SystemExit("Staged artifacts already exist; pass --force to replace them.")

    DEST.mkdir(parents=True, exist_ok=True)
    for name in ARTIFACTS:
        shutil.copy2(SOURCE / name, DEST / name)
    print(f"Staged trusted model artifacts in {DEST.relative_to(ROOT)}")


if __name__ == "__main__":
    main()

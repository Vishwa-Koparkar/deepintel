from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger
import subprocess
import sys
import logging
import os
from datetime import datetime

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler("logs/scheduler.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

FEEDBACK_RETRAIN_THRESHOLD = 10   # unlearned user corrections that trigger a retrain

scheduler = BlockingScheduler()


@scheduler.scheduled_job(IntervalTrigger(hours=24), id="deepintel_pipeline", name="DeepIntel Auto-Update")
def run_pipeline():
    logger.info("=" * 50)
    logger.info("Running auto-update pipeline...")

    try:
        result = subprocess.run(
            [sys.executable, "auto_update.py"], capture_output=True, text=True,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        logger.info(result.stdout)
        if result.stderr:
            logger.warning(result.stderr)
    except Exception as e:
        logger.error(f"Pipeline failed: {e}")
        return

    root = os.path.dirname(os.path.abspath(__file__))
    flag = os.path.join(root, "retrain_trigger.flag")

    reasons = []
    if os.path.exists(flag):
        reasons.append("new threat-feed URLs reached the threshold")
    try:
        import feedback
        pending = feedback.count_untrained()
        if pending >= FEEDBACK_RETRAIN_THRESHOLD:
            reasons.append(f"{pending} unlearned user corrections")
    except Exception as e:
        logger.warning(f"Could not check feedback: {e}")

    if reasons:
        logger.info(f"Retrain triggered ({'; '.join(reasons)}). Rebuilding features, then training...")
        try:
            from scripts.pipeline import retrain
            ok = retrain.run(log=logger.info)
        except Exception as e:
            logger.error(f"Retraining crashed: {e}")
            ok = False
        if ok:
            if os.path.exists(flag):
                os.remove(flag)
            logger.info("Model retrained successfully.")
        else:
            # Keep the flag so the next run retries instead of silently dropping the update
            logger.error("Retraining failed or was rejected; keeping the current model and the retrain flag.")
    else:
        logger.info("Retrain threshold not yet reached.")

    logger.info("Pipeline run complete.")
    logger.info("=" * 50)


if __name__ == "__main__":
    logger.info("DeepIntel Scheduler starting...")
    logger.info("Pipeline will run every 24 hours")
    run_pipeline()
    scheduler.start()
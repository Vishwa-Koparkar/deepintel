from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.interval import IntervalTrigger
import subprocess
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

scheduler = BlockingScheduler()


@scheduler.scheduled_job(IntervalTrigger(hours=24), id="deepintel_pipeline", name="DeepIntel Auto-Update")
def run_pipeline():
    logger.info("=" * 50)
    logger.info("Running auto-update pipeline...")

    try:
        result = subprocess.run(
            ["python", "auto_update.py"], capture_output=True, text=True,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        logger.info(result.stdout)
        if result.stderr:
            logger.warning(result.stderr)
    except Exception as e:
        logger.error(f"Pipeline failed: {e}")
        return

    if os.path.exists("retrain_trigger.flag"):
        logger.info("Retrain trigger detected. Starting model retraining...")
        try:
            retrain = subprocess.run(
                ["python", "scripts/evaluation/tune_model.py"],
                capture_output=True, text=True,
                cwd=os.path.dirname(os.path.abspath(__file__))
            )
            logger.info(retrain.stdout)
            os.remove("retrain_trigger.flag")
            logger.info("Model retrained successfully.")
        except Exception as e:
            logger.error(f"Retraining failed: {e}")
    else:
        logger.info("Retrain threshold not yet reached.")

    logger.info("Pipeline run complete.")
    logger.info("=" * 50)


if __name__ == "__main__":
    logger.info("DeepIntel Scheduler starting...")
    logger.info("Pipeline will run every 24 hours")
    run_pipeline()
    scheduler.start()
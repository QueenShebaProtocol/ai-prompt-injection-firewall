"""
Application entrypoint.

Startup order:
  1. Validate config/firewall.yaml (an invalid file aborts startup).
  2. Verify the database, create the schema, load Layer 1 rules.
  3. Start the Layer 1 rule hot-reload watcher.
  4. Load and warm up the Layer 2 classifier (if enabled). If the model files
     are missing or broken, log it and carry on: the pipeline then runs on
     Layer 1 only.
  5. Start the hourly system_metrics rollup as a background task.
Shutdown reverses this and cancels the background tasks.
"""

import asyncio
import contextlib
import logging
import os
from contextlib import asynccontextmanager

# Load .env before any other project import, so every module that reads
# an environment variable at import time sees the real values.
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI

from src.database.connection import check_database_connection, init_schema
from src.database.storage import run_rollup_loop
from src.engine.layer_1_deterministic import layer1_engine
from src.engine.layer_2_classifier import ClassifierUnavailable, get_classifier
from src.engine.pipeline import get_pipeline_config
from src.proxy.forwarder import close_http_client
from src.proxy.handler import router as proxy_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("firewall.main")

RULES_POLL_SECONDS = float(os.getenv("RULES_POLL_SECONDS", "5"))
ROLLUP_INTERVAL_SECONDS = float(os.getenv("ROLLUP_INTERVAL_SECONDS", "300"))


async def _load_layer1_rules() -> None:
    """Load Layer 1 rules without letting a failure stop the gateway.

    Same policy as "database unreachable": start, say so loudly, and let the
    watcher keep retrying so Layer 1 comes up on its own as soon as loading
    works again (no restart needed).
    """
    try:
        await layer1_engine.load_rules()
    except Exception:
        logger.exception(
            "Layer 1 rules could not be loaded: Layer 1 is INACTIVE until a reload succeeds."
        )


async def _load_layer2() -> None:
    """Load and warm up Layer 2. Never raises: a Layer 2 problem must not stop
    the gateway from starting, because the pipeline falls back to Layer 1."""
    classifier = get_classifier()
    try:
        # Both calls are blocking (disk + CPU), so keep them off the event loop.
        await asyncio.to_thread(classifier.load)
        logger.info("Layer 2 classifier loaded from %s.", classifier.model_path)
        await asyncio.to_thread(classifier.warm_up)
        logger.info("Layer 2 classifier warmed up.")
    except ClassifierUnavailable as exc:
        logger.error("Layer 2 unavailable, running on Layer 1 only: %s", exc)
    except Exception:
        logger.exception("Unexpected error starting Layer 2, running on Layer 1 only.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup ---
    # Fail fast: a PipelineConfigError here aborts startup instead of
    # surfacing later as a 503 on the first request.
    cfg = get_pipeline_config()

    if await check_database_connection():
        logger.info("Database connection verified.")
        await init_schema()
        await _load_layer1_rules()
    else:
        # Without rules, Layer 1 would pass everything through unfiltered,
        # so this is logged loudly rather than failing silently.
        logger.error("Database unreachable at startup — Layer 1 has NO rules loaded yet.")

    # Start regardless of whether the rules loaded just now: the watcher keeps
    # retrying and will load them once the problem is gone.
    layer1_engine.start_watcher(RULES_POLL_SECONDS)

    if cfg.layer_2_enabled:
        await _load_layer2()
    else:
        logger.info("Layer 2 is disabled in firewall.yaml; skipping model load.")

    # run_rollup_loop logs and survives database errors; it only stops when cancelled.
    rollup_task = asyncio.create_task(
        run_rollup_loop(ROLLUP_INTERVAL_SECONDS), name="metrics-rollup"
    )

    yield

    # --- Shutdown ---
    rollup_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await rollup_task
    await layer1_engine.stop_watcher()
    await close_http_client()
    logger.info("Shutdown complete.")


app = FastAPI(
    title="Decentralized AI Prompt Injection Firewall",
    description="Inline security proxy for LLM traffic: layered prompt inspection and output scanning.",
    version="0.2.0",
    lifespan=lifespan,
)

app.include_router(proxy_router)


@app.get("/")
async def root():
    cfg = get_pipeline_config()
    layer2 = get_classifier().status()

    active_layers = []
    if cfg.layer_1_enabled and layer1_engine.rule_count > 0:   # enabled AND has rules
        active_layers.append("LAYER_1")
    if cfg.layer_2_enabled and layer2["loaded"]:      # enabled AND actually running
        active_layers.append("LAYER_2")
    if cfg.layer_3_enabled:
        active_layers.append("LAYER_3")
    if getattr(cfg, "output_scanner_enabled", False):   # absent in older PipelineConfig versions
        active_layers.append("OUTPUT_SCANNER")

    return {
        "service": "ai-prompt-firewall",
        "active_layers": active_layers,
        "layer1_rules_loaded": layer1_engine.rule_count,
        "layer2": {"enabled": cfg.layer_2_enabled, **layer2},
    }
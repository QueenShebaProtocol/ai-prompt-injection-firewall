"""
Application entrypoint.

Boots FastAPI, creates the database schema, loads Layer 1 rules, starts
the rule hot-reload watcher, and registers the proxy router.
"""

import logging
import os
from contextlib import asynccontextmanager

# Load .env before any other project import, so every module that reads
# an environment variable at import time sees the real values.
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI

from src.database.connection import check_database_connection, init_schema
from src.engine.layer_1_deterministic import layer1_engine
from src.proxy.forwarder import close_http_client
from src.proxy.handler import router as proxy_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("firewall.main")

RULES_POLL_SECONDS = float(os.getenv("RULES_POLL_SECONDS", "5"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup ---
    if await check_database_connection():
        logger.info("Database connection verified.")
        await init_schema()
        await layer1_engine.load_rules()
    else:
        # Without rules, Layer 1 would pass everything through unfiltered,
        # so this is logged loudly rather than failing silently.
        logger.error("Database unreachable at startup — Layer 1 has NO rules loaded yet.")

    # Start regardless of whether the database was reachable just now:
    # the watcher keeps retrying and will load the rules once it returns.
    layer1_engine.start_watcher(RULES_POLL_SECONDS)

    yield

    # --- Shutdown ---
    await layer1_engine.stop_watcher()
    await close_http_client()
    logger.info("Shutdown complete.")


app = FastAPI(
    title="Decentralized AI Prompt Injection Firewall",
    description="Week 1 build: proxy skeleton + Layer 1 deterministic engine.",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(proxy_router)


@app.get("/")
async def root():
    return {
        "service": "ai-prompt-firewall",
        "active_layers": ["LAYER_1"],
        "layer1_rules_loaded": layer1_engine.rule_count,
    }
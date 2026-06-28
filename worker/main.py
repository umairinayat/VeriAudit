"""FastAPI entry point. Exposes POST /analyze. Run with:

    uvicorn worker.main:app --port 8001 --reload

The TS orchestrator (../orchestrator) is the only intended caller.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException

from . import pipeline
from .models import AnalysisRequest, AnalysisResponse

logger = logging.getLogger("veriaudit.worker")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = FastAPI(
    title="VeriAudit AI Analysis Worker",
    version="0.1.0",
    description="Source in -> audit bundle JSON out. No chain access. No persistence.",
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalysisResponse)
def analyze(req: AnalysisRequest) -> AnalysisResponse:
    if not any([req.source, req.address, req.repo]):
        raise HTTPException(status_code=400, detail="supply source | address | repo")
    try:
        return pipeline.run(req)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # pragma: no cover - defensive
        logger.exception("analysis failed")
        raise HTTPException(status_code=500, detail=f"analysis failed: {e}")

"""API REST + panel web de AgentSec (FastAPI + Jinja2 + SQLite)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

import app.db as dbmod
from agentsec.models import ScanOptions, ScanResult
from agentsec.reporter import render_html
from agentsec.scanner import run_scan

BASE_DIR = Path(__file__).resolve().parent
app = FastAPI(title="AgentSec API", version="0.1.0")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


class ScanRequest(BaseModel):
    path: str
    allow: list[str] = []
    threshold: float = 60.0


class ScanResponse(BaseModel):
    id: int | None = None
    result: ScanResult | None = None
    error: str | None = None


@app.post("/api/scan", response_model=ScanResponse)
def api_scan(req: ScanRequest) -> ScanResponse:
    options = ScanOptions(path=req.path, allow=req.allow, threshold=req.threshold, formats=["json"])
    try:
        result = run_scan(options)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    record = {
        "project": result.project,
        "framework": result.framework,
        "score": result.score,
        "scanned_files": result.scanned_files,
        "rules_loaded": result.rules_loaded,
        "duration_ms": result.duration_ms,
        "findings_json": result.model_dump_json(),
    }
    with dbmod.db() as conn:
        scan_id = dbmod.insert_scan(conn, record)

    return ScanResponse(id=scan_id, result=result)


@app.get("/api/scans")
def api_list(limit: int = 50) -> list[dict[str, Any]]:
    with dbmod.db() as conn:
        return dbmod.list_scans(conn, limit=limit)


@app.get("/api/scans/{scan_id}")
def api_detail(scan_id: int) -> dict[str, Any]:
    with dbmod.db() as conn:
        record = dbmod.get_scan(conn, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="scan no encontrado")
    return record


@app.get("/api/reports/{scan_id}")
def api_report(scan_id: int, fmt: str = "json") -> dict[str, Any]:
    with dbmod.db() as conn:
        record = dbmod.get_scan(conn, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="scan no encontrado")
    return {"scan": record, "formats": ["html", "sarif", "json"], "requested": fmt}


@app.get("/api/stats")
def api_stats() -> dict[str, Any]:
    with dbmod.db() as conn:
        return dbmod.stats(conn)


@app.get("/api/rules")
def api_rules() -> list[dict[str, Any]]:
    from agentsec.rules import load_rules

    return [
        {
            "id": r.id,
            "name": r.name,
            "severity": r.severity.value,
            "cwe": r.cwe,
            "owasp_llm": r.owasp_llm,
            "frameworks": r.frameworks,
        }
        for r in load_rules()
    ]


# -------------------------------- panel web -------------------------------- #


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    with dbmod.db() as conn:
        scans = dbmod.list_scans(conn)
        stats = dbmod.stats(conn)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"scans": scans, "stats": stats, "page": "dashboard"},
    )


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
def scan_detail(request: Request, scan_id: int) -> HTMLResponse:
    with dbmod.db() as conn:
        record = dbmod.get_scan(conn, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="scan no encontrado")
    result = ScanResult.model_validate(record["findings"])
    return templates.TemplateResponse(
        request,
        "scan_detail.html",
        {"record": record, "result": result, "html_report": render_html(result), "page": "detail"},
    )


@app.get("/report/{scan_id}", response_class=HTMLResponse)
def report_html(scan_id: int) -> HTMLResponse:
    with dbmod.db() as conn:
        record = dbmod.get_scan(conn, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="scan no encontrado")
    result = ScanResult.model_validate(record["findings"])
    return HTMLResponse(content=render_html(result))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)

"""Captura el dashboard de AgentSec y la pagina de detalle para la demo."""

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("demo")
OUT.mkdir(parents=True, exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={"width": 1100, "height": 720})

    page.goto("http://127.0.0.1:8000/", wait_until="networkidle")
    page.wait_for_timeout(600)
    page.screenshot(path=str(OUT / "panel_dashboard.png"), full_page=True)
    print("captura 1/2: panel_dashboard.png")

    page.goto("http://127.0.0.1:8000/scan/1", wait_until="networkidle")
    page.wait_for_timeout(800)
    page.screenshot(path=str(OUT / "panel_detalle.png"), full_page=True)
    print("captura 2/2: panel_detalle.png")

    browser.close()

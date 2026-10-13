"""Verify the release image executes the fixed browser, not an unused package."""

import json
import sys

sys.path.insert(0, "/app")

from core.web.browser_runtime import launch_options
from playwright.sync_api import sync_playwright

assert launch_options() == {"channel": "chrome"}, "Release must use Chrome Stable"
with sync_playwright() as playwright:
    browser = playwright.chromium.launch(
        **launch_options(),
        headless=True,
        args=["--no-sandbox", "--disable-dev-shm-usage"]
    )
    version = browser.version
    assert tuple(map(int, version.split("."))) >= (155, 0, 8059, 39), version
    page = browser.new_page()
    page.set_content("<main><p id='probe'>browser runtime verified</p></main>")
    assert page.locator("#probe").inner_text() == "browser runtime verified"
    browser.close()
print(json.dumps({"channel": "chrome", "version": version, "result": "PASS"}))

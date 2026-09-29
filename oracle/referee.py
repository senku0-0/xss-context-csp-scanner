import asyncio
import json
import sys
from urllib.parse import quote
from playwright.async_api import async_playwright

# Fallback payload used when the CLI is called without --payload.
# Contains the marker so we can detect execution.
DEFAULT_PAYLOAD = "<script>window.__xss_fired=1</script>"

async def check(url, param="q", payload=DEFAULT_PAYLOAD):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        fired = {"alert": False, "marker": False, "console": [], "error": None}

        # Listen for alerts and console messages
        page.on("dialog", lambda d: (
            fired.update(alert=True),
            asyncio.create_task(d.dismiss())
        ))
        page.on("console", lambda m: fired["console"].append(m.text))

        # URL-encode the payload so special characters survive the query string
        full_url = f"{url}?{param}={quote(payload)}"
        try:
            await page.goto(full_url, wait_until="networkidle", timeout=5000)
        except Exception as e:
            fired["error"] = str(e)

        # Click any links on the page (so javascript: URLs get a chance to fire)
        try:
            links = await page.query_selector_all("a")
            for link in links:
                try:
                    await link.click(timeout=500)
                    await page.wait_for_timeout(100)
                except Exception:
                    pass
        except Exception:
            pass

        # Check the marker variable that every payload sets when it runs
        try:
            fired["marker"] = bool(await page.evaluate("window.__xss_fired === 1"))
        except Exception:
            pass

        await browser.close()
        fired["runs"] = fired["alert"] or fired["marker"]
        return fired


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python oracle/referee.py <url> [param] [payload]")
        sys.exit(1)

    url = sys.argv[1]
    param = sys.argv[2] if len(sys.argv) > 2 else "q"
    payload = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_PAYLOAD

    result = asyncio.run(check(url, param=param, payload=payload))
    print(json.dumps(result, indent=2))
#!/usr/bin/env python3
import re
import time
from typing import Any, Dict, List

import requests
from bs4 import BeautifulSoup
from mcp.server.fastmcp import FastMCP
from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.common.by import By

mcp = FastMCP("ccx-search")


def _mk_driver() -> webdriver.Chrome:
    opts = ChromeOptions()
    opts.add_argument("--headless=new")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument(
        "--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)

    driver = webdriver.Chrome(options=opts)
    driver.set_page_load_timeout(25)
    return driver


def _normalize_whitespace(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


@mcp.tool()
def search_web(query: str, max_results: int = 5, engine: str = "duckduckgo") -> Dict[str, Any]:
    if not query or not query.strip():
        return {"status": "error", "error": "query is empty"}

    max_results = max(1, min(int(max_results), 20))

    if engine.lower() != "duckduckgo":
        return {"status": "error", "error": f"unsupported engine: {engine}"}

    url = f"https://duckduckgo.com/html/?q={requests.utils.quote(query)}"

    driver = None
    try:
        driver = _mk_driver()
        driver.get(url)
        time.sleep(0.8)

        results: List[Dict[str, str]] = []
        cards = driver.find_elements(By.CSS_SELECTOR, "div.result")

        for card in cards:
            if len(results) >= max_results:
                break

            links = card.find_elements(By.CSS_SELECTOR, "a.result__a")
            if not links:
                continue

            a = links[0]
            title = _normalize_whitespace(a.text)
            href = a.get_attribute("href") or ""

            snips = card.find_elements(By.CSS_SELECTOR, "a.result__snippet, div.result__snippet")
            snippet = _normalize_whitespace(snips[0].text) if snips else ""

            if href and title:
                results.append({
                    "title": title,
                    "url": href,
                    "snippet": snippet,
                })

        return {
            "status": "ok",
            "engine": "duckduckgo",
            "query": query,
            "results": results,
        }

    except Exception as e:
        return {"status": "error", "error": str(e)}
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass


@mcp.tool()
def open_url(url: str, max_chars: int = 20000) -> Dict[str, Any]:
    if not url or not url.strip():
        return {"status": "error", "error": "url is empty"}

    max_chars = max(1000, min(int(max_chars), 200000))

    try:
        r = requests.get(
            url,
            timeout=20,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )
            },
        )
        r.raise_for_status()

        soup = BeautifulSoup(r.text, "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()

        text = _normalize_whitespace(soup.get_text(" "))
        if len(text) > max_chars:
            text = text[:max_chars] + " …(truncated)"

        return {
            "status": "ok",
            "url": url,
            "content_type": r.headers.get("content-type", ""),
            "text": text,
        }

    except Exception as e:
        return {"status": "error", "error": str(e)}


if __name__ == "__main__":
    mcp.run(transport="stdio")
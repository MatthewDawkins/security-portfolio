from typing import List, Dict, Set
from urllib.parse import urlparse, urljoin, urlunparse
from collections import deque
import requests
from bs4 import BeautifulSoup


def _normalize(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment=""))


def _same_origin(base: str, url: str) -> bool:
    b = urlparse(base)
    u = urlparse(url)
    return b.scheme == u.scheme and b.netloc == u.netloc


def crawl(
    start_url: str,
    session: requests.Session,
    max_pages: int = 50,
    timeout: int = 10,
) -> tuple[List[str], List[Dict]]:
    """
    BFS crawl starting from start_url.
    Returns (urls_found, forms_found).
    forms_found entries: {action, method, inputs: [{name, type, value}]}
    """
    visited: Set[str] = set()
    queue: deque = deque([_normalize(start_url)])
    urls: List[str] = []
    forms: List[Dict] = []

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
        except Exception:
            continue

        urls.append(url)

        content_type = resp.headers.get("Content-Type", "")
        if "html" not in content_type:
            continue

        soup = BeautifulSoup(resp.text, "html.parser")

        # Collect links
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith(("javascript:", "mailto:", "#")):
                continue
            abs_url = _normalize(urljoin(url, href))
            if _same_origin(start_url, abs_url) and abs_url not in visited:
                queue.append(abs_url)

        # Collect forms
        for form in soup.find_all("form"):
            action_raw = form.get("action", "") or url
            action = _normalize(urljoin(url, action_raw))
            method = form.get("method", "get").lower()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                if not name:
                    continue
                inputs.append({
                    "name": name,
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", "test"),
                })
            if inputs:
                forms.append({"action": action, "method": method, "inputs": inputs})

    return urls, forms

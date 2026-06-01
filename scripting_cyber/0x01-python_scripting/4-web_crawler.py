#!/usr/bin/env python3
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
from requests.exceptions import (
    ConnectionError,
    InvalidURL,
    RequestException,
    Timeout,
)


def crawl_website(start_url, max_depth=2):
    visited = set()
    start_domain = urlparse(start_url).netloc

    def crawl(url, depth):
        if depth < 0 or url in visited:
            return

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()

        except ConnectionError:
            print(f"[!] Connection error: {url}")
            return

        except Timeout:
            print(f"[!] Request timed out: {url}")
            return

        except InvalidURL:
            print(f"[!] Invalid URL: {url}")
            return

        except RequestException as e:
            print(f"[!] Request failed for {url}: {e}")
            return

        visited.add(url)

        if depth == 0:
            return

        soup = BeautifulSoup(response.text, "html.parser")

        for link in soup.find_all("a", href=True):
            next_url = urljoin(url, link["href"])
            parsed = urlparse(next_url)

            if parsed.scheme not in ("http", "https"):
                continue

            if parsed.netloc != start_domain:
                continue

            crawl(next_url, depth - 1)

    crawl(start_url, max_depth)

    return visited


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <url>")
        sys.exit(1)

    url = sys.argv[1]

    visited = crawl_website(url)

    for page in sorted(visited):
        print(page)

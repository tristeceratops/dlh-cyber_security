#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup


def download_page(url):
    result = ""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        result = soup.prettify()
    except requests.exceptions.RequestException as e:
        result = f"RequestException for {url}: {e}"
    except Exception as e:
        result = f"{url}: {e}"
    return result


if __name__ == "__main__":
    import sys
    url = sys.argv[1]
    print(f"\nPage content from {url}:")
    print("=" * 50)
    content = download_page(url)
    print(content)
    print("=" * 50)
    print(f"Content length: {len(content)} characters")

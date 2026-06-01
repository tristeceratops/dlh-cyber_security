#!/usr/bin/env python3
import requests


def get_http_headers(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        return {
                "status_code": response.status_code,
                "headers": dict(response.headers)
                }

    except requests.exceptions.RequestException as e:
        print(f"Request error occurred for URL {url}: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error occurred for URL {url}: {e}")
        return None


if __name__ == "__main__":
    import sys
    url = sys.argv[1]
    header = get_http_headers(url)
    if header:
        print(f"respone {header['status_code']}: ")
        print(f"{header['headers']}")

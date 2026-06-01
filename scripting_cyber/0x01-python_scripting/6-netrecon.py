#!/usr/bin/env python3
import socket
# import dns.resolver
import requests
from bs4 import BeautifulSoup
import subprocess


def resolve_domain_to_ipv4(domain_name):
    try:
        return socket.gethostbyname(domain_name)
    except socket.gaierror:
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None


def dns_recon(domain):
    ipv4 = resolve_domain_to_ipv4(domain)
    if ipv4:
        print(f"IP Address: {ipv4}")
        try:
            # answers = dns.resolver.resolve(domain, "MX")
            print("MX Records:")
            # for answer in answers:
            # print(answer)
            result = subprocess.run(
                    ["dig", domain, "MX", "+short"],
                    capture_output=True,
                    text=True
            )

            print(result.stdout)
        except Exception as e:
            print(f"Error: {e}")


def web_recon(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        response.raise_for_status()

        print(f"Status code: {response.status_code}")

        print("Important Headers:")
        for header, value in response.headers.items():
            print(f"{header}: {value}")

        soup = BeautifulSoup(response.text, "html.parser")
        links_count = len(soup.find_all("a", href=True))
        print(f"Total Links found: {links_count}")
    except Exception as e:
        print(f"Error: {e}")


def port_scan(domain):
    ports = {80, 443}

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)

            result = sock.connect_ex((domain, port))
            if result == 0:
                print(f"{port} OPEN")
            else:
                print(f"{port} CLOSED")

            sock.close()
        except Exception as e:
            print(f"Error: {e}")


def main():
    print("=" * 50)
    print("NETWORK RECONNAISSANCE TOOL")
    print("=" * 50)

    target = input("Enter target domain: ")

    print("\n" + "=" * 50)
    print("DNS RECONNAISSANCE")
    print("=" * 50)
    dns_recon(target)

    print("\n" + "=" * 50)
    print("WEB RECONNAISSANCE")
    print("=" * 50)
    web_recon(target)

    print("\n" + "=" * 50)
    print("PORT SCANNING")
    print("=" * 50)
    port_scan(target)

    print("\n" + "=" * 50)
    print("RECONNAISSANCE COMPLETE")
    print("=" * 50)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import socket


def check_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((host, port))
        sock.close()

        return result == 0

    except Exception as e:
        print(f"[!] {host} for port: {port}: {e}")
        return False


if __name__ == "__main__":
    import sys
    host = sys.argv[1]
    port = int(sys.argv[2])
    print(check_port(host, port))

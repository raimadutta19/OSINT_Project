# get_ip.py
import socket
import sys

def resolve(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None
    except Exception as e:
        return None

if __name__ == "__main__":
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input("Enter domain (e.g. example.com): ").strip()
    if not domain:
        print("No domain provided.")
        sys.exit(1)
    ip = resolve(domain)
    if ip:
        print(f"IP address of {domain} is: {ip}")
    else:
        print(f"Could not resolve domain: {domain}")

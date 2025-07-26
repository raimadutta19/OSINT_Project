import socket

domain = "mckvie.edu.in"
try:
    ip = socket.gethostbyname(domain)
    print(f"IP address of {domain} is: {ip}")
except socket.gaierror:
    print("Could not resolve domain.")

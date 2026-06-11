import socket
import ssl


import subprocess
import json

def get_sans(domain):
    result = subprocess.run(
        ["gsan", domain],
        capture_output=True,
        text=True
    )
    return result.stdout

sans = get_sans("google.com")
print(sans)
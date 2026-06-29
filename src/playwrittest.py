from urllib.parse import urlparse
from playwright.sync_api import sync_playwright #

def playwright():
    with sync_playwright() as p:
        browser = p.chromium.launch() #
        page = browser.new_page() #
        
        hostnames = set()
        
        # Attach the network request listener
        page.on("request", lambda request: hostnames.add(urlparse(request.url).hostname))
        
        # Open page and wait for resources to finish loading
        page.goto("https://google.com", wait_until="networkidle")
        
        print("Hostnames serving objects on this page:")
        for host in sorted(filter(None, hostnames)):
            print(f"- {host}")
            
        browser.close()

import findcdn
import json

def findcdnmethod():
    domains = ['google.com', 'cisa.gov', 'censys.io', 'yahoo.com', 'pbs.org', 'github.com']
    resp_json = findcdn.main(domains, output_path="output1.json", double_in=True, threads=23)

    dumped_json = json.loads(resp_json)

    for domain in dumped_json['domains']:
        print(f"{domain} has CDNs:\n {dumped_json['domains'][domain]['cdns']}")

#findcdnmethod()

import requests

domains = ["netflix.com", "unity3d.com"]

for domain in domains:
    try:
        resp = requests.get(f"https://{domain}", timeout=8, headers={"User-Agent": "Mozilla/5.0"}, verify=False)
        print(f"\n--- {domain} ---")
        for k, v in resp.headers.items():
            print(f"  {k}: {v}")
    except Exception as e:
        print(f"{domain} FAILED: {e}")
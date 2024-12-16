import requests
import sys
import time
import json
from bs4 import BeautifulSoup
import os
import subprocess
import re
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3 needed
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# ASCII Banner with Emojis
ascii_banner = r"""
 
 __   __ _____ _____    _____                                 
 \ \ / // ____/ ____|  / ____|                                
  \ V /| (___| (___   | (___   ___ __ _ _ __  _ __   ___ _ __ 
   > <  \___ \\___ \   \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
  / . \ ____) |___) |  ____) | (_| (_| | | | | | | |  __/ |   
 /_/ \_\_____/_____/  |_____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                              
           BY KARTHIK S SATHYAN                                                   

"""

def animate_ascii_banner(banner):
    """Display the ASCII banner with an animation effect."""
    for line in banner.splitlines():
        print(line)
        time.sleep(0.1)

def scrape_form_fields(url):
    """Scrape form fields from the target URL."""
    try:
        response = requests.get(url, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        form_data = []
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            fields = {inp.get('name'): inp.get('value', '') for inp in inputs if inp.get('name')}
            form_data.append({'action': action, 'method': method, 'fields': fields})
        return form_data
    except requests.exceptions.RequestException as e:
        print(f"❌ Error scraping forms: {e}")
        return []

def test_payloads(url, payloads, method="GET", data=None):
    """Test payloads for XSS vulnerabilities."""
    vulnerable = False
    vulnerable_payloads = []
    for i, payload in enumerate(payloads):
        if method.upper() == "POST":
            for key in data.keys():
                data[key] = data[key] + payload if data[key] else payload
            response = requests.post(url, data=data, verify=False)
        else:
            parsed_url = re.split(r'[?&]', url)
            if len(parsed_url) > 1:
                params = parsed_url[1:]
                for param in params:
                    key, value = param.split('=')
                    if value:
                        injection_url = f"{url.replace(param, f'{key}={value}{payload}')}"
                    else:
                        injection_url = f"{url.replace(param, f'{key}={payload}')}"
            else:
                injection_url = f"{url}?q={payload}"
            response = requests.get(injection_url, verify=False)
        print(f"\033[96mChecking URL: {injection_url}\033[0m")
        if payload in response.text:
            print(f"\033[91mVulnerability detected: {injection_url}\033[0m")
            vulnerable = True
            vulnerable_payloads.append(payload)
        # Ask user after testing 30 payloads
        if (i + 1) % 30 == 0:
            continue_attack = input("🔧 Do you want to continue the attack? (Y/N): ").strip().upper()
            if continue_attack == 'N':
                break
    return vulnerable, vulnerable_payloads

def scan_xss(url, payloads):
    print(f"🔍 Scanning URL: {url}")
    forms = scrape_form_fields(url)
    vulnerable = False
    vulnerable_payloads = []

    print("\n🌐 Testing GET requests...")
    is_vulnerable, payloads_found = test_payloads(url, payloads)
    vulnerable |= is_vulnerable
    vulnerable_payloads.extend(payloads_found)

    for form in forms:
        print(f"\n📝 Testing form with action: {form['action']} and method: {form['method'].upper()}")
        action_url = url + form['action']
        if form['method'] == 'post':
            is_vulnerable, payloads_found = test_payloads(action_url, payloads, method="POST", data=form['fields'])
            vulnerable |= is_vulnerable
            vulnerable_payloads.extend(payloads_found)

    if not vulnerable:
        print("✔️ No XSS vulnerabilities found.")
    else:
        print(f"🚨 Vulnerable URL: {url} with payloads: {vulnerable_payloads}")

def load_payloads_from_file(file_path):
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return []

    with open(file_path, 'r') as file:
        payloads = [line.strip() for line in file.readlines() if line.strip()]
    print(f"📂 Loaded {len(payloads)} payloads from {file_path}")
    return payloads

def scan_from_file(file_path, payloads):
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return

    with open(file_path, 'r') as file:
        urls = file.readlines()

    for url in urls:
        url = url.strip()
        if url:
            print(f"\n🌐 Scanning URL: {url}")
            scan_xss(url, payloads)

def collect_urls_from_wayback(domain):
    """Collect URLs from Wayback Machine for the given domain."""
    try:
        result = subprocess.run(['waybackurls', domain], capture_output=True, text=True)
        urls = result.stdout.splitlines()
        return urls
    except FileNotFoundError:
        print("❌ waybackurls tool not found. Please install it using 'go get -u github.com/tomnomnom/waybackurls'.")
        return []

def filter_xss_vulnerable_urls(urls):
    """Filter URLs to keep only those with common XSS-vulnerable parameters."""
    common_xss_params = ['q', 'search', 'query', 'keyword', 'term', 'name', 'id', 'page', 'view', 'content', 'text', 'param', 'input', 'data', 'value', 'message', 'comment']
    filtered_urls = {}

    for url in urls:
        parsed_url = re.split(r'[?&]', url)
        if len(parsed_url) > 1:
            params = parsed_url[1:]
            for param in params:
                key = param.split('=')[0]
                if key in common_xss_params and key not in filtered_urls:
                    filtered_urls[key] = url
                    break

    return list(filtered_urls.values())

def main():
    animate_ascii_banner(ascii_banner)
    payloads = load_payloads_from_file('xsspayloads.txt')

    print("\n🔍 Scan Options:")
    print("1️⃣ Scan a Single URL")
    print("2️⃣ Scan from a .txt File")
    print("3️⃣ Collect URLs from Wayback Machine")
    scan_mode = input("👉 Choose an option: ")

    if scan_mode == '1':
        target_url = input("🌐 Enter the URL to scan: ")
        scan_xss(target_url, payloads)
    elif scan_mode == '2':
        file_path = input("📂 Enter the path to the .txt file containing URLs: ")
        scan_from_file(file_path, payloads)
    elif scan_mode == '3':
        domain = input("🌐 Enter the domain name (e.g., example.com): ")
        urls = collect_urls_from_wayback(domain)
        if urls:
            filtered_urls = filter_xss_vulnerable_urls(urls)
            for url in filtered_urls:
                print(f"\n🌐 Scanning URL: {url}")
                scan_xss(url, payloads)
        else:
            print("❌ No URLs found from Wayback Machine.")
    else:
        print("❌ Invalid choice. Please enter '1', '2', or '3'.")

if __name__ == "__main__":
    main()

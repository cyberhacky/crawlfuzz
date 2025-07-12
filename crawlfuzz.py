#!/usr/bin/env python3
import os
import sys
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import subprocess
import json

# Terminal colors
RED, GREEN, YELLOW, BLUE, RESET = "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[0m"

# Globals
visited_urls = set()
extracted_urls = set()
js_files = set()
forms = []
parameters = set()

# WAF bypass techniques
waf_evasion_techniques = [
    ("header_smuggling", {"X-Forwarded-For": "127.0.0.1", "X-Originating-IP": "127.0.0.1"}),
    ("double_url_encode", {}),
    ("path_tampering", {"payload": "/%2e%2e/admin"}),
]

# CLI Arguments
parser = argparse.ArgumentParser(description="CRAWLFUZZ - Recursive Crawler + Fuzzer with WAF Bypass")
parser.add_argument("-u", "--url", required=True, help="Target URL")
parser.add_argument("-o", "--output", default="crawlfuzz_results", help="Output directory")
parser.add_argument("--deep", action="store_true", help="Deep crawl (3 levels)")
parser.add_argument("--waf-bypass", action="store_true", help="Enable WAF evasion")
parser.add_argument("--fuzz", action="store_true", help="Auto-run Nuclei, Dalfox, SQLMap")
parser.add_argument("--fast-nuclei", action="store_true", help="Use optimized nuclei scan for bug bounty/pentest")
parser.add_argument("--insecure", action="store_true", help="Ignore SSL certificate validation (for expired certs)")
args = parser.parse_args()

# Output dir
os.makedirs(args.output, exist_ok=True)

def crawl(url, depth=0, max_depth=3):
    if depth > max_depth or url in visited_urls:
        return
    visited_urls.add(url)
    print(f"{GREEN}[+] Crawling:{RESET} {url}")

    try:
        headers = {
            "User-Agent": "CRAWLFUZZ",
            "X-Researcher": "cyber1_hacky"
        }
        response = requests.get(url, timeout=10, headers=headers, verify=not args.insecure)
        soup = BeautifulSoup(response.text, 'html.parser')

        for link in soup.find_all('a', href=True):
            absolute_url = urljoin(url, link['href'])
            if args.url in absolute_url:
                extracted_urls.add(absolute_url)
                crawl(absolute_url, depth + 1, max_depth)

        for script in soup.find_all('script', src=True):
            js_url = urljoin(url, script['src'])
            if js_url.endswith('.js'):
                js_files.add(js_url)

        for form in soup.find_all('form'):
            form_action = urljoin(url, form.get('action', ''))
            form_method = form.get('method', 'get').lower()
            form_inputs = {
                input_tag.get('name'): input_tag.get('value', '')
                for input_tag in form.find_all('input') if input_tag.get('name')
            }
            forms.append((form_action, form_method, form_inputs))
            parameters.update(form_inputs.keys())

    except Exception as e:
        print(f"{RED}[!] Error crawling {url}: {e}{RESET}")

def merge_passive_data(target):
    print(f"{BLUE}[+] Running GAU + WaybackURLs{RESET}")
    try:
        gau_output = subprocess.check_output(f"gau {target}", shell=True, text=True).splitlines()
        wayback_output = subprocess.check_output(f"waybackurls {target}", shell=True, text=True).splitlines()
        return set(gau_output + wayback_output)
    except Exception as e:
        print(f"{RED}[!] Passive tools missing or failed: {e}{RESET}")
        return set()

def apply_waf_evasion(urls):
    print(f"{YELLOW}[+] Applying WAF Bypass Techniques{RESET}")
    modified_urls = set()
    header_payloads = []

    for url in urls:
        for technique, payload in waf_evasion_techniques:
            if technique == "header_smuggling":
                header_payloads.append((url, payload))
            elif technique == "double_url_encode":
                encoded = requests.utils.quote(requests.utils.quote(url))
                modified_urls.add(encoded)
            elif technique == "path_tampering":
                parsed = urlparse(url)
                tampered = parsed._replace(path=parsed.path + payload["payload"]).geturl()
                modified_urls.add(tampered)

    return modified_urls.union(urls), header_payloads

def generate_fuzzable_targets(all_urls):
    print(f"{GREEN}[+] Generating Fuzzable Targets{RESET}")
    with open(f"{args.output}/fuzz_targets.txt", "w") as f:
        for url in all_urls:
            f.write(f"{url}\n")
        for js in js_files:
            f.write(f"{js}\n")
        for form in forms:
            fuzz_url = f"{form[0]}?{'&'.join([f'{k}=FUZZ' for k in form[2].keys()])}"
            f.write(f"{fuzz_url}\n")

    with open(f"{args.output}/fuzz_targets_small.txt", "w") as fsmall:
        for i, url in enumerate(list(all_urls)[:500]):
            fsmall.write(f"{url}\n")

def run_vuln_scanners():
    print(f"{BLUE}[+] Running Vulnerability Scanners{RESET}")
    
    nuclei_input = f"{args.output}/fuzz_targets.txt"
    if args.fast_nuclei:
        print(f"{YELLOW}[!] Fast Nuclei mode activated (top 500 URLs, CVE/misconfig only){RESET}")
        nuclei_input = f"{args.output}/fuzz_targets_small.txt"
        nuclei_cmd = (
            f"nuclei -l {nuclei_input} "
            f"-t cves/ -t vulnerabilities/ -t misconfiguration/ "
            f"-rl 100 -timeout 5 -retries 1 -c 50 -max-host-error 50 "
            f"-H 'X-Researcher: cyber1_hacky' "
            f"-o {args.output}/nuclei_results.txt"
        )
    else:
        nuclei_cmd = (
            f"nuclei -l {nuclei_input} "
            f"-rl 50 -timeout 10 -retries 2 -c 30 -max-host-error 30 "
            f"-H 'X-Researcher: cyber1_hacky' "
            f"-o {args.output}/nuclei_results.txt"
        )

    subprocess.run(nuclei_cmd, shell=True)
    subprocess.run(f"dalfox file {nuclei_input} -H 'X-Researcher: cyber1_hacky' -o {args.output}/dalfox_results.txt", shell=True)
    subprocess.run(
        f"sqlmap -m {nuclei_input} --batch --output-dir={args.output}/sqlmap_results "
        f"--headers='User-Agent: CRAWLFUZZ\\nX-Researcher: cyber1_hacky'",
        shell=True
    )

# MAIN
if __name__ == "__main__":
    print(f"{YELLOW}=== CRAWLFUZZ - Recursive Crawler + Fuzzer ==={RESET}")

    crawl(args.url, max_depth=3 if args.deep else 1)
    extracted_urls.update(merge_passive_data(args.url))

    header_payloads = []
    if args.waf_bypass:
        extracted_urls, header_payloads = apply_waf_evasion(extracted_urls)

    generate_fuzzable_targets(extracted_urls)

    if header_payloads:
        with open(f"{args.output}/waf_headers.json", "w") as f:
            json.dump(header_payloads, f, indent=2)

    if args.fuzz:
        run_vuln_scanners()

    print(f"{GREEN}[+] Scan completed! Results saved to {args.output}/{RESET}")

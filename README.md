# CRAWLFUZZ 

> Recursive crawler + fuzzer with WAF bypass, passive recon & integrated vulnerability scanning — built for bug bounty hunters, pentesters, and rebels of the web.

![Banner](https://raw.githubusercontent.com/cyberhacy/crawlfuzz/main/banner.png)



   Features

-  Recursive HTML & JS crawler
-  GAU + Wayback passive URL collection
-  WAF Bypass (header smuggling, double encode, path tricks)
-  Auto-run: Nuclei, Dalfox, SQLMap
-  fast-nuclei` mode (bug bounty optimized)
-  Custom headers: (eg.`X-Researcher: cyber1_hacky`)


 Usage

python3 crawlfuzz.py -u https://target.com --deep --waf-bypass --fuzz --fast-nuclei --insecure

  Flag	                Description
--deep	                Crawl up to 3 levels deep
--waf-bypass	          Adds obfuscation techniques
--fuzz	                Runs vulnerability scanners
--fast-nuclei	          Limits to top 500 targets & relevant templates
--insecure	            Ignore expired SSL certs


 Requirements

pip install -r requirements.txt

Tools you'll need to installed:

gau
    
waybackurls

nuclei
    
dalfox
    
sqlmap

 Author

Made by @cyberhacy

Recursive Web Crawling

 Crawls target URLs up to 3 levels deep (--deep)

 Follows internal links only (domain-restricted)

  Extracts:

  All <a href> links

  JavaScript file paths (.js)

  HTML forms and input fields

  Useful for building dynamic attack surface maps automatically

2. Passive Reconnaissance Integration

Merges in results from:

gau (getallurls)

waybackurls (archived endpoints)

Finds legacy endpoints, API paths, and parameters missed by live crawl

3. WAF Bypass Techniques (--waf-bypass)

Applies multiple evasion tricks to every crawled URL:

Header smuggling: X-Forwarded-For, X-Originating-IP

Double URL encoding: /admin → %252e%252e%2fadmin

Path tampering: Appending /../admin, etc.

Bypasses naive path-based or header-based security filters

4. Parameter & Form Discovery

Parses <form> actions, methods, and inputs

Builds fuzzable request URLs like:

http://target.com/login.php?username=FUZZ&password=FUZZ

Fuel for XSS, SQLi, SSRF, and more

5. Vulnerability Scanning (--fuzz)

Automatically launches:
Nuclei

CVEs, misconfigurations, tech detection
    
Optimized in --fast-nuclei mode to run top 3 template types against top 500 URLs

Dalfox

DOM & reflected XSS scanning

Uses discovered URLs and form payloads

SQLMap

SQL injection fuzzing using --batch mode

Injects payloads into all detected parameters

All scanners send attribution header:

X-Researcher: cyber1_hacky

6. SSL-Bypass Mode (--insecure)

Skips certificate verification to allow scanning of:

Expired certs (e.g. webscantest.com)

Self-signed test labs

 Bug bounty subdomains not properly configured
    
7. Optimized Fast-Strike Mode (--fast-nuclei)

Reduces scan size intelligently:

Uses top 500 URLs

Loads CVE/misconfig templates only

Applies rate limits and concurrency controls

 Perfect for daily recon and scoped bounty testing
    
 8. Organized Output

fuzz_targets.txt → full target list

fuzz_targets_small.txt → prioritized top 500

waf_headers.json → header-based bypass combos
    
Scanner outputs saved to:

nuclei_results.txt

dalfox_results.txt

sqlmap_results/
        
Bonus: Easy to Extend

You can bolt on:

Interactsh integration (for blind RCE/XSS)

Subdomain brute-force

Directory fuzzing (ffuf, feroxbuster)

GitHub Actions for CI-based scanning


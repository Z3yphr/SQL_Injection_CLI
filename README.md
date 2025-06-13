# SQL Injection Testing CLI Tool

This project is a Python-based command-line tool designed to test web applications for SQL injection vulnerabilities. It supports both automated and manual testing, brute-force credential discovery, and blind SQLi extraction.

## Features

- Accepts a target URL and parameters
- Automatically discovers and tests forms for SQL injection
- Supports crawling all internal pages for comprehensive testing
- Brute-force login forms using user-supplied username and password lists (external files required)
- Blind SQLi extraction to enumerate credentials from scratch
- Clear, grouped CLI output and summary

## Usage

- `No Arguments` will display my dev name, the date, and all the possible input details you need. 
- `--auto` tests forms only on the page specified by `--url` (no crawling).
- `--crawl` starts at the specified URL and follows internal links, testing forms on every discovered page.
- Use both `--auto` and `--crawl` together to test the initial page and crawl the rest of the site.

### Launch the Test Dummy Site

1. Ensure you have Python 3.8+ and Flask installed:

   ```powershell
   pip install flask
   ```

2. Start the vulnerable test site:

   ```powershell
   python vuln_app.py
   ```

   The site will be available at http://127.0.0.1:5000/
   - The home page is at `/`.
   - The login form is at `/login`.

### Basic SQLi Test (manual parameters)

```powershell
python main.py --url "http://127.0.0.1:5000/login" --params "username=admin&password=admin"
```

### Automatic Form Discovery (main login page only, no crawling)

```powershell
python main.py --url "http://127.0.0.1:5000/login" --auto
```

### Crawl and Test All Pages (finds and tests all forms on all internal pages)

```powershell
python main.py --url "http://127.0.0.1:5000/" --crawl
```

### Use Both --auto and --crawl (comprehensive, no duplicate testing)

```powershell
python main.py --url "http://127.0.0.1:5000/" --auto --crawl
```

### Brute-force Credentials with User/Password Lists

```powershell
python main.py --url "http://127.0.0.1:5000/login" --auto --crack_lists --userlist users.txt --passlist passwords.txt
```

- `users.txt` and `passwords.txt` should contain one entry per line.
- Both files are required for brute-force mode. If not provided, brute-force will not run.

### Blind SQLi Extraction (no prior knowledge, enumerate all users)

```powershell
python main.py --url "http://127.0.0.1:5000/login" --auto --fresh_crack
```

Or, to crawl and extract from all forms on all pages:

```powershell
python main.py --url "http://127.0.0.1:5000/" --crawl --fresh_crack
```

### All Options

Run `python main.py --help` for a full list of options and descriptions.

## Example Output

```text
========== SUMMARY ==========
[Page: http://127.0.0.1:5000/]
Possible SQLi payloads:
  - username with payload: ' OR 1=1--  (response changed)
  - [!!!] Authentication bypassed using username with payload: ' OR 1=1--
Validated credentials:
  - username='admin', password='admin123'
============================
```

## Secure Demo Site

A secure version of the dummy site is provided in `secure_app.py`. This site uses parameterized SQL queries and proper output escaping to demonstrate how to mitigate SQL injection and XSS vulnerabilities.

- Start the secure site:
  ```powershell
  python secure_app.py
  ```
  The site will be available at http://127.0.0.1:5000/

- The code structure and user experience are identical to the vulnerable version, but all major vulnerabilities are mitigated.

## CLI Output Details

- **[!] Potential SQL Injection (SQL error):** Strong indicator of SQL injection (SQL error message detected).
- **[i] Response changed for payload, but this does NOT confirm SQL injection:** The page output changed when a payload was injected, but this is not a confirmed vulnerability. This may be normal behavior for some forms.
- **[!] Potential XSS (payload reflected):** The payload was reflected in the response and may be exploitable as XSS.
- **[POC]**: Proof-of-concept URL or curl command for XSS payloads that are reflected.

## Vulnerabilities Demonstrated

### Vulnerable Site (`vuln_app.py`)
- **SQL Injection:**
  - Login form uses string formatting in SQL queries (vulnerable).
  - Profile lookup may reflect input unsafely.
- **XSS:**
  - Profile page reflects user input with `|safe` (vulnerable to reflected XSS).

### Secure Site (`secure_app.py`)
- **SQL Injection Mitigation:**
  - All queries use parameterized statements (`?` placeholders).
- **XSS Mitigation:**
  - No use of `|safe` in templates; Flask auto-escapes output.

## Requirements

- Python 3.8+
- Install dependencies:

  ```powershell
  pip install -r requirements.txt
  ```

## Vulnerable Dummy Site Details

The included `vuln_app.py` is an intentionally vulnerable Flask web application for safe SQL injection testing. **Do not deploy in production!**

### What is Vulnerable?

- The login form at `/login` is vulnerable to SQL injection in both the `username` and `password` fields.
- The backend uses a raw SQL query with unsanitized user input:

  ```python
  query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
  ```

- No input validation or parameterization is performed.
- The login form always returns a message on the same page, indicating success or failure.
- The user database is reset on every login attempt, so destructive SQLi payloads do not persist.
- The `/profile` page is vulnerable to reflected XSS in the `username` parameter (input is echoed unsanitized).

### How the CLI Tool Tests the Dummy Site

- **Basic SQLi:** The tool injects common payloads into each form field and looks for changes in the response or error messages.
- **XSS:** The tool injects common XSS payloads into each form field and checks if the payload is reflected in the response (reflected XSS detection).
- **Authentication Bypass:** If a payload causes the login to succeed ("Login successful!"), the tool reports an authentication bypass.
- **Brute-force:** The tool can try username/password combinations from external lists, reporting any valid credentials found.
- **Blind SQLi Extraction:** The tool uses boolean-based blind SQLi to extract usernames and passwords character by character, by observing when the response indicates a successful login.
- **Crawling:** The tool can discover and test all forms on all internal pages of the dummy site, including pages with many links.

**Note:** The dummy site is designed to be stable for repeated testing, and the CLI tool is tailored to detect and exploit its specific vulnerabilities for educational and demonstration purposes.

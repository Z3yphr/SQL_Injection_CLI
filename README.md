# SQL Injection Testing and Remediation CLI Tool

This project is a Python-based command-line tool designed to test web applications for SQL injection vulnerabilities and suggest remediation strategies. It supports both automated and manual testing, brute-force credential discovery, and blind SQLi extraction.

## Features

- Accepts a target URL and parameters
- Automatically discovers and tests forms for SQL injection
- Supports crawling all internal pages for comprehensive testing
- Brute-force login forms using user-supplied username and password lists (external files required)
- Blind SQLi extraction to enumerate credentials from scratch
- Clear, grouped CLI output and summary

## Usage

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

### Basic SQLi Test (manual parameters)

```powershell
python main.py --url "http://127.0.0.1:5000/" --params "username=admin&password=admin"
```

### Automatic Form Discovery (main page only, blind SQLi by default)

```powershell
python main.py --url "http://127.0.0.1:5000/" --auto
```

### Crawl and Test All Pages (blind SQLi by default)

```powershell
python main.py --url "http://127.0.0.1:5000/" --crawl
```

### Use Both --auto and --crawl (comprehensive, no duplicate testing)

```powershell
python main.py --url "http://127.0.0.1:5000/" --auto --crawl
```

### Brute-force Credentials with User/Password Lists

```powershell
python main.py --url "http://127.0.0.1:5000/" --auto --crack_lists --userlist users.txt --passlist passwords.txt
```

- `users.txt` and `passwords.txt` should contain one entry per line.
- Both files are required for brute-force mode. If not provided, brute-force will not run.

### Blind SQLi Extraction (no prior knowledge, enumerate all users)

```powershell
python main.py --url "http://127.0.0.1:5000/" --auto --fresh_crack
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

## Requirements

- Python 3.8+
- Install dependencies:

  ```powershell
  pip install -r requirements.txt
  ```

## Vulnerable Dummy Site Details

The included `vuln_app.py` is an intentionally vulnerable Flask web application for safe SQL injection testing. **Do not deploy in production!**

### What is Vulnerable?

- The login form at `/` is vulnerable to SQL injection in both the `username` and `password` fields.
- The backend uses a raw SQL query with unsanitized user input:

  ```python
  query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
  ```

- No input validation or parameterization is performed.
- The login form always returns a message on the same page, indicating success or failure.
- The user database is reset on every login attempt, so destructive SQLi payloads do not persist.

### How the CLI Tool Tests the Dummy Site

- **Basic SQLi:** The tool injects common payloads into each form field and looks for changes in the response or error messages.
- **Authentication Bypass:** If a payload causes the login to succeed ("Login successful!"), the tool reports an authentication bypass.
- **Brute-force:** The tool can try username/password combinations from external lists, reporting any valid credentials found.
- **Blind SQLi Extraction:** The tool uses boolean-based blind SQLi to extract usernames and passwords character by character, by observing when the response indicates a successful login.
- **Crawling:** The tool can discover and test all forms on all internal pages of the dummy site.

**Note:** The dummy site is designed to be stable for repeated testing, and the CLI tool is tailored to detect and exploit its specific vulnerabilities for educational and demonstration purposes.

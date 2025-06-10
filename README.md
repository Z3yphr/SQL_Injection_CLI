# SQL Injection Testing and Remediation CLI Tool

This project is a Python-based command-line tool designed to test web applications for SQL injection vulnerabilities and suggest remediation strategies. It supports both automated and manual testing, brute-force credential discovery, and blind SQLi extraction.

## Features

- Accepts a target URL and parameters
- Automatically discovers and tests forms for SQL injection
- Supports crawling all internal pages for comprehensive testing
- Brute-force login forms using user-supplied username and password lists
- Blind SQLi extraction to enumerate credentials from scratch
- Clear, grouped CLI output and summary

## Usage

### Basic SQLi Test (manual parameters)

```powershell
python main.py --url "http://target.site/login" --params "username=admin&password=admin"
```

### Automatic Form Discovery (main page only, blind SQLi by default)

```powershell
python main.py --url "http://target.site/" --auto
```

### Crawl and Test All Pages (blind SQLi by default)

```powershell
python main.py --url "http://target.site/" --crawl
```

### Use Both --auto and --crawl (comprehensive, no duplicate testing)

```powershell
python main.py --url "http://target.site/" --auto --crawl
```

### Brute-force Credentials with User/Password Lists

```powershell
python main.py --url "http://target.site/" --auto --crack_lists --userlist users.txt --passlist passwords.txt
```

- `users.txt` and `passwords.txt` should contain one entry per line.
- Both files are required for brute-force mode.

### Blind SQLi Extraction (no prior knowledge, enumerate all users)

```powershell
python main.py --url "http://target.site/" --auto --fresh_crack
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

## License

MIT

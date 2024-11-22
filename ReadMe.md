# Log File Analyzer

## Overview
The **Log File Analyzer** is a Python-based tool that parses and analyzes server log files (e.g., Apache or Nginx) for suspicious activity. It identifies patterns such as failed login attempts, high-frequency IP requests, and access to sensitive endpoints. The findings are saved in a CSV file for further analysis.

## Purpose
This project aims to provide a simple yet effective way to identify potential security threats in server log files. By automating log analysis, system administrators and cybersecurity analysts can quickly detect and respond to suspicious activity, improving the overall security posture of their systems.

## Features
- Parses server logs in Apache/Nginx format.
- Detects:
  - Failed login attempts (401 or 403 HTTP status codes).
  - Access to sensitive endpoints like `/admin` or `/login`.
  - High-frequency requests from IPs.
- Outputs suspicious activity to a structured CSV file.

## Technologies Used
- **Python**: Core programming language for log analysis.
- **Regex (`re`)**: For extracting data from log entries.
- **CSV**: To store results for further inspection.

## How to Use
1. Clone the repository:
    ```bash
    git clone <repository_url>
    cd log_file_analyzer
    ```
2. Place your log file in the project folder and name it `access.log`.
3. Run the script:
    ```bash
    python log_file_analyzer.py
    ```
4. Check the results:
    - Suspicious activity will be saved in `suspicious_activity.csv`.
    - High-frequency IPs will be displayed in the terminal.

## Example
### Input (`access.log`):
127.0.0.1 - - [20/Nov/2024:12:34:56 +0000] "GET /index.html HTTP/1.1" 200 1024 192.168.1.1 - - [20/Nov/2024:12:35:01 +0000] "POST /login HTTP/1.1" 401 512 203.0.113.5 - - [20/Nov/2024:12:35:05 +0000] "GET /admin HTTP/1.1" 403 256 198.51.100.2 - - [20/Nov/2024:12:35:10 +0000] "GET /contact.html HTTP/1.1" 200 1024 192.168.1.1 - - [20/Nov/2024:12:35:15 +0000] "POST /login HTTP/1.1" 401 512

### Output (`suspicious_activity.csv`):
| IP Address    | Timestamp                  | Method | Endpoint | Status Code |
|---------------|----------------------------|--------|----------|-------------|
| 192.168.1.1   | 20/Nov/2024:12:35:01 +0000 | POST   | /login   | 401         |
| 203.0.113.5   | 20/Nov/2024:12:35:05 +0000 | GET    | /admin   | 403         |
| 192.168.1.1   | 20/Nov/2024:12:35:15 +0000 | POST   | /login   | 401         |

### High-Frequency IPs:
192.168.1.1: 2 requests

## License
This project is licensed under the MIT License.

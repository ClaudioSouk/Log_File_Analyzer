import re
import csv

# Step 1: Define suspicious patterns
SUSPICIOUS_ENDPOINTS = ["/admin", "/login"]
FAILED_STATUS_CODES = [401, 403]

# Step 2: Function to parse a log line
def parse_log_line(line):
    pattern = r'(?P<ip>\S+) - - \[(?P<timestamp>.*?)\] "(?P<method>\S+) (?P<endpoint>\S+) \S+" (?P<status>\d+) (?P<size>\d+)'
    match = re.match(pattern, line)
    if match:
        return match.groupdict()
    return None

# Step 3: Analyze the log file
def analyze_log(file_path, output_file):
    results = []
    ip_request_count = {}

    print(f"Analyzing log file: {file_path}")
    
    with open(file_path, 'r') as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                # Count requests per IP
                ip = parsed["ip"]
                ip_request_count[ip] = ip_request_count.get(ip, 0) + 1

                # Check for suspicious activity
                endpoint = parsed["endpoint"]
                status = int(parsed["status"])
                is_suspicious = endpoint in SUSPICIOUS_ENDPOINTS or status in FAILED_STATUS_CODES

                if is_suspicious:
                    results.append({
                        "IP Address": ip,
                        "Timestamp": parsed["timestamp"],
                        "Method": parsed["method"],
                        "Endpoint": endpoint,
                        "Status Code": status
                    })

    # Save results to a CSV file
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ["IP Address", "Timestamp", "Method", "Endpoint", "Status Code"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    
    # Print high-frequency IPs
    print("\nHigh-frequency IPs:")
    for ip, count in ip_request_count.items():
        if count > 3:
            print(f"{ip}: {count} requests")

    print(f"\nSuspicious activity saved to {output_file}")

# Step 4: Run the analysis
if __name__ == "__main__":
    log_file = "access.log"  # Input log file
    output_csv = "suspicious_activity.csv"  # Output file
    analyze_log(log_file, output_csv)

#!/usr/bin/env python3
# VoIP LFI Vulnerability Scanner

import asyncio
import httpx
import sqlite3
import logging
from datetime import datetime
import re
import json
import os
import ipaddress
import ssl
import csv
import yaml
import pdfkit
from tenacity import retry, wait_fixed, stop_after_attempt
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
import time
import warnings
import urllib3
from jinja2 import Environment, FileSystemLoader

# -- Configuration Settings --
CONFIG_FILE = "config.yaml"
DB_FILE = "voip_scanner.db"
RESULTS_FILE = "results.log"
REPORTS_DIR = "reports"
TEMPLATES_DIR = "templates"

# -- Load Configuration --
def load_config():
    """Load configuration from YAML file"""
    try:
        with open(CONFIG_FILE, "r") as f:
            config = yaml.safe_load(f)
            
        # Default values if not provided in file
        defaults = {
            'http_timeout': 7,
            'concurrent_connections': 50,
            'rate_limit_delay': 0.05,
            'scan_ports': [80, 443, 8080, 8443],
            'user_agents': [
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36",
                "VOIP Device Agent/1.0"
            ]
        }
        
        for key, value in defaults.items():
            if key not in config:
                config[key] = value
                
        return config
    except Exception as e:
        print(f"Error loading config file: {str(e)}")
        return None

config = load_config()

if not config:
    print("Cannot continue without valid config file")
    exit(1)

# -- Logging Setup --
logging.basicConfig(
    filename=RESULTS_FILE,
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

console = Console()

# -- Database Functions --
def init_db():
    """Initialize the database"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Known devices table
    c.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            device_name TEXT PRIMARY KEY,
            user_agents TEXT,
            paths TEXT,
            fingerprints TEXT
        )
    ''')
    
    # Scan results table
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            port INTEGER,
            device_name TEXT,
            path TEXT,
            protocol TEXT,
            status_code INTEGER,
            response_time REAL,
            response_size INTEGER,
            detected_lfi BOOLEAN,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Scan statistics table
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            total_ips INTEGER,
            scanned_ips INTEGER,
            vulnerable_ips INTEGER,
            start_time TEXT,
            end_time TEXT
        )
    ''')
    
    conn.commit()
    return conn

def load_devices_db(conn):
    """Load device data from database"""
    c = conn.cursor()
    c.execute('SELECT device_name, user_agents, paths, fingerprints FROM devices')
    rows = c.fetchall()
    devices_db = {}
    for device_name, user_agents_str, paths_str, fingerprints_str in rows:
        devices_db[device_name] = {
            "user_agents": json.loads(user_agents_str) if user_agents_str else [],
            "paths": json.loads(paths_str) if paths_str else [],
            "fingerprints": json.loads(fingerprints_str) if fingerprints_str else []
        }
    return devices_db

def save_device(conn, device_name, user_agents=None, paths=None, fingerprints=None):
    """Save or update device in database"""
    if user_agents is None:
        user_agents = []
    if paths is None:
        paths = []
    if fingerprints is None:
        fingerprints = []
        
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO devices 
        (device_name, user_agents, paths, fingerprints) 
        VALUES (?, ?, ?, ?)
    ''', (
        device_name, 
        json.dumps(user_agents), 
        json.dumps(paths),
        json.dumps(fingerprints)
    ))
    conn.commit()

def save_scan_result(conn, ip, port, device_name, path, protocol, status_code, response_time, response_size, detected_lfi):
    """Save scan result to database"""
    c = conn.cursor()
    c.execute('''
        INSERT INTO scan_results
        (ip, port, device_name, path, protocol, status_code, response_time, response_size, detected_lfi)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (ip, port, device_name, path, protocol, status_code, response_time, response_size, detected_lfi))
    conn.commit()

def start_scan_session(conn, total_ips):
    """Start new scan session and record start time"""
    c = conn.cursor()
    c.execute('''
        INSERT INTO scan_stats 
        (total_ips, scanned_ips, vulnerable_ips, start_time)
        VALUES (?, ?, ?, datetime('now'))
    ''', (total_ips, 0, 0))
    conn.commit()
    return c.lastrowid

def update_scan_session(conn, session_id, scanned_ips, vulnerable_ips):
    """Update scan session statistics"""
    c = conn.cursor()
    c.execute('''
        UPDATE scan_stats 
        SET scanned_ips = ?, vulnerable_ips = ?
        WHERE id = ?
    ''', (scanned_ips, vulnerable_ips, session_id))
    conn.commit()

def end_scan_session(conn, session_id):
    """End scan session and record end time"""
    c = conn.cursor()
    c.execute('''
        UPDATE scan_stats 
        SET end_time = datetime('now')
        WHERE id = ?
    ''', (session_id,))
    conn.commit()

# -- Response Analysis --
def analyze_response(resp: httpx.Response):
    """Analyze response for LFI vulnerabilities"""
    if resp is None or resp.status_code != 200:
        return False

    content = resp.text.lower()
    for keyword in config.get('lfi_indicators', {}).get('content', []):
        if keyword.lower() in content:
            return True

    headers = resp.headers
    for header_key in config.get('lfi_indicators', {}).get('headers', []):
        header_value = headers.get(header_key, "").lower()
        if header_value and any(k in header_value for k in config.get('lfi_indicators', {}).get('content', [])):
            return True

    return False

def extract_body_patterns(body_text):
    """Extract distinctive patterns from page content"""
    patterns = []
    body_text = body_text.lower()
    
    # HTML meta tags
    meta_generator = re.search(r'<meta name="generator" content="([^"]+)"', body_text)
    if meta_generator:
        patterns.append(f"meta_generator:{meta_generator.group(1)}")
    
    # Copyright notices
    copyright_match = re.search(r'copyright.*?(\d{4})', body_text)
    if copyright_match:
        patterns.append(f"copyright:{copyright_match.group(1)}")
    
    # Login forms
    if any(x in body_text for x in ["login", "username", "password", "sign in"]):
        patterns.append("login_form")
    
    return patterns

def detect_device_system(resp: httpx.Response, devices_db):
    """Detect device type using advanced fingerprinting"""
    if resp is None:
        return None
    
    # Build device fingerprint from response
    fingerprint = {
        'server': resp.headers.get("server", "").lower(),
        'x-powered-by': resp.headers.get("x-powered-by", "").lower(),
        'www-authenticate': resp.headers.get("www-authenticate", "").lower(),
        'set-cookie': resp.headers.get("set-cookie", "").lower(),
        'body_patterns': extract_body_patterns(resp.text)
    }
    
    # Check against known device fingerprints
    for device, info in devices_db.items():
        for known_fingerprint in info.get("fingerprints", []):
            match_score = 0
            
            # Match HTTP headers
            for header in ['server', 'x-powered-by', 'www-authenticate', 'set-cookie']:
                if known_fingerprint.get(header) and known_fingerprint[header] in fingerprint[header]:
                    match_score += 1
            
            # Match body patterns
            for pattern in known_fingerprint.get('body_patterns', []):
                if pattern in fingerprint['body_patterns']:
                    match_score += 1
                    
            # Consider it a match if 3+ elements match
            if match_score >= 3:
                return device
    
    # Fallback to traditional detection if fingerprinting fails
    combined_headers = (resp.headers.get("server", "") + " " + resp.headers.get("user-agent", "")).strip()
    for device, info in devices_db.items():
        for known_ua in info.get("user_agents", []):
            if known_ua.lower() in combined_headers.lower():
                return device
                
    return None

# -- HTTP Requests with Retry --
@retry(wait=wait_fixed(2), stop=stop_after_attempt(3))
async def fetch_url(client, url):
    """Send HTTP request with retry on failure"""
    start_time = time.monotonic()
    resp = await client.get(url, follow_redirects=True)
    resp.raise_for_status()
    elapsed = time.monotonic() - start_time
    return resp, elapsed

async def request_url(client, protocol, ip, port, path):
    """Send HTTP/HTTPS request"""
    url = f"{protocol}://{ip}:{port}{path}"
    try:
        resp, elapsed = await fetch_url(client, url)
        return resp, elapsed
    except (httpx.RequestError, httpx.HTTPStatusError) as e:
        logging.debug(f"Request failed to {url}: {str(e)}")
        return None, None

async def test_path(client, ip, port, path):
    """Test specific path on both HTTP and HTTPS"""
    # Test HTTP
    resp, elapsed = await request_url(client, "http", ip, port, path)
    if resp and analyze_response(resp):
        return True, resp.status_code, "http", elapsed, len(resp.content)

    # Test HTTPS
    resp, elapsed = await request_url(client, "https", ip, port, path)
    if resp and analyze_response(resp):
        return True, resp.status_code, "https", elapsed, len(resp.content)

    return False, None, None, None, None

# -- Device Management --
def add_unknown_device(conn, devices_db, ip, resp=None):
    """Add unknown device to database"""
    device_name = f"Unknown_{ip.replace('.','_')}"
    
    if device_name in devices_db:
        return device_name
    
    console.log(f"[yellow]New device detected: {device_name}[/yellow]")
    
    # Default paths to scan
    default_paths = config.get('default_paths', [
        "/etc/passwd", 
        "/etc/shadow", 
        "/admin/config", 
        "/cgi-bin/", 
        "/etc/config.php"
    ])
    
    # Device fingerprint if response is available
    fingerprint = {}
    if resp:
        fingerprint = {
            'server': resp.headers.get("server", "").lower(),
            'x-powered-by': resp.headers.get("x-powered-by", "").lower(),
            'www-authenticate': resp.headers.get("www-authenticate", "").lower(),
            'set-cookie': resp.headers.get("set-cookie", "").lower(),
            'body_patterns': extract_body_patterns(resp.text)
        }
    
    devices_db[device_name] = {
        "user_agents": [],
        "paths": default_paths,
        "fingerprints": [fingerprint] if fingerprint else []
    }
    
    save_device(
        conn, 
        device_name, 
        paths=default_paths,
        fingerprints=[fingerprint] if fingerprint else []
    )
    
    return device_name

# -- Results Handling --
def get_vulnerabilities(conn, limit=1000):
    """Get list of discovered vulnerabilities"""
    c = conn.cursor()
    c.execute('''
        SELECT 
            ip || ':' || port as ip_port,
            device_name,
            path,
            protocol,
            status_code,
            response_time,
            response_size,
            timestamp
        FROM scan_results
        WHERE detected_lfi = 1
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (limit,))
    
    return [dict(zip(['ip_port', 'device_name', 'path', 'protocol', 'status_code', 
                     'response_time', 'response_size', 'timestamp'], row)) 
            for row in c.fetchall()]

def get_scan_statistics(conn):
    """Get scan statistics"""
    c = conn.cursor()
    
    # General statistics
    c.execute('SELECT COUNT(*) FROM scan_results')
    total_scans = c.fetchone()[0]
    
    c.execute('SELECT COUNT(DISTINCT ip) FROM scan_results')
    unique_ips = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM scan_results WHERE detected_lfi = 1')
    vulnerabilities = c.fetchone()[0]
    
    c.execute('SELECT COUNT(DISTINCT ip) FROM scan_results WHERE detected_lfi = 1')
    vulnerable_ips = c.fetchone()[0]
    
    # Most vulnerable devices
    c.execute('''
        SELECT device_name, COUNT(*) as count 
        FROM scan_results 
        WHERE detected_lfi = 1
        GROUP BY device_name 
        ORDER BY count DESC 
        LIMIT 5
    ''')
    top_devices = [dict(zip(['device_name', 'count'], row)) for row in c.fetchall()]
    
    # Most vulnerable paths
    c.execute('''
        SELECT path, COUNT(*) as count 
        FROM scan_results 
        WHERE detected_lfi = 1
        GROUP BY path 
        ORDER BY count DESC 
        LIMIT 5
    ''')
    top_paths = [dict(zip(['path', 'count'], row)) for row in c.fetchall()]
    
    return {
        'total_scans': total_scans,
        'unique_ips': unique_ips,
        'vulnerabilities': vulnerabilities,
        'vulnerable_ips': vulnerable_ips,
        'top_devices': top_devices,
        'top_paths': top_paths
    }

# -- Report Generation --
def generate_reports(conn):
    """Generate multiple report formats"""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(TEMPLATES_DIR, exist_ok=True)
    
    # Create HTML template if it doesn't exist
    if not os.path.exists(os.path.join(TEMPLATES_DIR, "report_template.html")):
        create_default_template()
    
    # Get data
    vulns = get_vulnerabilities(conn)
    stats = get_scan_statistics(conn)
    
    # Generate reports
    generate_html_report(vulns, stats, os.path.join(REPORTS_DIR, "report.html"))
    generate_pdf_report(vulns, stats, os.path.join(REPORTS_DIR, "report.pdf"))
    generate_csv_report(vulns, os.path.join(REPORTS_DIR, "report.csv"))
    
    console.log(f"[green]Reports generated in {REPORTS_DIR} directory[/green]")

def create_default_template():
    """Create default HTML report template"""
    template_content = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>LFI Vulnerability Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #2c3e50; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .vulnerable { color: red; font-weight: bold; }
        .summary { background-color: #f0f8ff; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>LFI Vulnerability Scan Report</h1>
    <p>Report Date: {{ scan_date }}</p>
    
    <div class="summary">
        <h2>Scan Summary</h2>
        <p>Total Targets Scanned: {{ statistics.total_scans }}</p>
        <p>Unique IPs: {{ statistics.unique_ips }}</p>
        <p>Vulnerabilities Found: <span class="vulnerable">{{ statistics.vulnerabilities }}</span></p>
        <p>Vulnerable IPs: <span class="vulnerable">{{ statistics.vulnerable_ips }}</span></p>
    </div>
    
    <h2>Top Vulnerable Devices</h2>
    <table>
        <tr>
            <th>Device Name</th>
            <th>Vulnerability Count</th>
        </tr>
        {% for device in statistics.top_devices %}
        <tr>
            <td>{{ device.device_name }}</td>
            <td>{{ device.count }}</td>
        </tr>
        {% endfor %}
    </table>
    
    <h2>Top Vulnerable Paths</h2>
    <table>
        <tr>
            <th>Path</th>
            <th>Vulnerability Count</th>
        </tr>
        {% for path in statistics.top_paths %}
        <tr>
            <td>{{ path.path }}</td>
            <td>{{ path.count }}</td>
        </tr>
        {% endfor %}
    </table>
    
    <h2>Vulnerability Details</h2>
    <table>
        <tr>
            <th>Target</th>
            <th>Device</th>
            <th>Path</th>
            <th>Protocol</th>
            <th>Status</th>
            <th>Response Time</th>
            <th>Size</th>
            <th>Timestamp</th>
        </tr>
        {% for vuln in vulnerabilities %}
        <tr>
            <td>{{ vuln.ip_port }}</td>
            <td>{{ vuln.device_name }}</td>
            <td class="vulnerable">{{ vuln.path }}</td>
            <td>{{ vuln.protocol }}</td>
            <td>{{ vuln.status_code }}</td>
            <td>{{ "%.2f"|format(vuln.response_time) }}s</td>
            <td>{{ vuln.response_size }} bytes</td>
            <td>{{ vuln.timestamp }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>"""
    
    with open(os.path.join(TEMPLATES_DIR, "report_template.html"), "w", encoding="utf-8") as f:
        f.write(template_content)

def generate_html_report(vulns, stats, output_file):
    """Generate HTML report using Jinja2"""
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    template = env.get_template('report_template.html'))
    
    html_content = template.render(
        vulnerabilities=vulns,
        statistics=stats,
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

def generate_pdf_report(vulns, stats, output_file):
    """Generate PDF report from HTML"""
    html_file = output_file.replace(".pdf", ".html")
    generate_html_report(vulns, stats, html_file)
    
    options = {
        'encoding': 'UTF-8',
        'quiet': '',
        'footer-right': '[page] of [topage]',
        'orientation': 'Landscape'
    }
    
    try:
        pdfkit.from_file(html_file, output_file, options=options)
    except Exception as e:
        console.log(f"[red]PDF generation error: {str(e)}[/red]")
    finally:
        if os.path.exists(html_file):
            os.remove(html_file)

def generate_csv_report(vulns, output_file):
    """Generate CSV report"""
    with open(output_file, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "IP:Port", "Device", "Path", "Protocol", 
            "Status", "Response Time", "Size", "Timestamp"
        ])
        
        for vuln in vulns:
            writer.writerow([
                vuln['ip_port'], vuln['device_name'], vuln['path'],
                vuln['protocol'], vuln['status_code'], vuln['response_time'],
                vuln['response_size'], vuln['timestamp']
            ])

# -- IP Scanning --
async def scan_ip(conn, devices_db, client, ip, port, session_id):
    """Scan specific IP address"""
    console.log(f"[cyan]==> Scanning {ip}:{port}[/cyan]")
    
    # Try HTTP and HTTPS
    resp, _ = await request_url(client, "http", ip, port, "/")
    if resp is None or resp.status_code >= 400:
        resp, _ = await request_url(client, "https", ip, port, "/")

    if resp is None:
        console.log(f"[red]Failed to connect to {ip}:{port} (HTTP & HTTPS)[/red]")
        update_scan_session(conn, session_id, 1, 0)
        return

    # Detect device type
    device = detect_device_system(resp, devices_db)
    if device:
        console.log(f"[green]Detected device: {device}[/green]")
        paths = devices_db[device]["paths"]
    else:
        device = add_unknown_device(conn, devices_db, ip, resp)
        paths = devices_db[device]["paths"]

    found_vulns = 0
    
    # Scan all defined paths
    for path in paths:
        vulnerable, status, proto, resp_time, resp_size = await test_path(client, ip, port, path)
        if vulnerable:
            console.log(f"[bold green][+] Potential LFI at {ip}:{port}{path} | Status: {status} | Protocol: {proto.upper()} | Response: {resp_time:.2f}s | Size: {resp_size} bytes[/bold green]")
            save_scan_result(conn, ip, port, device, path, proto, status, resp_time, resp_size, True)
            found_vulns += 1
        else:
            console.log(f"[-] No vulnerability at path: {path}")

        await asyncio.sleep(config['rate_limit_delay'])  # Rate limiting

    # Update session statistics
    update_scan_session(conn, session_id, 1, 1 if found_vulns > 0 else 0)
    
    if found_vulns:
        console.log(f"[bold yellow]Logged {found_vulns} vulnerabilities for {ip}:{port}[/bold yellow]")
    else:
        console.log(f"[dim]No vulnerabilities found for {ip}:{port}[/dim]")

# -- IP Loading --
def validate_ip_port(ip_str, port):
    """Validate IP address and port"""
    try:
        ipaddress.ip_address(ip_str)
        if not (1 <= port <= 65535):
            raise ValueError("Port must be between 1 and 65535")
        return True
    except ValueError as e:
        logging.warning(f"Invalid address skipped: {ip_str}:{port} - {str(e)}")
        return False

def load_ips_from_file(filename):
    """Load IP addresses from file with validation"""
    valid_ips = []
    if not os.path.exists(filename):
        console.log(f"[red]IP file {filename} not found[/red]")
        return valid_ips
    
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):  # Skip empty lines and comments
                # Expected formats: IP or IP:Port
                if ':' in line:
                    ip_part, port_part = line.split(':', 1)
                    try:
                        port = int(port_part)
                        if validate_ip_port(ip_part, port):
                            valid_ips.append((ip_part, port))
                    except ValueError:
                        continue
                else:
                    if validate_ip_port(line, 80):  # Default port 80
                        valid_ips.append((line, 80))
    
    return valid_ips

# -- SSL Security Settings --
def create_ssl_context():
    """Create secure SSL context"""
    context = ssl.create_default_context()
    
    # Disable insecure protocols
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1
    
    # Enable strict certificate verification
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    
    # Load system trusted certificates
    context.load_default_certs()
    
    return context

async def create_http_client():
    """Create HTTP client with enhanced security"""
    ssl_context = create_ssl_context()
    
    limits = httpx.Limits(
        max_connections=config['concurrent_connections'],
        max_keepalive_connections=20
    )
    
    return httpx.AsyncClient(
        limits=limits,
        http2=True,
        verify=ssl_context,
        timeout=config['http_timeout'],
        follow_redirects=True,
        headers={
            "User-Agent": config['user_agents'][0]
        }
    )

# -- Main Function --
async def main():
    """Main scanning function"""
    # Load configuration
    if not config:
        console.log("[red]Cannot continue without valid config file[/red]")
        return
    
    # Initialize database
    conn = init_db()
    
    # Load known devices
    devices_db = load_devices_db(conn)
    
    # Load IP addresses
    ip_list = load_ips_from_file("ip.txt")
    if not ip_list:
        console.log("[red]No valid IPs to scan[/red]")
        return
    
    console.print(f"\n[bold magenta]Loaded {len(ip_list)} valid IP addresses[/bold magenta]")
    
    # Start scan session
    session_id = start_scan_session(conn, len(ip_list))
    
    # Create HTTP client
    async with await create_http_client() as client:
        tasks = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn()
        ) as progress:
            task = progress.add_task("[green]Scanning targets...", total=len(ip_list))
            
            for ip, port in ip_list:
                tasks.append(scan_ip(conn, devices_db, client, ip, port, session_id))
                
            for future in asyncio.as_completed(tasks):
                await future
                progress.update(task, advance=1)
    
    # End scan session
    end_scan_session(conn, session_id)
    
    # Generate reports
    generate_reports(conn)
    
    # Show summary
    stats = get_scan_statistics(conn)
    console.print(f"\n[bold]Scan Summary:[/bold]")
    console.print(f"- Targets scanned: {stats['total_scans']}")
    console.print(f"- Unique IPs: {stats['unique_ips']}")
    console.print(f"- Vulnerabilities found: [red]{stats['vulnerabilities']}[/red]")
    console.print(f"- Vulnerable IPs: [red]{stats['vulnerable_ips']}[/red]")

if __name__ == "__main__":
    # Disable unnecessary SSL warnings
    warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
    
    # Run the scanner
    asyncio.run(main())

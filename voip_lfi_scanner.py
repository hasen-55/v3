#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
# -- إعدادات التكوين --
CONFIG_FILE = "config.yaml"
DB_FILE = "voip_scanner.db"
RESULTS_FILE = "results.log"
REPORTS_DIR = "reports"
TEMPLATES_DIR = "templates"

# -- تحميل التكوين --
def load_config():
    """تحميل إعدادات التكوين من ملف YAML"""
    try:
        with open(CONFIG_FILE, "r") as f:
            config = yaml.safe_load(f)
            
        # القيم الافتراضية إذا لم يتم توفيرها في الملف
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
        print(f"خطأ في تحميل ملف التكوين: {str(e)}")
        return None

config = load_config()

if not config:
    print("لا يمكن المتابعة بدون ملف تكوين صالح")
    exit(1)

# -- إعداد التسجيل --
logging.basicConfig(
    filename=RESULTS_FILE,
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

console = Console()

# -- قاعدة بيانات SQLite --
def init_db():
    """تهيئة قاعدة البيانات"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # جدول الأجهزة المعروفة
    c.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            device_name TEXT PRIMARY KEY,
            user_agents TEXT,
            paths TEXT,
            fingerprints TEXT
        )
    ''')
    
    # جدول نتائج الفحص
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
    
    # جدول إحصائيات الفحص
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
    """تحميل بيانات الأجهزة من قاعدة البيانات"""
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
    """حفظ أو تحديث جهاز في قاعدة البيانات"""
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
    """حفظ نتيجة الفحص في قاعدة البيانات"""
    c = conn.cursor()
    c.execute('''
        INSERT INTO scan_results
        (ip, port, device_name, path, protocol, status_code, response_time, response_size, detected_lfi)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (ip, port, device_name, path, protocol, status_code, response_time, response_size, detected_lfi))
    conn.commit()

def start_scan_session(conn, total_ips):
    """بدء جلسة فحص جديدة وتسجيل وقت البدء"""
    c = conn.cursor()
    c.execute('''
        INSERT INTO scan_stats 
        (total_ips, scanned_ips, vulnerable_ips, start_time)
        VALUES (?, ?, ?, datetime('now'))
    ''', (total_ips, 0, 0))
    conn.commit()
    return c.lastrowid

def update_scan_session(conn, session_id, scanned_ips, vulnerable_ips):
    """تحديث إحصائيات جلسة الفحص"""
    c = conn.cursor()
    c.execute('''
        UPDATE scan_stats 
        SET scanned_ips = ?, vulnerable_ips = ?
        WHERE id = ?
    ''', (scanned_ips, vulnerable_ips, session_id))
    conn.commit()

def end_scan_session(conn, session_id):
    """إنهاء جلسة الفحص وتسجيل وقت الانتهاء"""
    c = conn.cursor()
    c.execute('''
        UPDATE scan_stats 
        SET end_time = datetime('now')
        WHERE id = ?
    ''', (session_id,))
    conn.commit()

# -- تحليل الاستجابة --
def analyze_response(resp: httpx.Response):
    """تحليل الاستجابة للكشف عن ثغرات LFI"""
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
    """استخراج أنماط مميزة من محتوى الصفحة"""
    patterns = []
    body_text = body_text.lower()
    
    # علامات HTML مميزة
    meta_generator = re.search(r'<meta name="generator" content="([^"]+)"', body_text)
    if meta_generator:
        patterns.append(f"meta_generator:{meta_generator.group(1)}")
    
    # نصوص حقوق الملكية
    copyright_match = re.search(r'copyright.*?(\d{4})', body_text)
    if copyright_match:
        patterns.append(f"copyright:{copyright_match.group(1)}")
    
    # نماذج تسجيل الدخول
    if any(x in body_text for x in ["login", "username", "password", "sign in"]):
        patterns.append("login_form")
    
    return patterns

def detect_device_system(resp: httpx.Response, devices_db):
    """كشف نوع الجهاز باستخدام بصمات متقدمة"""
    if resp is None:
        return None
    
    # جمع بصمة الجهاز من الاستجابة
    fingerprint = {
        'server': resp.headers.get("server", "").lower(),
        'x-powered-by': resp.headers.get("x-powered-by", "").lower(),
        'www-authenticate': resp.headers.get("www-authenticate", "").lower(),
        'set-cookie': resp.headers.get("set-cookie", "").lower(),
        'body_patterns': extract_body_patterns(resp.text)
    }
    
    # البحث في قاعدة البيانات عن تطابق البصمة
    for device, info in devices_db.items():
        for known_fingerprint in info.get("fingerprints", []):
            match_score = 0
            
            # مطابقة رؤوس HTTP
            for header in ['server', 'x-powered-by', 'www-authenticate', 'set-cookie']:
                if known_fingerprint.get(header) and known_fingerprint[header] in fingerprint[header]:
                    match_score += 1
            
            # مطابقة أنماط الجسم
            for pattern in known_fingerprint.get('body_patterns', []):
                if pattern in fingerprint['body_patterns']:
                    match_score += 1
                    
            # إذا تطابق أكثر من 3 عناصر، نعتبره مطابقًا
            if match_score >= 3:
                return device
    
    # محاولة الكشف باستخدام العوامل التقليدية إذا فشل الكشف بالبصمة
    combined_headers = (resp.headers.get("server", "") + " " + resp.headers.get("user-agent", "")).strip()
    for device, info in devices_db.items():
        for known_ua in info.get("user_agents", []):
            if known_ua.lower() in combined_headers.lower():
                return device
                
    return None

# -- طلب HTTP مع Retry --
@retry(wait=wait_fixed(2), stop=stop_after_attempt(3))
async def fetch_url(client, url):
    """إرسال طلب HTTP مع إعادة المحاولة عند الفشل"""
    start_time = time.monotonic()
    resp = await client.get(url, follow_redirects=True)
    resp.raise_for_status()
    elapsed = time.monotonic() - start_time
    return resp, elapsed

async def request_url(client, protocol, ip, port, path):
    """إرسال طلب HTTP/HTTPS"""
    url = f"{protocol}://{ip}:{port}{path}"
    try:
        resp, elapsed = await fetch_url(client, url)
        return resp, elapsed
    except (httpx.RequestError, httpx.HTTPStatusError) as e:
        logging.debug(f"فشل الطلب إلى {url}: {str(e)}")
        return None, None

async def test_path(client, ip, port, path):
    """اختبار مسار معين على HTTP و HTTPS"""
    # اختبار HTTP
    resp, elapsed = await request_url(client, "http", ip, port, path)
    if resp and analyze_response(resp):
        return True, resp.status_code, "http", elapsed, len(resp.content)

    # اختبار HTTPS
    resp, elapsed = await request_url(client, "https", ip, port, path)
    if resp and analyze_response(resp):
        return True, resp.status_code, "https", elapsed, len(resp.content)

    return False, None, None, None, None

# -- إدارة الأجهزة --
def add_unknown_device(conn, devices_db, ip, resp=None):
    """إضافة جهاز غير معروف إلى قاعدة البيانات"""
    device_name = f"Unknown_{ip.replace('.','_')}"
    
    if device_name in devices_db:
        return device_name
    
    console.log(f"[yellow]تم اكتشاف جهاز جديد: {device_name}[/yellow]")
    
    # المسارات الافتراضية للفحص
    default_paths = config.get('default_paths', [
        "/etc/passwd", 
        "/etc/shadow", 
        "/admin/config", 
        "/cgi-bin/", 
        "/etc/config.php"
    ])
    
    # بصمة الجهاز إذا توفرت استجابة
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

# -- تحميل وعرض النتائج --
def get_vulnerabilities(conn, limit=1000):
    """جلب قائمة الثغرات المكتشفة"""
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
    """جلب إحصائيات الفحص"""
    c = conn.cursor()
    
    # إحصائيات عامة
    c.execute('SELECT COUNT(*) FROM scan_results')
    total_scans = c.fetchone()[0]
    
    c.execute('SELECT COUNT(DISTINCT ip) FROM scan_results')
    unique_ips = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM scan_results WHERE detected_lfi = 1')
    vulnerabilities = c.fetchone()[0]
    
    c.execute('SELECT COUNT(DISTINCT ip) FROM scan_results WHERE detected_lfi = 1')
    vulnerable_ips = c.fetchone()[0]
    
    # الأجهزة الأكثر عرضة
    c.execute('''
        SELECT device_name, COUNT(*) as count 
        FROM scan_results 
        WHERE detected_lfi = 1
        GROUP BY device_name 
        ORDER BY count DESC 
        LIMIT 5
    ''')
    top_devices = [dict(zip(['device_name', 'count'], row)) for row in c.fetchall()]
    
    # المسارات الأكثر عرضة
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

# -- توليد التقارير --
def generate_reports(conn):
    """إنشاء تقارير متعددة التنسيقات"""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(TEMPLATES_DIR, exist_ok=True)
    
    # إنشاء نموذج HTML إذا لم يكن موجودًا
    if not os.path.exists(os.path.join(TEMPLATES_DIR, "report_template.html")):
        create_default_template()
    
    # جلب البيانات
    vulns = get_vulnerabilities(conn)
    stats = get_scan_statistics(conn)
    
    # إنشاء التقارير
    generate_html_report(vulns, stats, os.path.join(REPORTS_DIR, "report.html"))
    generate_pdf_report(vulns, stats, os.path.join(REPORTS_DIR, "report.pdf"))
    generate_csv_report(vulns, os.path.join(REPORTS_DIR, "report.csv"))
    
    console.log(f"[green]تم إنشاء التقارير في مجلد {REPORTS_DIR}[/green]")

def create_default_template():
    """إنشاء نموذج HTML افتراضي للتقرير"""
    template_content = """<!DOCTYPE html>
<html dir="rtl" lang="ar">
<head>
    <meta charset="UTF-8">
    <title>تقرير فحص ثغرات LFI</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #2c3e50; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { padding: 8px; text-align: right; border: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .vulnerable { color: red; font-weight: bold; }
        .summary { background-color: #f0f8ff; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>تقرير فحص ثغرات LFI</h1>
    <p>تاريخ التقرير: {{ scan_date }}</p>
    
    <div class="summary">
        <h2>ملخص النتائج</h2>
        <p>إجمالي العناوين المفحوصة: {{ statistics.total_scans }}</p>
        <p>عدد العناوين الفريدة: {{ statistics.unique_ips }}</p>
        <p>عدد الثغرات المكتشفة: <span class="vulnerable">{{ statistics.vulnerabilities }}</span></p>
        <p>عدد العناوين المعرضة: <span class="vulnerable">{{ statistics.vulnerable_ips }}</span></p>
    </div>
    
    <h2>أكثر الأجهزة عرضة</h2>
    <table>
        <tr>
            <th>اسم الجهاز</th>
            <th>عدد الثغرات</th>
        </tr>
        {% for device in statistics.top_devices %}
        <tr>
            <td>{{ device.device_name }}</td>
            <td>{{ device.count }}</td>
        </tr>
        {% endfor %}
    </table>
    
    <h2>أكثر المسارات عرضة</h2>
    <table>
        <tr>
            <th>المسار</th>
            <th>عدد الثغرات</th>
        </tr>
        {% for path in statistics.top_paths %}
        <tr>
            <td>{{ path.path }}</td>
            <td>{{ path.count }}</td>
        </tr>
        {% endfor %}
    </table>
    
    <h2>تفاصيل الثغرات</h2>
    <table>
        <tr>
            <th>العنوان</th>
            <th>الجهاز</th>
            <th>المسار</th>
            <th>البروتوكول</th>
            <th>الحالة</th>
            <th>وقت الاستجابة</th>
            <th>الحجم</th>
            <th>التاريخ</th>
        </tr>
        {% for vuln in vulnerabilities %}
        <tr>
            <td>{{ vuln.ip_port }}</td>
            <td>{{ vuln.device_name }}</td>
            <td class="vulnerable">{{ vuln.path }}</td>
            <td>{{ vuln.protocol }}</td>
            <td>{{ vuln.status_code }}</td>
            <td>{{ "%.2f"|format(vuln.response_time) }} ثانية</td>
            <td>{{ vuln.response_size }} بايت</td>
            <td>{{ vuln.timestamp }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>"""
    
    with open(os.path.join(TEMPLATES_DIR, "report_template.html"), "w", encoding="utf-8") as f:
        f.write(template_content)

def generate_html_report(vulns, stats, output_file):
    """إنشاء تقرير HTML باستخدام Jinja2"""
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    template = env.get_template('report_template.html')
    
    html_content = template.render(
        vulnerabilities=vulns,
        statistics=stats,
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

def generate_pdf_report(vulns, stats, output_file):
    """إنشاء تقرير PDF من HTML"""
    html_file = output_file.replace(".pdf", ".html")
    generate_html_report(vulns, stats, html_file)
    
    options = {
        'encoding': 'UTF-8',
        'quiet': '',
        'footer-right': '[page] من [topage]',
        'orientation': 'Landscape'
    }
    
    try:
        pdfkit.from_file(html_file, output_file, options=options)
    except Exception as e:
        console.log(f"[red]خطأ في إنشاء PDF: {str(e)}[/red]")
    finally:
        if os.path.exists(html_file):
            os.remove(html_file)

def generate_csv_report(vulns, output_file):
    """إنشاء تقرير CSV"""
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

# -- فحص IP --
async def scan_ip(conn, devices_db, client, ip, port, session_id):
    """فحص عنوان IP معين"""
    console.log(f"[cyan]==> جاري فحص {ip}:{port}[/cyan]")
    
    # محاولة الاتصال عبر HTTP و HTTPS
    resp, _ = await request_url(client, "http", ip, port, "/")
    if resp is None or resp.status_code >= 400:
        resp, _ = await request_url(client, "https", ip, port, "/")

    if resp is None:
        console.log(f"[red]فشل الاتصال بـ {ip}:{port} (HTTP و HTTPS)[/red]")
        update_scan_session(conn, session_id, 1, 0)
        return

    # كشف نوع الجهاز
    device = detect_device_system(resp, devices_db)
    if device:
        console.log(f"[green]تم اكتشاف الجهاز: {device}[/green]")
        paths = devices_db[device]["paths"]
    else:
        device = add_unknown_device(conn, devices_db, ip, resp)
        paths = devices_db[device]["paths"]

    found_vulns = 0
    
    # فحص جميع المسارات المعرفة
    for path in paths:
        vulnerable, status, proto, resp_time, resp_size = await test_path(client, ip, port, path)
        if vulnerable:
            console.log(f"[bold green][+] ثغرة LFI محتملة في {ip}:{port}{path} | الحالة: {status} | البروتوكول: {proto.upper()} | وقت الاستجابة: {resp_time:.2f} ثانية | الحجم: {resp_size} بايت[/bold green]")
            save_scan_result(conn, ip, port, device, path, proto, status, resp_time, resp_size, True)
            found_vulns += 1
        else:
            console.log(f"[-] لا توجد ثغرة في المسار: {path}")

        await asyncio.sleep(config['rate_limit_delay'])  # تجنب الحظر

    # تحديث إحصائيات الجلسة
    update_scan_session(conn, session_id, 1, 1 if found_vulns > 0 else 0)
    
    if found_vulns:
        console.log(f"[bold yellow]تم تسجيل {found_vulns} ثغرة لـ {ip}:{port}[/bold yellow]")
    else:
        console.log(f"[dim]لا توجد ثغرات في {ip}:{port}[/dim]")

# -- تحميل عناوين IP --
def validate_ip_port(ip_str, port):
    """التحقق من صحة عنوان IP ومنفذ"""
    try:
        ipaddress.ip_address(ip_str)
        if not (1 <= port <= 65535):
            raise ValueError("المنفذ يجب أن يكون بين 1 و 65535")
        return True
    except ValueError as e:
        logging.warning(f"عنوان غير صالح تم تجاهله: {ip_str}:{port} - {str(e)}")
        return False

def load_ips_from_file(filename):
    """تحميل عناوين IP من ملف مع التحقق من صحتها"""
    valid_ips = []
    if not os.path.exists(filename):
        console.log(f"[red]ملف العناوين {filename} غير موجود[/red]")
        return valid_ips
    
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):  # تجاهل الأسطر الفارغة والتعليقات
                # تنسيقات متوقعة: IP أو IP:Port
                if ':' in line:
                    ip_part, port_part = line.split(':', 1)
                    try:
                        port = int(port_part)
                        if validate_ip_port(ip_part, port):
                            valid_ips.append((ip_part, port))
                    except ValueError:
                        continue
                else:
                    if validate_ip_port(line, 80):  # المنفذ الافتراضي 80
                        valid_ips.append((line, 80))
    
    return valid_ips

# -- إعدادات SSL الآمنة --
def create_ssl_context():
    """إنشاء سياق SSL آمن"""
    context = ssl.create_default_context()
    
    # تعطيل البروتوكولات غير الآمنة
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1
    
    # تفعيل تحقق صارم من الشهادة
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    
    # تحميل شهادات موثوقة من النظام
    context.load_default_certs()
    
    return context

async def create_http_client():
    """إنشاء عميل HTTP مع خيارات أمان محسنة"""
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

# -- الوظيفة الرئيسية --
async def main():
    """الدالة الرئيسية لتشغيل الفحص"""
    # تحميل التكوين
    if not config:
        console.log("[red]لا يمكن المتابعة بدون ملف تكوين صالح[/red]")
        return
    
    # تهيئة قاعدة البيانات
    conn = init_db()
    
    # تحميل الأجهزة المعروفة
    devices_db = load_devices_db(conn)
    
    # تحميل عناوين IP
    ip_list = load_ips_from_file("ip.txt")
    if not ip_list:
        console.log("[red]لا توجد عناوين IP صالحة للمسح[/red]")
        return
    
    console.print(f"\n[bold magenta]تم تحميل {len(ip_list)} عنوان IP صالح[/bold magenta]")
    
    # بدء جلسة الفحص
    session_id = start_scan_session(conn, len(ip_list))
    
    # إنشاء عميل HTTP
    async with await create_http_client() as client:
        tasks = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn()
        ) as progress:
            task = progress.add_task("[green]جاري فحص العناوين...", total=len(ip_list))
            
            for ip, port in ip_list:
                tasks.append(scan_ip(conn, devices_db, client, ip, port, session_id))
                
            for future in asyncio.as_completed(tasks):
                await future
                progress.update(task, advance=1)
    
    # إنهاء جلسة الفحص
    end_scan_session(conn, session_id)
    
    # إنشاء التقارير
    generate_reports(conn)
    
    # عرض ملخص النتائج
    stats = get_scan_statistics(conn)
    console.print(f"\n[bold]ملخص النتائج:[/bold]")
    console.print(f"- العناوين المفحوصة: {stats['total_scans']}")
    console.print(f"- العناوين الفريدة: {stats['unique_ips']}")
    console.print(f"- الثغرات المكتشفة: [red]{stats['vulnerabilities']}[/red]")
    console.print(f"- العناوين المعرضة: [red]{stats['vulnerable_ips']}[/red]")

if __name__ == "__main__":
    # تعطيل تحذيرات SSL غير الضرورية
    warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
    
    # تشغيل الأداة
    asyncio.run(main())
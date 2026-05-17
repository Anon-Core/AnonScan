# scanner.py
import socket
import ssl
import re
import json
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin, urlunparse
from html.parser import HTMLParser
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import dns.resolver
import base64

class AnonScanner:
    def __init__(self, target, shodan_key="", censys_id="", censys_secret="", 
                 log_callback=None, progress_callback=None, status_callback=None,
                 enabled_modules=None):
        self.target = self.normalize_target(target)
        self.domain = self.extract_domain(self.target)
        self.shodan_key = shodan_key
        self.censys_id = censys_id
        self.censys_secret = censys_secret
        self.log = log_callback or print
        self.update_progress = progress_callback or (lambda x: None)
        self.update_status = status_callback or (lambda x: None)
        self.enabled_modules = enabled_modules or {}
        
        self.session = self.create_session()
        self.results = {}
        
    def normalize_target(self, target):
        target = target.strip()
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        return target
    
    def extract_domain(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        domain = domain.split(':')[0]
        return domain
    
    def create_session(self):
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        return session
    
    def run_scan(self):
        self.log("[INFO] Starting scan...")
        self.update_status("Initializing scan")
        
        total_modules = sum(1 for v in self.enabled_modules.values() if v)
        current = 0
        
        # Basic info
        self.update_status("Resolving target")
        self.results['basic'] = self.get_basic_info()
        current += 1
        self.update_progress(int(current / total_modules * 100))
        
        # Subdomains
        if self.enabled_modules.get('subdomains', True):
            self.update_status("Enumerating subdomains")
            self.results['subdomains'] = self.enumerate_subdomains()
            current += 1
            self.update_progress(int(current / total_modules * 100))
        
        # DNS
        if self.enabled_modules.get('dns', True):
            self.update_status("Querying DNS records")
            self.results['dns'] = self.query_dns()
            current += 1
            self.update_progress(int(current / total_modules * 100))
        
        # Shodan/Censys
        if self.enabled_modules.get('shodan_censys', True):
            self.update_status("Querying Shodan/Censys")
            self.results['shodan'] = self.query_shodan()
            self.results['censys'] = self.query_censys()
            current += 1
            self.update_progress(int(current / total_modules * 100))
        
        # Web tech
        if self.enabled_modules.get('web_tech', True):
            self.update_status("Detecting web technologies")
            self.results['web_tech'] = self.detect_web_tech()
            current += 1
            self.update_progress(int(current / total_modules * 100))
        
        # HTTP probe
        if self.enabled_modules.get('http_probe', True):
            self.update_status("Probing HTTP/HTTPS")
            self.results['http_probe'] = self.http_probe()
            current += 1
            self.update_progress(int(current / total_modules * 100))
        
        # Wayback
        if self.enabled_modules.get('wayback', True):
            self.update_status("Fetching historical URLs")
            self.results['wayback'] = self.get_wayback_urls()
            current += 1
            self.update_progress(int(current / total_modules * 100))
        
        # Crawler
        if self.enabled_modules.get('crawler', True):
            self.update_status("Crawling target")
            self.results['crawler'] = self.crawl_target()
            current += 1
            self.update_progress(int(current / total_modules * 100))
        
        # Port scan
        if self.enabled_modules.get('port_scan', True):
            self.update_status("Scanning ports")
            self.results['ports'] = self.scan_ports()
            current += 1
            self.update_progress(int(current / total_modules * 100))
        
        # SSL info
        if self.enabled_modules.get('ssl_info', True):
            self.update_status("Analyzing SSL/TLS")
            self.results['ssl'] = self.get_ssl_info()
            current += 1
            self.update_progress(int(current / total_modules * 100))
        
        # Email OSINT
        if self.enabled_modules.get('email_osint', True):
            self.update_status("Extracting emails")
            self.results['emails'] = self.extract_emails()
            current += 1
            self.update_progress(int(current / total_modules * 100))
        
        self.log("[INFO] Scan complete")
        return self.results
    
    def get_basic_info(self):
        self.log("[INFO] Resolving target IP addresses")
        ips = []
        try:
            answers = socket.getaddrinfo(self.domain, None)
            ips = list(set([ans[4][0] for ans in answers]))
            self.log(f"[SUCCESS] Resolved IPs: {', '.join(ips)}")
        except Exception as e:
            self.log(f"[ERROR] Failed to resolve domain: {str(e)}")
        
        return {
            'target': self.target,
            'domain': self.domain,
            'ips': ips,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def enumerate_subdomains(self):
        self.log("[INFO] Starting subdomain enumeration")
        subdomains = set()
        
        # crt.sh
        try:
            self.log("[INFO] Querying crt.sh")
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub and self.domain in sub:
                            subdomains.add(sub)
                self.log(f"[SUCCESS] crt.sh found {len(subdomains)} subdomains")
        except Exception as e:
            self.log(f"[ERROR] crt.sh query failed: {str(e)}")
        
        # HackerTarget
        try:
            self.log("[INFO] Querying HackerTarget")
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                for line in resp.text.split('\n'):
                    if ',' in line:
                        sub = line.split(',')[0].strip().lower()
                        if sub and self.domain in sub:
                            subdomains.add(sub)
                self.log(f"[SUCCESS] HackerTarget added subdomains")
        except Exception as e:
            self.log(f"[ERROR] HackerTarget query failed: {str(e)}")
        
        # ThreatCrowd
        try:
            self.log("[INFO] Querying ThreatCrowd")
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                subs = data.get('subdomains', [])
                for sub in subs:
                    subdomains.add(sub.lower())
                self.log(f"[SUCCESS] ThreatCrowd added subdomains")
        except Exception as e:
            self.log(f"[ERROR] ThreatCrowd query failed: {str(e)}")
        
        result = sorted(list(subdomains))
        self.log(f"[SUCCESS] Total unique subdomains: {len(result)}")
        return result
    
    def query_dns(self):
        self.log("[INFO] Querying DNS records")
        records = {}
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
                self.log(f"[SUCCESS] {rtype} records: {len(records[rtype])}")
            except dns.resolver.NoAnswer:
                records[rtype] = []
            except dns.resolver.NXDOMAIN:
                self.log(f"[ERROR] Domain does not exist")
                records[rtype] = []
            except Exception as e:
                self.log(f"[ERROR] {rtype} query failed: {str(e)}")
                records[rtype] = []
        
        return records
    
    def query_shodan(self):
        if not self.shodan_key:
            self.log("[WARN] Shodan API key not provided, skipping")
            return {'error': 'No API key'}
        
        self.log("[INFO] Querying Shodan")
        ips = self.results.get('basic', {}).get('ips', [])
        if not ips:
            return {'error': 'No IPs to query'}
        
        results = []
        for ip in ips[:3]:
            try:
                url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}"
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    results.append({
                        'ip': ip,
                        'ports': data.get('ports', []),
                        'vulns': list(data.get('vulns', {}).keys()),
                        'org': data.get('org', 'N/A'),
                        'os': data.get('os', 'N/A')
                    })
                    self.log(f"[SUCCESS] Shodan data for {ip}")
            except Exception as e:
                self.log(f"[ERROR] Shodan query for {ip} failed: {str(e)}")
        
        return results
    
    def query_censys(self):
        if not self.censys_id or not self.censys_secret:
            self.log("[WARN] Censys credentials not provided, skipping")
            return {'error': 'No credentials'}
        
        self.log("[INFO] Querying Censys")
        ips = self.results.get('basic', {}).get('ips', [])
        if not ips:
            return {'error': 'No IPs to query'}
        
        results = []
        auth = (self.censys_id, self.censys_secret)
        
        for ip in ips[:3]:
            try:
                url = f"https://search.censys.io/api/v2/hosts/{ip}"
                resp = self.session.get(url, auth=auth, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    results.append({
                        'ip': ip,
                        'services': data.get('result', {}).get('services', []),
                        'autonomous_system': data.get('result', {}).get('autonomous_system', {})
                    })
                    self.log(f"[SUCCESS] Censys data for {ip}")
            except Exception as e:
                self.log(f"[ERROR] Censys query for {ip} failed: {str(e)}")
        
        return results
    
    def detect_web_tech(self):
        self.log("[INFO] Detecting web technologies")
        tech = []
        
        try:
            resp = self.session.get(self.target, timeout=10, allow_redirects=True)
            headers = resp.headers
            html = resp.text.lower()
            
            # Server header
            if 'server' in headers:
                tech.append(f"Server: {headers['server']}")
            
# scanner.py  (continued)
            # X-Powered-By
            if 'x-powered-by' in headers:
                tech.append(f"X-Powered-By: {headers['x-powered-by']}")
            
            # Simple fingerprinting
            fingerprints = {
                'WordPress': ['wp-content', 'wp-includes'],
                'Drupal': ['drupal.settings', 'sites/all/modules'],
                'Joomla': ['content="Joomla!', 'Joomla!'],
                'Laravel': ['laravel_session'],
                'Django': ['csrftoken', 'django'],
                'React': ['react-dom', 'react.production.min.js'],
                'Angular': ['angular.min.js', 'ng-app'],
                'Vue.js': ['vue.js', 'vue.runtime.min.js'],
                'jQuery': ['jquery.min.js', 'jquery.js'],
                'Google Analytics': ['www.google-analytics.com/analytics.js', 'gtag('],
                'Cloudflare': ['cloudflare-ray', '__cfduid'],
                'Next.js': ['_next/static', 'next-data'],
            }
            
            for name, patterns in fingerprints.items():
                if any(pat.lower() in html for pat in patterns):
                    tech.append(name)
            
            tech = sorted(set(tech))
            self.log(f"[SUCCESS] Detected technologies: {', '.join(tech) if tech else 'None'}")
            return {'technologies': tech, 'headers': dict(headers)}
        except Exception as e:
            self.log(f"[ERROR] Web technology detection failed: {str(e)}")
            return {'technologies': [], 'headers': {}}
    
    def http_probe(self):
        self.log("[INFO] Probing HTTP/HTTPS endpoints")
        results = []
        schemes = ['http', 'https']
        parsed = urlparse(self.target)
        host = parsed.netloc or parsed.path
        
        for scheme in schemes:
            url = urlunparse((scheme, host, '', '', '', ''))
            try:
                t0 = time.time()
                resp = self.session.get(url, timeout=10, allow_redirects=True)
                t1 = time.time()
                chain = [r.url for r in resp.history] + [resp.url]
                info = {
                    'scheme': scheme,
                    'url': url,
                    'final_url': resp.url,
                    'status_code': resp.status_code,
                    'redirect_chain': chain,
                    'response_time_ms': int((t1 - t0) * 1000),
                    'headers': dict(resp.headers),
                }
                # SSL info for HTTPS
                if scheme == 'https':
                    try:
                        ssl_info = self.get_ssl_info()
                        info['ssl'] = ssl_info
                    except Exception:
                        info['ssl'] = {}
                results.append(info)
                self.log(f"[SUCCESS] {scheme.upper()} {resp.status_code} {resp.url} in {info['response_time_ms']} ms")
            except Exception as e:
                self.log(f"[ERROR] HTTP probe for {url} failed: {str(e)}")
        return results
    
    def get_wayback_urls(self, limit=500):
        self.log("[INFO] Querying Wayback Machine for historical URLs")
        urls = set()
        try:
            api = f"http://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=json&fl=original&collapse=urlkey"
            resp = self.session.get(api, timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                for row in data[1:]:  # first row is header
                    if not row:
                        continue
                    u = row[0]
                    urls.add(u)
                    if len(urls) >= limit:
                        break
                self.log(f"[SUCCESS] Retrieved {len(urls)} historical URLs")
            else:
                self.log(f"[WARN] Wayback returned status {resp.status_code}")
        except Exception as e:
            self.log(f"[ERROR] Wayback query failed: {str(e)}")
        return sorted(urls)
    
    class _SimpleHTMLLinkParser(HTMLParser):
        def __init__(self, base_url):
            super().__init__()
            self.base_url = base_url
            self.links = set()
        
        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == 'a' and 'href' in attrs:
                self.add_url(attrs['href'])
            elif tag == 'script' and 'src' in attrs:
                self.add_url(attrs['src'])
            elif tag == 'link' and 'href' in attrs:
                self.add_url(attrs['href'])
        
        def add_url(self, url):
            if url.startswith('javascript:') or url.startswith('mailto:'):
                return
            full = urljoin(self.base_url, url)
            if full.startswith('http://') or full.startswith('https://'):
                self.links.add(full)
    
    def crawl_target(self, max_pages=20, depth=1):
        self.log("[INFO] Crawling target (hakrawler-like)")
        visited = set()
        to_visit = [(self.target, 0)]
        discovered = set()
        
        while to_visit and len(visited) < max_pages:
            url, d = to_visit.pop(0)
            if url in visited or d > depth:
                continue
            visited.add(url)
            try:
                resp = self.session.get(url, timeout=10)
                parser = self._SimpleHTMLLinkParser(url)
                parser.feed(resp.text)
                for link in parser.links:
                    if link not in discovered:
                        discovered.add(link)
                        if d + 1 <= depth:
                            to_visit.append((link, d + 1))
                self.log(f"[INFO] Crawled {url}, found {len(parser.links)} links")
            except Exception as e:
                self.log(f"[ERROR] Crawl failed for {url}: {str(e)}")
        
        self.log(f"[SUCCESS] Crawler discovered {len(discovered)} URLs")
        return sorted(discovered)
    
    def scan_ports(self):
        self.log("[INFO] Performing TCP port scan (nmap-like fast scan)")
        ips = self.results.get('basic', {}).get('ips', [])
        if not ips:
            self.log("[WARN] No IPs for port scan")
            return {}
        
        common_ports = [
            21, 22, 25, 53, 80, 110, 143,
            443, 3306, 3389, 8080, 8443, 6379, 5900
        ]
        timeout = 0.5
        scan_result = {}
        
        for ip in ips:
            ip_results = {}
            for port in common_ports:
                status = 'filtered'
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    res = sock.connect_ex((ip, port))
                    if res == 0:
                        status = 'open'
                    else:
                        status = 'closed'
                    sock.close()
                except socket.timeout:
                    status = 'filtered'
                except Exception:
                    status = 'filtered'
                ip_results[port] = status
            scan_result[ip] = ip_results
            self.log(f"[INFO] Port scan for {ip} completed")
        
        return scan_result
    
    def get_ssl_info(self):
        self.log("[INFO] Gathering SSL/TLS certificate info")
        info = {}
        try:
            ctx = ssl.create_default_context()
            conn = ctx.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=self.domain,
            )
            conn.settimeout(5.0)
            conn.connect((self.domain, 443))
            cert = conn.getpeercert()
            cipher = conn.cipher()
            protocol_version = conn.version()
            conn.close()
            
            not_before = cert.get('notBefore')
            not_after = cert.get('notAfter')
            # ssl date format: 'Jun  1 12:00:00 2024 GMT'
            def parse_dt(s):
                return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")
            
            valid_from = parse_dt(not_before) if not_before else None
            valid_to = parse_dt(not_after) if not_after else None
            
            now = datetime.utcnow()
            expired = valid_to is not None and valid_to < now
            expiring_soon = valid_to is not None and valid_to < now + timedelta(days=30)
            
            info = {
                'subject': dict(x[0] for x in cert.get('subject', [])),
                'issuer': dict(x[0] for x in cert.get('issuer', [])),
                'valid_from': valid_from.isoformat() if valid_from else None,
                'valid_to': valid_to.isoformat() if valid_to else None,
                'protocol': protocol_version,
                'cipher': cipher[0] if cipher else None,
                'expired': expired,
                'expiring_soon': expiring_soon,
            }
            self.log("[SUCCESS] Retrieved SSL certificate info")
        except Exception as e:
            self.log(f"[ERROR] SSL info retrieval failed: {str(e)}")
        return info
    
    def extract_emails(self, max_pages=30):
        self.log("[INFO] Extracting emails (theHarvester-like)")
        emails = set()
        sources = []
        
        # main page
        sources.append(self.target)
        # few crawled URLs
        for url in self.results.get('crawler', [])[:10]:
            sources.append(url)
        # few wayback URLs
        for url in self.results.get('wayback', [])[:10]:
            sources.append(url)
        
        email_regex = re.compile(r'[a-zA-Z0-9.\-_+%]+@' + re.escape(self.domain), re.IGNORECASE)
        
        checked = 0
        for url in sources:
            if checked >= max_pages:
                break
            checked += 1
            try:
                resp = self.session.get(url, timeout=8)
                found = email_regex.findall(resp.text)
                for e in found:
                    emails.add(e.lower())
                if found:
                    self.log(f"[INFO] Found {len(found)} emails in {url}")
            except Exception:
                continue
        
        self.log(f"[SUCCESS] Total unique emails: {len(emails)}")
        return sorted(emails)
    
    def generate_summary(self, results):
        lines = []
        b = results.get('basic', {})
        lines.append(f"Target: {b.get('target', '')}")
        lines.append(f"Domain: {b.get('domain', '')}")
        lines.append(f"Resolved IPs: {', '.join(b.get('ips', [])) or 'None'}")
        lines.append(f"Timestamp: {b.get('timestamp', '')}")
        lines.append("")
        
        subs = results.get('subdomains', [])
        lines.append(f"Subdomains found: {len(subs)}")
        
        dns_info = results.get('dns', {})
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            recs = dns_info.get(rtype, [])
            lines.append(f"{rtype} records: {len(recs)}")
        
        ports = results.get('ports', {})
        for ip, pres in ports.items():
            open_ports = [str(p) for p, st in pres.items() if st == 'open']
            lines.append(f"{ip} - Open ports: {', '.join(open_ports) if open_ports else 'None'}")
        
        tech = results.get('web_tech', {}).get('technologies', [])
        lines.append(f"Detected technologies: {', '.join(tech) if tech else 'None'}")
        
        emails = results.get('emails', [])
        lines.append(f"Emails discovered: {len(emails)}")
        
        if not self.shodan_key:
            lines.append("Shodan: skipped (no API key)")
        if not self.censys_id or not self.censys_secret:
            lines.append("Censys: skipped (no credentials)")
        
        return "\n".join(lines)
    
    def generate_html_report(self, results):
        self.log("[INFO] Generating HTML report")
        basic = results.get('basic', {})
        subs = results.get('subdomains', [])
        dns_info = results.get('dns', {})
        shodan = results.get('shodan', {})
        censys = results.get('censys', {})
        web_tech = results.get('web_tech', {})
        http_probe = results.get('http_probe', [])
        wayback = results.get('wayback', [])
        crawler = results.get('crawler', [])
        ports = results.get('ports', {})
        ssl_info = results.get('ssl', {})
        emails = results.get('emails', [])
        
        # embed logo via base64 if possible
        logo_b64 = ""
        try:
            with open("Logo.png", "rb") as f:
                logo_b64 = base64.b64encode(f.read()).decode("ascii")
        except Exception:
            pass
        
        def esc(s):
            return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html lang='en'>")
        html.append("<head>")
        html.append("<meta charset='UTF-8'>")
        html.append("<meta name='viewport' content='width=device-width, initial-scale=1.0'>")
        html.append("<title>Anon Scan Report</title>")
        html.append("""
<style>
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background-color: #f4f4f4;
    color: #222;
    margin: 0;
    padding: 0;
}
.header {
    background-color: #930000;
    color: #ffffff;
    padding: 20px;
    display: flex;
    align-items: center;
}
.header img {
    height: 60px;
    margin-right: 20px;
}
.header .title-block {
    display: flex;
    flex-direction: column;
}
.header h1 {
    margin: 0;
    font-size: 28px;
}
.header .meta {
    font-size: 12px;
    opacity: 0.9;
}
.container {
    padding: 20px;
}
.section {
    background-color: #ffffff;
    border-radius: 8px;
    margin-bottom: 20px;
    padding: 15px 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.08);
}
.section h2 {
    border-bottom: 2px solid #930000;
    padding-bottom: 5px;
    margin-top: 0;
    color: #930000;
}
.section h3 {
    margin-bottom: 5px;
}
.badge {
    display: inline-block;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 11px;
    color: #fff;
    background-color: #930000;
}
table {
    border-collapse: collapse;
    width: 100%;
    font-size: 13px;
}
th, td {
    border-bottom: 1px solid #ddd;
    padding: 6px 4px;
    text-align: left;
}
th {
    background-color: #f0f0f0;
}
.code {
    font-family: "Consolas", "Fira Code", monospace;
    background-color: #222;
    color: #eee;
    padding: 10px;
    border-radius: 5px;
    overflow-x: auto;
    font-size: 12px;
}
.tag {
    display: inline-block;
    margin: 2px 4px 2px 0;
    padding: 2px 6px;
    border-radius: 4px;
    background-color: #eee;
    font-size: 11px;
}
.status-open {
    color: #0c7c0c;
    font-weight: bold;
}
.status-closed {
    color: #b00000;
}
.status-filtered {
    color: #666;
    font-style: italic;
}
.warning {
    color: #b00000;
    font-weight: bold;
}
.small {
    font-size: 12px;
}
</style>
        """)
        html.append("</head>")
        html.append("<body>")
        
        # Header
        html.append("<div class='header'>")
        if logo_b64:
            html.append(f"<img src='data:image/png;base64,{logo_b64}' alt='Logo'>")
        html.append("<div class='title-block'>")
        html.append("<h1>Anon Scan</h1>")
        html.append("<div class='meta'>")
        html.append(f"Target: {esc(basic.get('target', ''))} | ")
        html.append(f"Domain: {esc(basic.get('domain', ''))} | ")
        html.append(f"Timestamp: {esc(basic.get('timestamp', ''))}")
        html.append("</div></div></div>")
        
        html.append("<div class='container'>")
        
        # 1. Basic Target Info
        html.append("<div class='section'>")
        html.append("<h2>1. Basic Target Info</h2>")
        html.append("<p><strong>Input:</strong> " + esc(basic.get('target', '')) + "</p>")
        html.append("<p><strong>Domain:</strong> " + esc(basic.get('domain', '')) + "</p>")
        ips = basic.get('ips', [])
        if ips:
            html.append("<p><strong>Resolved IPs:</strong> " + ", ".join(esc(ip) for ip in ips) + "</p>")
        else:
            html.append("<p><strong>Resolved IPs:</strong> None</p>")
        html.append("</div>")
        
        # 2. Subdomains
        html.append("<div class='section'>")
        html.append("<h2>2. Subdomains</h2>")
        if subs:
            html.append(f"<p>Discovered {len(subs)} subdomains.</p>")
            html.append("<div class='code'>")
            html.append("<br>".join(esc(s) for s in subs))
            html.append("</div>")
        else:
            html.append("<p>No subdomains discovered.</p>")
        html.append("<p class='small'>Sources: crt.sh, ThreatCrowd, HackerTarget (Amass/Subfinder-like aggregation)</p>")
        html.append("</div>")
        
        # 3. DNS Info
        html.append("<div class='section'>")
        html.append("<h2>3. DNS Info</h2>")
        html.append("<table><tr><th>Type</th><th>Records</th></tr>")
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            recs = dns_info.get(rtype, [])
            html.append("<tr><td>" + rtype + "</td><td>")
            if recs:
                html.append("<br>".join(esc(r) for r in recs))
            else:
                html.append("<span class='small'>None</span>")
            html.append("</td></tr>")
        html.append("</table>")
        html.append("</div>")
        
        # 4. Shodan and Censys
        html.append("<div class='section'>")
        html.append("<h2>4. Shodan and Censys Summary</h2>")
        if isinstance(shodan, dict) and shodan.get('error'):
            html.append(f"<p>Shodan: <span class='warning'>{esc(shodan['error'])}</span></p>")
        else:
            if shodan:
                html.append("<h3>Shodan</h3>")
                for host in shodan:
                    html.append("<p><strong>IP:</strong> " + esc(host.get('ip', '')) + "</p>")
                    html.append("<p><strong>Ports:</strong> " + ", ".join(str(p) for p in host.get('ports', [])) + "</p>")
                    vulns = host.get('vulns', [])
                    if vulns:
                        html.append("<p><strong>Vulns:</strong> " + ", ".join(esc(v) for v in vulns) + "</p>")
                    html.append("<p><strong>Org:</strong> " + esc(host.get('org', 'N/A')) + 
                                " | <strong>OS:</strong> " + esc(host.get('os', 'N/A')) + "</p><hr>")
            else:
                html.append("<p>Shodan: No data or not executed.</p>")
        
        if isinstance(censys, dict) and censys.get('error'):
            html.append(f"<p>Censys: <span class='warning'>{esc(censys['error'])}</span></p>")
        else:
            if censys:
                html.append("<h3>Censys</h3>")
                for host in censys:
                    html.append("<p><strong>IP:</strong> " + esc(host.get('ip', '')) + "</p>")
                    services = host.get('services', [])
                    if services:
                        html.append("<p><strong>Services:</strong></p><ul>")
                        for s in services[:10]:
                            port = s.get('port')
                            proto = s.get('transport_protocol', '')
                            service_name = s.get('service_name', '')
                            html.append(f"<li>{port}/{esc(proto)} - {esc(service_name)}</li>")
                        if len(services) > 10:
                            html.append("<li>...</li>")
                        html.append("</ul>")
                    html.append("<hr>")
            else:
                html.append("<p>Censys: No data or not executed.</p>")
        html.append("</div>")
        
        # 5. Web Technologies
        html.append("<div class='section'>")
        html.append("<h2>5. Web Technologies</h2>")
        techs = web_tech.get('technologies', [])
        if techs:
            html.append("<p>Detected technologies:</p>")
            for t in techs:
                html.append(f"<span class='tag'>{esc(t)}</span>")
        else:
            html.append("<p>No specific technologies identified.</p>")
        html.append("</div>")
        
        # 6. HTTP Probing
        html.append("<div class='section'>")
        html.append("<h2>6. HTTP Probing (httpx-like)</h2>")
        if http_probe:
            for entry in http_probe:
                html.append(f"<h3>{entry['scheme'].upper()} - {esc(entry.get('url',''))}</h3>")
                html.append("<p>Status: " + str(entry.get('status_code', 'N/A')) +
                            f" | Time: {entry.get('response_time_ms', 0)} ms</p>")
                html.append("<p><strong>Final URL:</strong> " + esc(entry.get('final_url', '')) + "</p>")
                chain = entry.get('redirect_chain', [])
                if chain and len(chain) > 1:
                    html.append("<p><strong>Redirect Chain:</strong></p><ol>")
                    for u in chain:
                        html.append("<li>" + esc(u) + "</li>")
                    html.append("</ol>")
        else:
            html.append("<p>No HTTP probe data.</p>")
        html.append("</div>")
        
        # 7. Historical URLs
        html.append("<div class='section'>")
        html.append("<h2>7. Historical URLs (Wayback Machine)</h2>")
        if wayback:
            html.append(f"<p>Showing {len(wayback)} URLs (Wayback Machine).</p>")
            html.append("<div class='code'>")
            html.append("<br>".join(esc(u) for u in wayback))
            html.append("</div>")
        else:
            html.append("<p>No historical URLs found or API unavailable.</p>")
        html.append("</div>")
        
        # 8. Crawled URLs
        html.append("<div class='section'>")
        html.append("<h2>8. Crawled URLs (hakrawler-like)</h2>")
        if crawler:
            html.append(f"<p>Discovered {len(crawler)} URLs from crawling.</p>")
            html.append("<div class='code'>")
            html.append("<br>".join(esc(u) for u in crawler))
            html.append("</div>")
        else:
            html.append("<p>No URLs discovered during crawling.</p>")
        html.append("</div>")
        
        # 9. Open Ports
        html.append("<div class='section'>")
        html.append("<h2>9. Open Ports (Fast Scan)</h2>")
        if ports:
            for ip, pres in ports.items():
                html.append(f"<h3>{esc(ip)}</h3>")
                html.append("<table><tr><th>Port</th><th>Status</th></tr>")
                for port, status in sorted(pres.items()):
                    cls = f"status-{status}"
                    html.append(f"<tr><td>{port}</td><td class='{cls}'>{status}</td></tr>")
                html.append("</table>")
        else:
            html.append("<p>No port scan data.</p>")
        html.append("</div>")
        
        # 10. SSL/TLS details
        html.append("<div class='section'>")
        html.append("<h2>10. SSL/TLS Details</h2>")
        if ssl_info:
            html.append("<p><strong>Subject:</strong> " + esc(str(ssl_info.get('subject', {}))) + "</p>")
            html.append("<p><strong>Issuer:</strong> " + esc(str(ssl_info.get('issuer', {}))) + "</p>")
            html.append("<p><strong>Valid From:</strong> " + esc(ssl_info.get('valid_from', '')) + "</p>")
            html.append("<p><strong>Valid To:</strong> " + esc(ssl_info.get('valid_to', '')) + "</p>")
            html.append("<p><strong>Protocol:</strong> " + esc(ssl_info.get('protocol', '')) + "</p>")
            html.append("<p><strong>Cipher:</strong> " + esc(ssl_info.get('cipher', '')) + "</p>")
            if ssl_info.get('expired'):
                html.append("<p class='warning'>Certificate is expired.</p>")
            elif ssl_info.get('expiring_soon'):
                html.append("<p class='warning'>Certificate is expiring soon (within 30 days).</p>")
        else:
            html.append("<p>No SSL/TLS info available.</p>")
        html.append("</div>")
        
        # 11. Emails / OSINT
        html.append("<div class='section'>")
        html.append("<h2>11. Emails / OSINT</h2>")
        if emails:
            html.append(f"<p>Discovered {len(emails)} email addresses related to {esc(self.domain)}.</p>")
            html.append("<ul>")
            for e in emails:
                html.append("<li>" + esc(e) + "</li>")
            html.append("</ul>")
        else:
            html.append("<p>No emails discovered.</p>")
        html.append("</div>")
        
        # Skipped modules note
        html.append("<div class='section'>")
        html.append("<h2>Module Execution Notes</h2>")
        notes = []
        if not self.shodan_key:
            notes.append("Shodan module was skipped because no API key was provided.")
        if not self.censys_id or not self.censys_secret:
            notes.append("Censys module was skipped because API ID/Secret were not provided.")
        if not notes:
            html.append("<p>All enabled modules executed. Some data may still be unavailable due to network/API issues.</p>")
        else:
            html.append("<ul>")
            for n in notes:
                html.append("<li>" + esc(n) + "</li>")
            html.append("</ul>")
        html.append("</div>")
        
        html.append("</div></body></html>")
        return "\n".join(html)
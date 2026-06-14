from flask import Flask, render_template, request, jsonify
import requests
import redis
import json
import re
import logging
import ipaddress
from urllib.parse import urlparse, urljoin, urlunparse
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from bs4 import BeautifulSoup
import hashlib
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from curl_cffi import requests as cffi_requests
    CFFI_AVAILABLE = True
except ImportError:
    CFFI_AVAILABLE = False

load_dotenv()

# --- Pretty CLI Logging ---
class ColorFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[90m',
        'INFO': '\033[36m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[41m\033[97m',
    }
    RESET = '\033[0m'
    BOLD = '\033[1m'

    def format(self, record):
        color = self.COLORS.get(record.levelname, '')
        timestamp = self.formatTime(record, '%H:%M:%S')
        level = f"{color}{record.levelname:<8}{self.RESET}"
        msg = record.getMessage()
        return f"\033[90m{timestamp}\033[0m {level} {msg}"

logging.basicConfig(level=logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(ColorFormatter())
logging.root.handlers = [handler]
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Redis configuration
REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
REDIS_DB = int(os.environ.get('REDIS_DB', 0))

try:
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
    redis_client.ping()
    redis_available = True
except Exception:
    redis_available = False
    logger.warning("Redis not available, running without cache")


# --- Request logging ---
@app.before_request
def log_request():
    request._start_time = time.time()

@app.after_request
def log_response(response):
    duration = (time.time() - getattr(request, '_start_time', time.time())) * 1000
    status = response.status_code
    color = '\033[32m' if status < 400 else '\033[33m' if status < 500 else '\033[31m'
    logger.info(f"{color}{request.method}\033[0m {request.path} \033[90m→\033[0m {color}{status}\033[0m \033[90m({duration:.0f}ms)\033[0m")
    return response


# --- SSRF Protection ---
PRIVATE_IP_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
]


def is_safe_url(url: str) -> tuple[bool, str]:
    """Return (is_safe, error_message). Blocks SSRF targets."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False, 'Invalid URL: missing hostname'
        scheme = parsed.scheme.lower()
        if scheme not in ('http', 'https'):
            return False, f'Scheme "{scheme}" is not allowed'
        # Resolve IP
        import socket
        try:
            ip_str = socket.gethostbyname(hostname)
        except socket.gaierror:
            return False, f'Could not resolve hostname: {hostname}'
        ip = ipaddress.ip_address(ip_str)
        for network in PRIVATE_IP_NETWORKS:
            if ip in network:
                return False, f'Requests to private/internal addresses are not allowed'
        return True, ''
    except Exception as e:
        return False, f'URL validation error: {str(e)}'

class HeaderAnalyzer:
    def __init__(self):
        # Define header categories for detailed scoring
        self.header_categories = {
            'security': {
                'name': 'Security',
                'description': 'Headers that protect against common web vulnerabilities',
                'headers': [
                    'Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options',
                    'X-Content-Type-Options', 'X-Permitted-Cross-Domain-Policies',
                    'Clear-Site-Data', 'Cross-Origin-Embedder-Policy', 'Cross-Origin-Opener-Policy',
                    'Cross-Origin-Resource-Policy'
                ]
            },
            'privacy': {
                'name': 'Privacy',
                'description': 'Headers that control data sharing and user privacy',
                'headers': ['Referrer-Policy', 'Permissions-Policy', 'X-DNS-Prefetch-Control']
            },
            'performance': {
                'name': 'Performance',
                'description': 'Headers that optimize loading and caching behavior',
                'headers': ['Cache-Control']
            }
        }

        self.security_headers = {
            'Strict-Transport-Security': {
                'description': 'Forces HTTPS connections and prevents protocol downgrade attacks',
                'recommendation': 'max-age=31536000; includeSubDomains; preload',
                'severity': 'high',
                'category': 'security'
            },
            'Content-Security-Policy': {
                'description': 'Prevents XSS attacks by controlling resource loading',
                'recommendation': None,  # Will be dynamically generated
                'severity': 'high',
                'category': 'security'
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking attacks',
                'recommendation': None,  # Will be dynamically generated
                'severity': 'medium',
                'category': 'security'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME type sniffing',
                'recommendation': 'nosniff',
                'severity': 'medium',
                'category': 'security'
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information sent with requests',
                'recommendation': 'strict-origin-when-cross-origin',
                'severity': 'low',
                'category': 'privacy'
            },
            'Permissions-Policy': {
                'description': 'Controls browser features and APIs',
                'recommendation': None,  # Will be dynamically generated
                'severity': 'low',
                'category': 'privacy'
            },
            'X-Permitted-Cross-Domain-Policies': {
                'description': 'Controls cross-domain policy files for legacy Flash/PDF content',
                'recommendation': 'none',
                'severity': 'low',
                'category': 'security'
            },
            'Clear-Site-Data': {
                'description': 'Clears browsing data when user logs out or leaves sensitive pages',
                'recommendation': '"cache", "cookies", "storage"',
                'severity': 'low',
                'category': 'security'
            },
            'Cross-Origin-Embedder-Policy': {
                'description': 'Controls cross-origin embedding of resources',
                'recommendation': 'require-corp',
                'severity': 'medium',
                'category': 'security'
            },
            'Cross-Origin-Opener-Policy': {
                'description': 'Controls cross-origin window opening',
                'recommendation': 'same-origin',
                'severity': 'medium',
                'category': 'security'
            },
            'Cross-Origin-Resource-Policy': {
                'description': 'Controls cross-origin resource access',
                'recommendation': 'cross-origin',
                'severity': 'medium',
                'category': 'security'
            },
            'Cache-Control': {
                'description': 'Controls caching behavior for sensitive content',
                'recommendation': 'no-store, max-age=0',
                'severity': 'low',
                'category': 'performance'
            },
            'X-DNS-Prefetch-Control': {
                'description': 'Controls DNS prefetching to prevent information leakage',
                'recommendation': 'off',
                'severity': 'low',
                'category': 'privacy'
            }
        }

    def fetch_headers_and_content(self, url, analyze_content=False):
        """Fetch headers and optionally content from the given URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        try:
            result = self._fetch_with_cffi(url)
            if not result['success']:
                return result

            # Detect Cloudflare block
            cloudflare_blocked = self._detect_cloudflare_block(result)
            if cloudflare_blocked:
                result['cloudflare_blocked'] = True
                result['cloudflare_info'] = cloudflare_blocked

            if analyze_content and 'content' not in result:
                # Re-fetch with content if needed
                pass

            if analyze_content and result.get('content'):
                result['content_analysis'] = self.analyze_page_content(result['content'], result.get('final_url', url))

            return result
        except Exception as e:
            return {'error': str(e), 'success': False}

    def _fetch_with_cffi(self, url):
        """Fetch using curl_cffi with Chrome TLS impersonation"""
        if CFFI_AVAILABLE:
            try:
                response = cffi_requests.get(
                    url,
                    timeout=15,
                    allow_redirects=True,
                    impersonate="chrome"
                )
                result = {
                    'headers': dict(response.headers),
                    'status_code': response.status_code,
                    'final_url': str(response.url),
                    'content': response.text,
                    'success': True,
                    'fetch_method': 'chrome_tls'
                }
                return result
            except Exception as e:
                logger.warning(f"curl_cffi failed, falling back to requests: {e}")

        # Fallback to standard requests
        return self._fetch_with_requests(url)

    def _fetch_with_requests(self, url):
        """Fallback fetch using standard requests library"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            response = requests.get(url, timeout=15, allow_redirects=True, headers=headers)
            result = {
                'headers': dict(response.headers),
                'status_code': response.status_code,
                'final_url': response.url,
                'content': response.text,
                'success': True,
                'fetch_method': 'standard'
            }
            return result
        except requests.exceptions.ConnectionError:
            return {'error': f'Could not connect to {url}. Check the URL and try again.', 'success': False}
        except requests.exceptions.Timeout:
            return {'error': f'Request timed out after 15 seconds for {url}.', 'success': False}
        except requests.exceptions.RequestException as e:
            return {'error': str(e), 'success': False}

    def _detect_cloudflare_block(self, result):
        """Detect if the response is a Cloudflare challenge/block page"""
        headers = result.get('headers', {})
        content = result.get('content', '')
        status = result.get('status_code', 0)

        # Check for Cloudflare server header
        server = headers.get('server', '').lower()
        cf_ray = headers.get('cf-ray', '')
        is_cloudflare = 'cloudflare' in server or cf_ray

        if not is_cloudflare:
            return None

        # Check for challenge/block indicators
        indicators = []

        if status == 403:
            indicators.append('access_denied')
        elif status == 503:
            indicators.append('challenge_page')

        if content:
            cf_signatures = [
                ('Attention Required! | Cloudflare', 'attention_required'),
                ('cf-browser-verification', 'browser_check'),
                ('challenge-platform', 'challenge_platform'),
                ('Just a moment...', 'waiting_room'),
                ('cf-challenge-running', 'challenge_running'),
                ('Checking your browser', 'browser_check'),
                ('ray ID', 'ray_id_page'),
            ]
            for signature, indicator in cf_signatures:
                if signature.lower() in content.lower():
                    indicators.append(indicator)

        if indicators:
            return {
                'blocked': True,
                'cf_ray': cf_ray,
                'indicators': indicators,
                'message': self._get_cloudflare_message(indicators)
            }

        return None

    def _get_cloudflare_message(self, indicators):
        """Get human-readable Cloudflare block message"""
        if 'access_denied' in indicators:
            return 'Cloudflare blocked this request (403 Forbidden). The site has strict bot protection.'
        elif 'challenge_page' in indicators or 'challenge_running' in indicators:
            return 'Cloudflare is showing a JavaScript challenge. The site requires browser verification.'
        elif 'browser_check' in indicators:
            return 'Cloudflare Browser Integrity Check is active. The site verifies real browsers.'
        elif 'waiting_room' in indicators:
            return 'Cloudflare Waiting Room or Under Attack Mode is active.'
        elif 'attention_required' in indicators:
            return 'Cloudflare flagged this request. The site has aggressive bot protection.'
        return 'Cloudflare protection detected. Response may not reflect actual site headers.'

    def analyze_page_content(self, html_content, base_url):
        """Analyze HTML content to find external resources and page features"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            parsed_base = urlparse(base_url)
            base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"

            # CSP domains
            domains = {
                'script-src': set(),
                'style-src': set(),
                'img-src': set(),
                'font-src': set(),
                'connect-src': set(),
                'frame-src': set(),
                'media-src': set()
            }

            # Page features that affect security headers
            page_features = {
                'has_iframes': False,
                'iframe_sources': [],
                'has_forms': False,
                'form_actions': [],
                'uses_geolocation': False,
                'uses_camera': False,
                'uses_microphone': False,
                'uses_payment': False,
                'has_downloads': False,
                'download_types': set(),
                'uses_popups': False,
                'uses_fullscreen': False,
                'has_embedded_content': False,
                'internal_links': [],
                'external_links': [],
                'mixed_content_risk': False
            }

            # Analyze scripts for API usage
            all_scripts = soup.find_all('script')
            script_content = ' '.join([script.string or '' for script in all_scripts if script.string])

            # Detect API usage patterns
            if re.search(r'navigator\.geolocation|getCurrentPosition', script_content, re.IGNORECASE):
                page_features['uses_geolocation'] = True

            if re.search(r'getUserMedia|navigator\.camera|video.*capture', script_content, re.IGNORECASE):
                page_features['uses_camera'] = True

            if re.search(r'getUserMedia|navigator\.microphone|audio.*capture', script_content, re.IGNORECASE):
                page_features['uses_microphone'] = True

            if re.search(r'PaymentRequest|payment.*api|stripe|paypal', script_content, re.IGNORECASE):
                page_features['uses_payment'] = True

            if re.search(r'window\.open|popup|new\s+Window', script_content, re.IGNORECASE):
                page_features['uses_popups'] = True

            if re.search(r'requestFullscreen|fullscreen.*api', script_content, re.IGNORECASE):
                page_features['uses_fullscreen'] = True

            # Analyze HTML elements

            # Find script sources
            for script in soup.find_all('script', src=True):
                src = script.get('src')
                domain = self.extract_domain(src, base_domain)
                if domain:
                    domains['script-src'].add(domain)

            # Find inline scripts (need 'unsafe-inline' or nonces)
            inline_scripts = soup.find_all('script', src=False)
            if any(script.string and script.string.strip() for script in inline_scripts):
                domains['script-src'].add("'unsafe-inline'")

            # Find style sources
            for link in soup.find_all('link', rel='stylesheet'):
                href = link.get('href')
                domain = self.extract_domain(href, base_domain)
                if domain:
                    domains['style-src'].add(domain)

            # Find inline styles
            if soup.find_all('style') or soup.find_all(attrs={'style': True}):
                domains['style-src'].add("'unsafe-inline'")

            # Find image sources
            for img in soup.find_all('img', src=True):
                src = img.get('src')
                domain = self.extract_domain(src, base_domain)
                if domain:
                    domains['img-src'].add(domain)

            # Find font sources
            for link in soup.find_all('link', rel='preload'):
                if link.get('as') == 'font':
                    href = link.get('href')
                    domain = self.extract_domain(href, base_domain)
                    if domain:
                        domains['font-src'].add(domain)

            # Analyze iframes
            iframes = soup.find_all('iframe')
            if iframes:
                page_features['has_iframes'] = True
                for iframe in iframes:
                    src = iframe.get('src')
                    if src:
                        page_features['iframe_sources'].append(src)
                        domain = self.extract_domain(src, base_domain)
                        if domain:
                            domains['frame-src'].add(domain)

            # Analyze forms
            forms = soup.find_all('form')
            if forms:
                page_features['has_forms'] = True
                for form in forms:
                    action = form.get('action')
                    if action:
                        page_features['form_actions'].append(action)

            # Analyze links
            links = soup.find_all('a', href=True)
            for link in links:
                href = link.get('href')
                if href:
                    if href.startswith(('http://', 'https://')):
                        parsed_link = urlparse(href)
                        if parsed_link.netloc != parsed_base.netloc:
                            page_features['external_links'].append(href)
                        else:
                            page_features['internal_links'].append(href)
                    elif href.startswith('/'):
                        page_features['internal_links'].append(href)

                    # Check for downloads
                    if link.get('download') or re.search(r'\.(pdf|doc|docx|xls|xlsx|zip|rar)$', href, re.IGNORECASE):
                        page_features['has_downloads'] = True
                        extension = href.split('.')[-1].lower() if '.' in href else 'unknown'
                        page_features['download_types'].add(extension)

            # Check for embedded content
            embeds = soup.find_all(['embed', 'object', 'video', 'audio'])
            if embeds:
                page_features['has_embedded_content'] = True

            # Check for mixed content risk (HTTPS page with HTTP resources)
            if base_url.startswith('https://'):
                http_resources = re.findall(r'http://[^"\s<>]+', html_content)
                if http_resources:
                    page_features['mixed_content_risk'] = True

            # Check for common CDNs and services
            self.add_common_domains(domains, html_content)

            return {
                'domains': domains,
                'page_features': page_features,
                'base_domain': base_domain,
                'analysis_complete': True
            }

        except Exception as e:
            return {
                'error': f'Content analysis failed: {str(e)}',
                'analysis_complete': False
            }

    def extract_domain(self, url, base_domain):
        """Extract domain from URL, handling relative URLs"""
        if not url:
            return None

        # Handle data URLs
        if url.startswith('data:'):
            return 'data:'

        # Handle protocol-relative URLs
        if url.startswith('//'):
            url = 'https:' + url

        # Handle relative URLs
        if url.startswith('/') or not url.startswith(('http://', 'https://')):
            return "'self'"

        try:
            parsed = urlparse(url)
            if parsed.netloc:
                domain = f"{parsed.scheme}://{parsed.netloc}"
                return domain if domain != base_domain else "'self'"
        except Exception:
            pass

        return None

    def add_common_domains(self, domains, html_content):
        """Add commonly detected domains from content analysis"""
        common_patterns = {
            'script-src': [
                r'google-analytics\.com',
                r'googletagmanager\.com',
                r'googleapis\.com',
                r'gstatic\.com',
                r'cdnjs\.cloudflare\.com',
                r'cdn\.jsdelivr\.net',
                r'unpkg\.com',
                r'code\.jquery\.com'
            ],
            'style-src': [
                r'fonts\.googleapis\.com',
                r'fonts\.gstatic\.com'
            ],
            'font-src': [
                r'fonts\.gstatic\.com',
                r'fonts\.googleapis\.com'
            ]
        }

        for directive, patterns in common_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    if 'googleapis.com' in pattern:
                        domains[directive].add('https://fonts.googleapis.com')
                    elif 'gstatic.com' in pattern:
                        domains[directive].add('https://fonts.gstatic.com')
                    elif 'google-analytics.com' in pattern:
                        domains[directive].add('https://www.google-analytics.com')
                    elif 'googletagmanager.com' in pattern:
                        domains[directive].add('https://www.googletagmanager.com')

    def generate_csp_recommendation(self, content_analysis=None):
        """Generate CSP recommendation based on content analysis"""
        if not content_analysis or not content_analysis.get('analysis_complete'):
            return "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'"

        domains = content_analysis['domains']
        csp_parts = []

        # Default source
        csp_parts.append("default-src 'self'")

        # Script sources
        script_sources = ["'self'"]
        if domains['script-src']:
            script_sources.extend(sorted(domains['script-src']))
        if script_sources:
            csp_parts.append(f"script-src {' '.join(script_sources)}")

        # Style sources
        style_sources = ["'self'"]
        if domains['style-src']:
            style_sources.extend(sorted(domains['style-src']))
        if style_sources:
            csp_parts.append(f"style-src {' '.join(style_sources)}")

        # Image sources
        img_sources = ["'self'", "data:"]
        if domains['img-src']:
            img_sources.extend(sorted(domains['img-src']))
        if img_sources:
            csp_parts.append(f"img-src {' '.join(img_sources)}")

        # Font sources
        if domains['font-src']:
            font_sources = ["'self'"] + sorted(domains['font-src'])
            csp_parts.append(f"font-src {' '.join(font_sources)}")

        # Frame sources
        if domains['frame-src']:
            frame_sources = ["'self'"] + sorted(domains['frame-src'])
            csp_parts.append(f"frame-src {' '.join(frame_sources)}")

        return '; '.join(csp_parts)

    def discover_internal_urls(self, base_url, html_content, max_urls=10):
        """Discover internal URLs from the page content"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            parsed_base = urlparse(base_url)
            base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"

            internal_urls = set()
            internal_urls.add(base_url)  # Include the original URL

            # Find all links
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                if not href:
                    continue

                # Handle relative URLs
                if href.startswith('/'):
                    full_url = urljoin(base_domain, href)
                elif href.startswith('http'):
                    parsed_href = urlparse(href)
                    if parsed_href.netloc == parsed_base.netloc:
                        full_url = href
                    else:
                        continue  # Skip external URLs
                else:
                    # Relative URL without leading slash
                    full_url = urljoin(base_url, href)
                    parsed_full = urlparse(full_url)
                    if parsed_full.netloc != parsed_base.netloc:
                        continue

                # Clean URL (remove fragment and query for uniqueness)
                parsed_url = urlparse(full_url)
                clean_url = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    '', '', ''
                ))

                # Skip common non-content URLs
                skip_patterns = [
                    '/admin', '/login', '/logout', '/wp-admin', '/wp-login',
                    '.pdf', '.doc', '.zip', '.jpg', '.png', '.gif', '.css', '.js',
                    '/api/', '/ajax/', '/rss', '/feed', '#', 'mailto:', 'tel:'
                ]

                if any(pattern in clean_url.lower() for pattern in skip_patterns):
                    continue

                internal_urls.add(clean_url)

                if len(internal_urls) >= max_urls:
                    break

            return list(internal_urls)[:max_urls]

        except Exception as e:
            logger.error(f"Error discovering URLs: {str(e)}")
            return [base_url]

    def scan_multiple_urls(self, urls, analyze_content=True):
        """Scan multiple URLs concurrently and return aggregated results"""
        results = []
        aggregated_analysis = {
            'total_pages': len(urls),
            'successful_scans': 0,
            'failed_scans': 0,
            'average_score': 0,
            'common_issues': {},
            'header_consistency': {},
            'page_results': []
        }

        def scan_single_url(url):
            try:
                result = self.fetch_headers_and_content(url, analyze_content)
                if result['success']:
                    analysis = self.analyze_headers(result['headers'], result.get('content_analysis'))
                    return {
                        'url': url,
                        'success': True,
                        'analysis': analysis,
                        'status_code': result['status_code'],
                        'headers': result['headers']
                    }
                else:
                    return {
                        'url': url,
                        'success': False,
                        'error': result.get('error', 'Unknown error')
                    }
            except Exception as e:
                return {
                    'url': url,
                    'success': False,
                    'error': str(e)
                }

        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_url = {executor.submit(scan_single_url, url): url for url in urls}

            for future in as_completed(future_to_url):
                result = future.result()
                results.append(result)

                if result['success']:
                    aggregated_analysis['successful_scans'] += 1
                    analysis = result['analysis']

                    # Track common issues
                    for rec in analysis['recommendations']:
                        header = rec['header']
                        if header not in aggregated_analysis['common_issues']:
                            aggregated_analysis['common_issues'][header] = 0
                        aggregated_analysis['common_issues'][header] += 1

                    # Track header consistency
                    for header, data in analysis['present_headers'].items():
                        if header not in aggregated_analysis['header_consistency']:
                            aggregated_analysis['header_consistency'][header] = []
                        aggregated_analysis['header_consistency'][header].append(data['value'])

                else:
                    aggregated_analysis['failed_scans'] += 1

        # Calculate average score
        successful_results = [r for r in results if r['success']]
        if successful_results:
            total_score = sum(r['analysis']['percentage'] for r in successful_results)
            aggregated_analysis['average_score'] = round(total_score / len(successful_results))

        # Identify inconsistent headers
        for header, values in aggregated_analysis['header_consistency'].items():
            unique_values = list(set(values))
            if len(unique_values) > 1:
                aggregated_analysis['header_consistency'][header] = {
                    'consistent': False,
                    'values': unique_values,
                    'count': len(values)
                }
            else:
                aggregated_analysis['header_consistency'][header] = {
                    'consistent': True,
                    'value': unique_values[0] if unique_values else None,
                    'count': len(values)
                }

        aggregated_analysis['page_results'] = results
        return aggregated_analysis

    def generate_xframe_recommendation(self, content_analysis=None):
        """Generate X-Frame-Options recommendation based on page features"""
        if not content_analysis or not content_analysis.get('analysis_complete'):
            return 'DENY'

        page_features = content_analysis.get('page_features', {})

        # If page has iframes or embedded content, might need SAMEORIGIN
        if page_features.get('has_iframes') or page_features.get('has_embedded_content'):
            return 'SAMEORIGIN'

        # Default to DENY for better security
        return 'DENY'

    def generate_permissions_policy_recommendation(self, content_analysis=None):
        """Generate Permissions-Policy recommendation based on page features"""
        if not content_analysis or not content_analysis.get('analysis_complete'):
            return 'geolocation=(), microphone=(), camera=(), payment=(), fullscreen=()'

        page_features = content_analysis.get('page_features', {})
        policies = []

        # Geolocation
        if page_features.get('uses_geolocation'):
            policies.append('geolocation=(self)')
        else:
            policies.append('geolocation=()')

        # Camera
        if page_features.get('uses_camera'):
            policies.append('camera=(self)')
        else:
            policies.append('camera=()')

        # Microphone
        if page_features.get('uses_microphone'):
            policies.append('microphone=(self)')
        else:
            policies.append('microphone=()')

        # Payment
        if page_features.get('uses_payment'):
            policies.append('payment=(self)')
        else:
            policies.append('payment=()')

        # Fullscreen
        if page_features.get('uses_fullscreen'):
            policies.append('fullscreen=(self)')
        else:
            policies.append('fullscreen=()')

        # Add other common permissions
        policies.extend([
            'accelerometer=()',
            'autoplay=()',
            'encrypted-media=()',
            'gyroscope=()',
            'picture-in-picture=()'
        ])

        return ', '.join(policies)

    def fetch_headers(self, url):
        """Legacy method for backward compatibility"""
        return self.fetch_headers_and_content(url, analyze_content=False)

    def analyze_headers(self, headers, content_analysis=None):
        """Analyze headers and provide recommendations with category-based scoring"""
        analysis = {
            'score': 0,
            'max_score': len(self.security_headers) * 10,
            'present_headers': {},
            'missing_headers': {},
            'recommendations': [],
            'category_scores': {}
        }

        # Initialize category scores
        for category_key, category_info in self.header_categories.items():
            analysis['category_scores'][category_key] = {
                'name': category_info['name'],
                'description': category_info['description'],
                'score': 0,
                'max_score': 0,
                'percentage': 0,
                'present_count': 0,
                'total_count': len(category_info['headers'])
            }

        # Calculate max scores per category
        for header, info in self.security_headers.items():
            category = info.get('category', 'security')
            if category in analysis['category_scores']:
                if info['severity'] == 'high':
                    analysis['category_scores'][category]['max_score'] += 10
                elif info['severity'] == 'medium':
                    analysis['category_scores'][category]['max_score'] += 7
                else:
                    analysis['category_scores'][category]['max_score'] += 5

        for header, info in self.security_headers.items():
            category = info.get('category', 'security')

            if header.lower() in [h.lower() for h in headers.keys()]:
                analysis['present_headers'][header] = {
                    'value': next(v for k, v in headers.items() if k.lower() == header.lower()),
                    'info': info
                }

                # Calculate scores
                score_value = 0
                if info['severity'] == 'high':
                    score_value = 10
                elif info['severity'] == 'medium':
                    score_value = 7
                else:
                    score_value = 5

                analysis['score'] += score_value
                if category in analysis['category_scores']:
                    analysis['category_scores'][category]['score'] += score_value
                    analysis['category_scores'][category]['present_count'] += 1
            else:
                # Generate dynamic recommendations based on content analysis
                dynamic_info = info.copy()

                if header == 'Content-Security-Policy':
                    dynamic_info['recommendation'] = self.generate_csp_recommendation(content_analysis)
                elif header == 'X-Frame-Options':
                    dynamic_info['recommendation'] = self.generate_xframe_recommendation(content_analysis)
                elif header == 'Permissions-Policy':
                    dynamic_info['recommendation'] = self.generate_permissions_policy_recommendation(content_analysis)

                analysis['missing_headers'][header] = dynamic_info

                if dynamic_info['recommendation']:  # Only add if recommendation exists
                    analysis['recommendations'].append({
                        'header': header,
                        'recommendation': dynamic_info['recommendation'],
                        'description': dynamic_info['description'],
                        'severity': dynamic_info['severity'],
                        'category': category
                    })

        # Check for Server Information Leaks (CVE / Recon vulnerability)
        leak_headers = ['Server', 'X-Powered-By']
        has_leak = False
        for leak_header in leak_headers:
            header_val = None
            for key, val in headers.items():
                if key.lower() == leak_header.lower():
                    header_val = val
                    break

            if header_val and re.search(r'[a-zA-Z]+/[\d\.]+', str(header_val)):
                has_leak = True
                analysis['recommendations'].append({
                    'header': leak_header,
                    'recommendation': 'Remove or obfuscate version numbers',
                    'description': f'Information Disclosure: The {leak_header} header exposes the exact software version ({header_val}). Attackers can use this to find specific CVEs targeting this version.',
                    'severity': 'high',
                    'category': 'security'
                })

        if has_leak:
            analysis['score'] = max(0, analysis['score'] - 15)  # Penalize 15 points
            if 'security' in analysis['category_scores']:
                analysis['category_scores']['security']['score'] = max(0, analysis['category_scores']['security']['score'] - 15)

        # Calculate percentage scores for each category
        for category_key, category_data in analysis['category_scores'].items():
            if category_data['max_score'] > 0:
                category_data['percentage'] = round((category_data['score'] / category_data['max_score']) * 100)
            else:
                category_data['percentage'] = 100  # If no headers in category, consider it complete

        # Calculate overall percentage score
        analysis['percentage'] = round((analysis['score'] / analysis['max_score']) * 100)

        # Add summary message based on score
        if analysis['percentage'] >= 90:
            analysis['summary'] = 'Excellent! Your security headers are well-configured.'
        elif analysis['percentage'] >= 70:
            analysis['summary'] = 'Good security configuration with room for improvement.'
        elif analysis['percentage'] >= 50:
            analysis['summary'] = 'Moderate security. Several important headers are missing.'
        else:
            analysis['summary'] = 'Poor security configuration. Many critical headers are missing.'

        return analysis

    def get_server_config(self, header, value, server_type):
        """Generate server-specific configuration"""
        configs = {
            'nginx': {
                'Strict-Transport-Security': f'add_header Strict-Transport-Security "{value}";',
                'Content-Security-Policy': f'add_header Content-Security-Policy "{value}";',
                'X-Frame-Options': f'add_header X-Frame-Options "{value}";',
                'X-Content-Type-Options': f'add_header X-Content-Type-Options "{value}";',
                'Referrer-Policy': f'add_header Referrer-Policy "{value}";',
                'Permissions-Policy': f'add_header Permissions-Policy "{value}";',
                'X-Permitted-Cross-Domain-Policies': f'add_header X-Permitted-Cross-Domain-Policies "{value}";',
                'Clear-Site-Data': f'add_header Clear-Site-Data "{value}";',
                'Cross-Origin-Embedder-Policy': f'add_header Cross-Origin-Embedder-Policy "{value}";',
                'Cross-Origin-Opener-Policy': f'add_header Cross-Origin-Opener-Policy "{value}";',
                'Cross-Origin-Resource-Policy': f'add_header Cross-Origin-Resource-Policy "{value}";',
                'Cache-Control': f'add_header Cache-Control "{value}";',
                'X-DNS-Prefetch-Control': f'add_header X-DNS-Prefetch-Control "{value}";'
            },
            'apache': {
                'Strict-Transport-Security': f'Header always set Strict-Transport-Security "{value}"',
                'Content-Security-Policy': f'Header always set Content-Security-Policy "{value}"',
                'X-Frame-Options': f'Header always set X-Frame-Options "{value}"',
                'X-Content-Type-Options': f'Header always set X-Content-Type-Options "{value}"',
                'Referrer-Policy': f'Header always set Referrer-Policy "{value}"',
                'Permissions-Policy': f'Header always set Permissions-Policy "{value}"',
                'X-Permitted-Cross-Domain-Policies': f'Header always set X-Permitted-Cross-Domain-Policies "{value}"',
                'Clear-Site-Data': f'Header always set Clear-Site-Data "{value}"',
                'Cross-Origin-Embedder-Policy': f'Header always set Cross-Origin-Embedder-Policy "{value}"',
                'Cross-Origin-Opener-Policy': f'Header always set Cross-Origin-Opener-Policy "{value}"',
                'Cross-Origin-Resource-Policy': f'Header always set Cross-Origin-Resource-Policy "{value}"',
                'Cache-Control': f'Header always set Cache-Control "{value}"',
                'X-DNS-Prefetch-Control': f'Header always set X-DNS-Prefetch-Control "{value}"'
            },
            'iis': {
                'Strict-Transport-Security': f'<add name="Strict-Transport-Security" value="{value}" />',
                'Content-Security-Policy': f'<add name="Content-Security-Policy" value="{value}" />',
                'X-Frame-Options': f'<add name="X-Frame-Options" value="{value}" />',
                'X-Content-Type-Options': f'<add name="X-Content-Type-Options" value="{value}" />',
                'Referrer-Policy': f'<add name="Referrer-Policy" value="{value}" />',
                'Permissions-Policy': f'<add name="Permissions-Policy" value="{value}" />',
                'X-Permitted-Cross-Domain-Policies': f'<add name="X-Permitted-Cross-Domain-Policies" value="{value}" />',
                'Clear-Site-Data': f'<add name="Clear-Site-Data" value="{value}" />',
                'Cross-Origin-Embedder-Policy': f'<add name="Cross-Origin-Embedder-Policy" value="{value}" />',
                'Cross-Origin-Opener-Policy': f'<add name="Cross-Origin-Opener-Policy" value="{value}" />',
                'Cross-Origin-Resource-Policy': f'<add name="Cross-Origin-Resource-Policy" value="{value}" />',
                'Cache-Control': f'<add name="Cache-Control" value="{value}" />',
                'X-DNS-Prefetch-Control': f'<add name="X-DNS-Prefetch-Control" value="{value}" />'
            }
        }

        return configs.get(server_type, {}).get(header, f'# Configuration for {header} not available for {server_type}')

analyzer = HeaderAnalyzer()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url', '').strip()
    analyze_content = data.get('analyze_content', True)
    bypass_cache = data.get('bypass_cache', False)
    scan_internal = data.get('scan_internal_urls', False)
    injected_headers = data.get('injected_headers', [])

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    # SSRF protection: validate URL before making any requests
    safe, err = is_safe_url(url)
    if not safe:
        return jsonify({'error': err}), 400

    # Check cache first (unless bypassed)
    cache_key = f"headers:{url}:content:{analyze_content}:internal:{scan_internal}"
    if redis_available and not bypass_cache:
        try:
            cached_result = redis_client.get(cache_key)
            if cached_result:
                cached_data = json.loads(cached_result)
                cached_data['from_cache'] = True
                return jsonify(cached_data)
        except Exception:
            pass

    # Initialize variables
    multi_scan_results = None
    analysis = None

    if scan_internal:
        # Internal URL scanning workflow
        try:
            # First, get the main page to discover URLs
            main_result = analyzer.fetch_headers_and_content(url, analyze_content)
            if not main_result['success']:
                return jsonify({'error': main_result['error']}), 400

            # Inject custom headers into main result for internal scans if present
            if injected_headers:
                for h in injected_headers:
                    main_result['headers'][h['name']] = h['value']

            # Discover internal URLs
            internal_urls = analyzer.discover_internal_urls(
                main_result['final_url'],
                main_result.get('content', ''),
                max_urls=10
            )

            # Scan all discovered URLs
            multi_scan_results = analyzer.scan_multiple_urls(internal_urls, analyze_content)

            response_data = {
                'url': main_result['final_url'],
                'scan_type': 'internal_urls',
                'discovered_urls': internal_urls,
                'multi_scan_results': multi_scan_results,
                'timestamp': datetime.now().isoformat(),
                'from_cache': False
            }

        except Exception as e:
            return jsonify({'error': f'Internal scanning failed: {str(e)}'}), 500

    else:
        # Single URL scanning (existing workflow)
        result = analyzer.fetch_headers_and_content(url, analyze_content)

        if not result['success']:
            return jsonify({'error': result['error']}), 400

        # Inject custom headers before analyzing
        if injected_headers:
            for h in injected_headers:
                result['headers'][h['name']] = h['value']

        content_analysis = result.get('content_analysis')
        analysis = analyzer.analyze_headers(result['headers'], content_analysis)

        response_data = {
            'url': result['final_url'],
            'scan_type': 'single_url',
            'status_code': result['status_code'],
            'headers': result['headers'],
            'analysis': analysis,
            'content_analyzed': analyze_content and content_analysis is not None,
            'timestamp': datetime.now().isoformat(),
            'from_cache': False,
            'fetch_method': result.get('fetch_method', 'standard'),
        }

        # Add Cloudflare block info if detected
        if result.get('cloudflare_blocked'):
            response_data['cloudflare_blocked'] = True
            response_data['cloudflare_info'] = result['cloudflare_info']

        # Add content analysis results if available
        if content_analysis and content_analysis.get('analysis_complete'):
            page_features = content_analysis.get('page_features', {})
            page_features_serializable = {}

            for key, value in page_features.items():
                if isinstance(value, set):
                    page_features_serializable[key] = list(value)
                else:
                    page_features_serializable[key] = value

            response_data['content_analysis'] = {
                'domains_found': {k: list(v) for k, v in content_analysis['domains'].items()},
                'page_features': page_features_serializable,
                'base_domain': content_analysis['base_domain']
            }

    # Cache result and store in scan history
    if redis_available:
        try:
            redis_client.setex(cache_key, 3600, json.dumps(response_data))

            # Store in scan history
            if scan_internal and multi_scan_results:
                score = multi_scan_results['average_score']
            elif analysis:
                score = analysis['percentage']
            else:
                score = 0

            history_item = {
                'url': response_data['url'],
                'timestamp': datetime.now().isoformat(),
                'score': score,
                'status_code': response_data.get('status_code', 200),
                'scan_type': response_data['scan_type']
            }

            redis_client.lpush("scan_history", json.dumps(history_item))
            redis_client.ltrim("scan_history", 0, 19)

        except Exception:
            pass

    return jsonify(response_data)

@app.route('/config', methods=['POST'])
def get_config():
    data = request.get_json()
    header = data.get('header')
    value = data.get('value')
    server_type = data.get('server_type', 'nginx')

    if not header or not value:
        return jsonify({'error': 'Header and value are required'}), 400

    config = analyzer.get_server_config(header, value, server_type)

    return jsonify({
        'header': header,
        'value': value,
        'server_type': server_type,
        'config': config
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({'status': 'ok', 'redis': redis_available})

@app.route('/history', methods=['GET'])
def get_scan_history():
    """Get recent scan history"""
    if not redis_available:
        return jsonify({'history': []})

    try:
        history_items = redis_client.lrange("scan_history", 0, 19)
        history = []

        for item in history_items:
            try:
                parsed_item = json.loads(item)
                # Parse timestamp for relative time
                scan_time = datetime.fromisoformat(parsed_item['timestamp'])
                time_diff = datetime.now() - scan_time

                if time_diff.days > 0:
                    relative_time = f"{time_diff.days}d ago"
                elif time_diff.seconds > 3600:
                    relative_time = f"{time_diff.seconds // 3600}h ago"
                elif time_diff.seconds > 60:
                    relative_time = f"{time_diff.seconds // 60}m ago"
                else:
                    relative_time = "Just now"

                parsed_item['relative_time'] = relative_time
                history.append(parsed_item)
            except Exception:
                continue

        return jsonify({'history': history})
    except Exception:
        return jsonify({'history': []})


@app.route('/top-scores', methods=['GET'])
def get_top_scores():
    """Get top scoring sites from scan history"""
    if not redis_available:
        return jsonify({'top_sites': []})

    try:
        history_items = redis_client.lrange("scan_history", 0, 49)
        sites = {}

        for item in history_items:
            try:
                parsed = json.loads(item)
                url = parsed.get('url', '')
                score = parsed.get('score', 0)
                # Keep the highest score per URL
                if url and (url not in sites or score > sites[url]['score']):
                    sites[url] = {'url': url, 'score': score}
            except Exception:
                continue

        # Sort by score descending, take top 5 with score >= 70
        top_sites = sorted(sites.values(), key=lambda x: x['score'], reverse=True)
        top_sites = [s for s in top_sites if s['score'] >= 70][:5]

        return jsonify({'top_sites': top_sites})
    except Exception:
        return jsonify({'top_sites': []})


@app.route('/clear-cache', methods=['POST'])
def clear_cache():
    """Clear cache for a specific URL"""
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url or not redis_available:
        return jsonify({'success': False, 'error': 'Invalid request'})

    try:
        # Clear all 4 cache key variants (content True/False × internal True/False)
        keys = [
            f"headers:{url}:content:True:internal:True",
            f"headers:{url}:content:True:internal:False",
            f"headers:{url}:content:False:internal:True",
            f"headers:{url}:content:False:internal:False",
        ]
        deleted = redis_client.delete(*keys)

        return jsonify({
            'success': True,
            'message': f'Cache cleared for {url}',
            'keys_deleted': deleted
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })



if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    print("""
\033[36m╔══════════════════════════════════════════════════╗
║                                                  ║
║   🛡️  \033[1mHeaderDoctor\033[0m\033[36m  — HTTP Security Scanner       ║
║                                                  ║
╚══════════════════════════════════════════════════╝\033[0m
""")
    logger.info(f"Redis: \033[{'32m✓ connected' if redis_available else '33m✗ unavailable'}\033[0m ({REDIS_HOST}:{REDIS_PORT})")
    logger.info(f"Server: \033[1mhttp://0.0.0.0:5000\033[0m")
    logger.info(f"Mode: \033[1m{'development' if debug_mode else 'production'}\033[0m")
    print()
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
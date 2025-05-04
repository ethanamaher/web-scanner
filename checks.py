import requests
from urllib.parse import urlparse

def get_response(url):
    try:
        headers = {'User-Agent': 'SimpleScanner/0.1'}
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching {url}: {e}")
        return None
    except Exception as e:
        print(f"[!] Unexpected exception for {url}: {e}")
        return None

def check_https(initial_url, final_url):
    result = []
    parsed_inital = urlparse(initial_url)
    parsed_final = urlparse(final_url)

    if parsed_inital.scheme != 'https':
        result.append({
            'id': 'HTTPS_USAGE',
            'description': f'Initial URL {initial_url} does not use HTTPS.'
        })
    if parsed_final.scheme != 'https':
        result.append({
            'id': 'HTTPS_FINAL',
            'description': f'Final URL {final_url} does not use HTTPS.'
        })
    else:
        result.append({
            'id': 'HTTPS_FINAL',
            'description': f'Final URL {final_url} uses HTTPS.'
        })

    return result

def check_headers(headers):
    result = []

    header_checks = {
        'Strict-Transport-Security': {
            'severity': 'HIGH',
            'recommendation': 'implement HSTS'
        },
        'Content-Security-Policy': {
            'severity': 'HIGH',
            'recommendation': 'implement CSP'
        },
        'X-Frame-Options': {
            'severity': 'MEDIUM',
            'recommendation': 'implement X-Frame-Options'
        },
        'X-Content-Type-Options': {
            'severity': 'MEDIUM',
            'recommendation': 'implement X-Content-Type-Options'
        },
        'Referrer-Policy': {
            'severity': 'LOW',
            'recommendation': 'consider implementing a Referrer-Policy'
        },
        'Permissions-Policy': {
            'severity': 'LOW',
            'recommendation': 'consider implementing a Permissions-Policy'
        }
    }

    present_headers = {h.lower() for h in headers.keys()}

    for header, details in header_checks.items():
        if header.lower() not in present_headers:
            result.append({
                'id': f'MISSING {header.upper()}',
                'severity': details['severity'],
                'recommendation': details['recommendation']
            })

        else:
            result.append({
                'id': f'PRESENT {header.upper()}',
                'severity': 'INFO',
                'recommendation': 'NONE',
            })

    return result

def check_server_header_disclosure(headers):
    result = []
    server_header = headers.get('Server')

    if server_header:
        if any(char.isdigit() for char in server_header):
            result.append({
                'id': 'SERVER_DISCLOSURE',
                'severity': 'Low',
                'description': f'Server header {server_header} may reveal specific version info',
            })
        else:
            result.append({
                'id': 'SERVER_HEADER_GENERIC',
                'severity': 'Info',
                'description': f'Server header {server_header}',
            })
    else:
        result.append({
            'id': 'SERVER_HEADER_MISSING',
            'severity': 'INFO',
            'description': 'Server header not present',
        })

    return result

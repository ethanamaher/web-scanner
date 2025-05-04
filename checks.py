import requests
from urllib.parse import urlparse

def get_response(url):
    """
    Handles requests and returns the final response object

    Returns (response) or
            (None) on error
    """
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
    """
    Checks if site uses HTTPS
    """
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
    """
    Checks for common security headers
    """
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

# probable merge this into check_headers
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

def check_cookies(response_cookies):
    """
    Check Set-Cookie attributes
    """
    result = []
    if not response_cookies:
        return result

    for cookie in response_cookies:
        name = cookie.name
        details = []
        if not cookie.secure:
            result.append({
                'id': 'COOKIE_{name}_NO_SECURE',
                'severity': 'Medium',
                'description': 'Cookie {name} is missing Secure flag',
                'recommendation': 'Add secure flag'
            })


        # HTTP Only check
        is_httponly = False
        if hasattr(cookie, '_rest'):
            for key in cookie._rest:
                if key.strip().lower() == 'httponly':
                    is_httponly = True
                    break

        if not is_httponly:
            result.append({
                'id': f'COOKIE_{name}_NO_HTTPONLY',
                'severity': 'Medium',
                'description': f'Cookie {name} is missing HttpOnly flag',
                'recommendation': 'Add HttpOnly Flag'
            })


        # SameSite check
        samesite_val = None
        samesite_key_found = None
        if hasattr(cookie, '_rest'):
             for key, val in cookie._rest.items():
                 if key.strip().lower() == 'samesite':
                     samesite_val = val
                     samesite_key_found = key
                     break

        if samesite_val is None:
            result.append({
                'id': f'COOKIE_{name}_SAMESITE_MISSING',
                'severity': 'Medium',
                'description': f'Cookie {name} is missing the SameSite attribute',
                'recommendation': 'Set SameSite=Lax or SameSite=Strict to mitigate CSRF attacks'
            })
        else:
            samesite_lower = samesite_val.strip().lower()

            if samesite_lower == 'none':
                severity = 'Medium' if not cookie.secure else 'Low'
                desc = f'Cookie {name} uses SameSite=None'
                if not cookie.secure:
                    desc += ' without the required Secure flag.'
                result.append({
                    'id': f'COOKIE_{name}_SAMESITE_NONE',
                    'severity': severity,
                    'description': desc,
                    'recommendation': 'SameSite=None allows cross-site usage'
                })
            elif samesite_lower not in ('lax', 'strict'):
                 result.append({
                    'id': f'COOKIE_{name}_SAMESITE_UNEXPECTED',
                    'severity': 'Low',
                    'description': f'Cookie {name} has an unexpected SameSite value ({samesite_val}).',
                    'recommendation': f'Review the SameSite attribute value ({samesite_key_found}={samesite_val})'
                })

        if not details:
            result.append({
                'id': f'COOKIE_{name}_SECURE_CONFIG',
                'severity': 'INFO',
                'description': f'Cookie {name} appears to be configured',
                'recommendation': 'None'
            })

    return result

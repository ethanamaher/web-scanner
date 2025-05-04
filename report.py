from colorama import Fore, Style, init

init(autoreset=True)


SEVERITY_COLORS = {
    'HIGH': Fore.RED,
    'MEDIUM': Fore.YELLOW,
    'LOW': Fore.CYAN,
    'INFO': Fore.GREEN,
}

SEVERITY_ORDER = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}

def print_report(target_url, results):
    print(f"\n{Style.BRIGHT}==== Report for: {target_url} ===={Style.RESET_ALL}")

    if not results:
        print(f"\n{Fore.YELLOW}No issues found or scanning failed.{Style.RESET_ALL}")
        return

    sorted_results = sorted(results, key=lambda x: (SEVERITY_ORDER.get(x.get('severity', 'Info'), 99), x.get('id', '')))

    for r in results:
        severity = r.get('severity', 'Info')
        color = SEVERITY_COLORS.get(severity, Fore.WHITE)

        print(f"\n{Style.BRIGHT}[{color}{severity.upper()}{Style.RESET_ALL}] {r.get('id', 'N/A')}")
        print(f"\tDescription: {r.get('description', 'No description')}")

        if severity != 'Info':
            print(f"\t{Fore.LIGHTBLACK_EX}Recommendation: {r.get('recommendation', 'N/A')}{Style.RESET_ALL}")

    print(f'\n{Style.BRIGHT}==== End of Report ===={Style.RESET_ALL}')

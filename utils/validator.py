import re

def validate_domain(domain: str) -> bool:
    """
    Validate domain name format
    """
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def validate_port_range(ports: str) -> bool:
    """
    Validate port range format (e.g., '80-443' or '80')
    """
    try:
        if '-' in ports:
            start, end = map(int, ports.split('-'))
            return 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end
        else:
            port = int(ports)
            return 1 <= port <= 65535
    except:
        return False

import requests
from core.base_plugin import BasePlugin
import logging
from urllib.parse import urljoin
import concurrent.futures

class URLScanner(BasePlugin):
    @property
    def name(self):
        return "URL Path Scanner"

    def __init__(self):
        self.common_paths = [
            'admin/', 'wp-admin/', 'login/', 'wp-login.php',
            'administrator/', 'admin.php', 'backend/',
            '.git/', '.env', 'config.php', 'backup/',
            'api/', 'test/', 'dev/', 'debug/',
            'phpinfo.php', 'info.php', '.htaccess',
            'server-status', '.svn/', '.DS_Store'
        ]

    def _check_path(self, base_url: str, path: str) -> dict:
        url = urljoin(base_url, path)
        try:
            response = requests.get(url, timeout=5, verify=False)
            status_code = response.status_code
            if status_code < 400:  # Consider any non-error response as potentially interesting
                return {
                    'url': url,
                    'status_code': status_code,
                    'vulnerability': 'Potentially sensitive path exposed',
                    'severity': 'High' if status_code == 200 else 'Medium'
                }
            return None
        except requests.exceptions.RequestException as e:
            logging.debug(f"Error checking {url}: {str(e)}")
            return None

    def run(self, target: str, ports: str = None) -> dict:
        logging.info(f"Starting URL path scan for {target}")
        results = {
            'target': target,
            'vulnerable_paths': [],
            'total_paths_checked': len(self.common_paths),
            'total_vulnerabilities': 0
        }

        protocols = ['https://', 'http://']
        for protocol in protocols:
            base_url = f"{protocol}{target}"
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                future_to_path = {
                    executor.submit(self._check_path, base_url, path): path
                    for path in self.common_paths
                }

                for future in concurrent.futures.as_completed(future_to_path):
                    result = future.result()
                    if result:
                        results['vulnerable_paths'].append(result)
                        results['total_vulnerabilities'] += 1

        logging.info(f"Completed URL path scan, found {results['total_vulnerabilities']} potential vulnerabilities")
        return results

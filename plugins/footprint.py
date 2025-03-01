import whois
import socket
import requests
from core.base_plugin import BasePlugin
import logging

class FootprintAnalyzer(BasePlugin):
    @property
    def name(self):
        return "Footprint Analysis"

    def _get_whois_info(self, domain: str) -> dict:
        try:
            logging.info(f"Getting WHOIS information for {domain}")
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'name_servers': w.name_servers
            }
        except Exception as e:
            logging.error(f"WHOIS lookup failed: {str(e)}")
            return {'error': str(e)}

    def _get_headers(self, domain: str) -> dict:
        headers = {}
        try:
            logging.info(f"Attempting HTTPS connection to {domain}")
            response = requests.get(f'https://{domain}', timeout=5, 
                                 verify=False)  # Reduced timeout to 5 seconds
            headers = dict(response.headers)
        except requests.exceptions.RequestException as e:
            logging.warning(f"HTTPS request failed: {str(e)}")
            try:
                logging.info(f"Attempting HTTP connection to {domain}")
                response = requests.get(f'http://{domain}', timeout=5)
                headers = dict(response.headers)
            except requests.exceptions.RequestException as e:
                logging.error(f"HTTP request failed: {str(e)}")
        return headers

    def run(self, target: str, ports: str = None) -> dict:
        logging.info(f"Starting footprint analysis for {target}")
        results = {
            'domain': target,
            'ip': None,
            'whois': None,
            'headers': None
        }

        try:
            results['ip'] = socket.gethostbyname(target)
            logging.info(f"Resolved IP: {results['ip']}")
        except socket.gaierror as e:
            logging.error(f"DNS resolution failed: {str(e)}")
            results['ip'] = 'Unable to resolve'

        results['whois'] = self._get_whois_info(target)
        results['headers'] = self._get_headers(target)

        logging.info("Completed footprint analysis")
        return results
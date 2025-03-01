import dns.resolver
import dns.exception
from core.base_plugin import BasePlugin
import logging

class SubdomainEnumerator(BasePlugin):
    @property
    def name(self):
        return "Subdomain Enumeration"

    def run(self, target: str, ports: str = None) -> dict:
        logging.info(f"Starting subdomain enumeration for {target}")
        results = {
            'target': target,
            'subdomains': []
        }

        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 
                           'test', 'store', 'shop', 'api', 'secure']

        for subdomain in common_subdomains:
            try:
                hostname = f"{subdomain}.{target}"
                answers = dns.resolver.resolve(hostname, 'A')
                for answer in answers:
                    results['subdomains'].append({
                        'subdomain': hostname,
                        'ip': answer.address
                    })
                logging.debug(f"Found subdomain: {hostname}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
                   dns.exception.Timeout):
                continue
            except Exception as e:
                logging.error(f"Error checking {hostname}: {str(e)}")

        logging.info(f"Found {len(results['subdomains'])} subdomains")
        return results
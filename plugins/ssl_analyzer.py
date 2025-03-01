import socket
import ssl
from datetime import datetime
from core.base_plugin import BasePlugin
import logging

class SSLAnalyzer(BasePlugin):
    @property
    def name(self):
        return "SSL Certificate Analysis"

    def _get_certificate(self, domain: str) -> dict:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return {'error': 'No certificate found'}

                    return {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'expired': cert.get('notAfter') and ssl.cert_time_to_seconds(cert['notAfter']) < datetime.now().timestamp()
                    }
        except (socket.gaierror, socket.timeout) as e:
            logging.error(f"Network error during SSL check: {str(e)}")
            return {'error': f'Network error: {str(e)}'}
        except ssl.SSLError as e:
            logging.error(f"SSL error: {str(e)}")
            return {'error': f'SSL error: {str(e)}'}
        except Exception as e:
            logging.error(f"Unexpected error during SSL check: {str(e)}")
            return {'error': f'Unexpected error: {str(e)}'}

    def run(self, target: str, ports: str = None) -> dict:
        logging.info(f"Starting SSL certificate analysis for {target}")
        result = self._get_certificate(target)
        logging.info("Completed SSL certificate analysis")
        return result
import socket
import concurrent.futures
from core.base_plugin import BasePlugin
import logging

class IPAnalyzer(BasePlugin):
    @property
    def name(self):
        return "IP Analysis"

    def _scan_port(self, ip: str, port: int) -> dict:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Reduced timeout to 1 second
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                return {
                    'port': port,
                    'state': 'open',
                    'service': service
                }
            return None
        except Exception as e:
            logging.debug(f"Error scanning port {port}: {str(e)}")
            return None
        finally:
            if sock:
                sock.close()

    def run(self, target: str, ports: str = None) -> dict:
        if not ports:
            ports = "1-100"  # Default to first 100 ports if none specified

        results = {
            'target': target,
            'ip': None,
            'open_ports': []
        }

        try:
            logging.info(f"Resolving IP for {target}")
            results['ip'] = socket.gethostbyname(target)
        except socket.gaierror as e:
            logging.error(f"Could not resolve {target}: {str(e)}")
            return results

        try:
            start_port, end_port = map(int, ports.split('-'))
            if end_port - start_port > 100:
                logging.warning("Limiting port scan range to first 100 ports")
                end_port = start_port + 100
        except ValueError:
            logging.error(f"Invalid port range format: {ports}")
            return results

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self._scan_port, results['ip'], port): port
                for port in range(start_port, end_port + 1)
            }

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result(timeout=2)  # Added timeout for future completion
                    if result:
                        results['open_ports'].append(result)
                except concurrent.futures.TimeoutError:
                    port = futures[future]
                    logging.warning(f"Scan timeout for port {port}")
                except Exception as e:
                    port = futures[future]
                    logging.error(f"Error scanning port {port}: {str(e)}")

        logging.info(f"Completed scanning {len(results['open_ports'])} open ports")
        return results
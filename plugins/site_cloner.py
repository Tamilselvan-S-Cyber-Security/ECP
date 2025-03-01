
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from core.base_plugin import BasePlugin
import logging
import networkx as nx
import json
import os
import mimetypes

class SiteCloner(BasePlugin):
    @property
    def name(self):
        return "Website Structure Analysis"

    def __init__(self):
        self.visited_urls = set()
        self.site_graph = nx.DiGraph()
        self.downloaded_files = {}

    def _is_valid_url(self, url, base_domain):
        """Check if URL belongs to the same domain"""
        parsed_url = urlparse(url)
        parsed_base = urlparse(base_domain)
        return parsed_url.netloc == parsed_base.netloc or not parsed_url.netloc

    def _extract_resources(self, url, html_content, base_domain):
        """Extract all resources from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        resources = set()
        
        # Extract links
        for tag in soup.find_all(['a', 'link', 'script', 'img']):
            href = tag.get('href') or tag.get('src')
            if href:
                full_url = urljoin(url, href)
                if self._is_valid_url(full_url, base_domain):
                    resources.add(full_url)
        
        return resources

    def _download_file(self, url):
        """Download file from URL"""
        try:
            response = requests.get(url, timeout=5, verify=False)
            if response.status_code == 200:
                content_type = response.headers.get('content-type', '').split(';')[0]
                return response.content, content_type
            return None, None
        except Exception as e:
            logging.error(f"Error downloading {url}: {str(e)}")
            return None, None

    def _clone_site(self, url, base_domain, max_depth=2, current_depth=0):
        """Recursively clone site structure and download files"""
        if current_depth > max_depth or url in self.visited_urls:
            return

        self.visited_urls.add(url)
        try:
            content, content_type = self._download_file(url)
            if content and content_type:
                self.downloaded_files[url] = {
                    'content': content,
                    'content_type': content_type
                }

                if 'text/html' in content_type:
                    resources = self._extract_resources(url, content.decode('utf-8', errors='ignore'), base_domain)
                    for resource in resources:
                        if resource not in self.visited_urls:
                            self.site_graph.add_edge(url, resource)
                            self._clone_site(resource, base_domain, max_depth, current_depth + 1)
                            
        except Exception as e:
            logging.error(f"Error cloning {url}: {str(e)}")

    def run(self, target: str, ports: str = None) -> dict:
        logging.info(f"Starting website structure analysis for {target}")
        base_url = f"https://{target}"
        
        self.visited_urls.clear()
        self.site_graph.clear()
        self.downloaded_files.clear()
        
        self._clone_site(base_url, base_url)
        
        nodes = list(self.site_graph.nodes())
        edges = list(self.site_graph.edges())
        
        site_structure = {
            'nodes': nodes,
            'edges': [{'source': s, 'target': t} for s, t in edges],
            'total_pages': len(nodes),
            'total_links': len(edges),
            'downloaded_files': {
                url: {
                    'content_type': info['content_type'],
                    'size': len(info['content'])
                } for url, info in self.downloaded_files.items()
            }
        }
        
        return site_structure

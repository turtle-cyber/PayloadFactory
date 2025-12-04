import requests
from urllib.parse import urljoin, urlparse
import logging
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WebSpider:
    def __init__(self, target_url, max_depth=2):
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited = set()
        self.discovered_paths = set()
        self.session = requests.Session()
        
        # Ensure target URL has scheme
        if not self.target_url.startswith("http"):
            self.target_url = "http://" + self.target_url

    def crawl(self, url=None, depth=0):
        """
        Recursively crawls the target URL to find endpoints.
        """
        if url is None:
            url = self.target_url
            
        if depth > self.max_depth:
            return
        
        if url in self.visited:
            return
        
        self.visited.add(url)
        
        try:
            logger.info(f"Spidering: {url} (Depth {depth})")
            response = self.session.get(url, timeout=3)
            
            if response.status_code == 200:
                # Extract links
                links = self.extract_links(response.text, url)
                
                for link in links:
                    # Only follow links on the same domain
                    if self.is_same_domain(link):
                        path = urlparse(link).path
                        if path and path not in self.discovered_paths:
                            self.discovered_paths.add(path)
                            logger.info(f"  -> Discovered Endpoint: {path}")
                        
                        self.crawl(link, depth + 1)
                        
        except Exception as e:
            logger.debug(f"Spider error on {url}: {e}")

    def extract_links(self, html, base_url):
        """
        Extracts href links from HTML content.
        """
        links = set()
        # Simple regex for hrefs (faster than BS4 for this purpose)
        href_pattern = r'href=["\'](.*?)["\']'
        matches = re.findall(href_pattern, html)
        
        for match in matches:
            full_url = urljoin(base_url, match)
            links.add(full_url)
            
        return links

    def is_same_domain(self, url):
        """
        Checks if the URL belongs to the target domain.
        """
        target_netloc = urlparse(self.target_url).netloc
        url_netloc = urlparse(url).netloc
        return target_netloc == url_netloc or not url_netloc

    def get_paths(self):
        return list(self.discovered_paths)

if __name__ == "__main__":
    spider = WebSpider("http://192.168.1.157:8080")
    spider.crawl()
    print("Discovered Paths:", spider.get_paths())

import requests
import logging
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ReconScanner:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    def scan_target(self, url):
        """
        Scans the target URL for server info, OS, and potential source code exposure.
        """
        logger.info(f"Starting reconnaissance on {url}")
        results = {
            "server": "Unknown",
            "os": "Unknown",
            "technologies": [],
            "potential_source_code": []
        }

        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            
            # Server Header
            if 'Server' in response.headers:
                results['server'] = response.headers['Server']
                # Simple heuristic for OS
                if 'Ubuntu' in results['server'] or 'Debian' in results['server']:
                    results['os'] = 'Linux'
                elif 'Windows' in results['server'] or 'IIS' in results['server']:
                    results['os'] = 'Windows'

            # X-Powered-By
            if 'X-Powered-By' in response.headers:
                results['technologies'].append(response.headers['X-Powered-By'])

            # Parse HTML for more info using Regex (avoiding bs4 dependency)
            html_content = response.text
            
            # Look for common source code extensions in links
            # Pattern: href="...zip" or href='...tar.gz'
            link_pattern = re.compile(r'href=["\'](.*?\.(?:zip|tar\.gz|git|bak|swp))["\']')
            links = link_pattern.findall(html_content)
            results['potential_source_code'].extend(links)
            
            # Look for meta generator tags
            # Pattern: <meta name="generator" content="...">
            generator_pattern = re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\'](.*?)["\']', re.IGNORECASE)
            generator_match = generator_pattern.search(html_content)
            if generator_match:
                results['technologies'].append(generator_match.group(1))

        except Exception as e:
            logger.error(f"Recon failed: {e}")
            return {"error": str(e)}

        logger.info(f"Recon results: {results}")
        return results

if __name__ == "__main__":
    scanner = ReconScanner()
    # Test with a dummy URL or local server
    # print(scanner.scan_target("http://localhost:8000"))

from script.scanner.site_scanner import SiteScanner
import json

def test_scanner():
    # Use example.com as a safe target
    scanner = SiteScanner(base_url="http://example.com", max_depth=1, headless=True)
    site_asset = scanner.scan()
    
    print(f"Scan finished. Pages: {len(site_asset.pages)}")
    for url, page in site_asset.pages.items():
        print(f"URL: {url}")
        print(f"  Inputs: {len(page.inputs)}")
        print(f"  Cookies: {len(page.cookies)}")
        print(f"  LocalStorage: {len(page.local_storage)}")
        print(f"  Comments: {len(page.comments)}")
        print(f"  Meta: {page.meta.keys()}")

if __name__ == "__main__":
    test_scanner()

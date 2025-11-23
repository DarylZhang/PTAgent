import json
from script.scanner.site_scanner import SiteScanner

def test_scanner():
    # Target local OWASP Juice Shop
    target_url = "http://localhost:3000"
    print(f"Scanning {target_url}...")
    
    # Increase depth slightly to ensure we hit some interactive pages if needed, 
    # though Juice Shop is an SPA so depth 1 might be enough for the main app load.
    scanner = SiteScanner(base_url=target_url, max_depth=1, headless=True)
    site_asset = scanner.scan()
    
    print(f"Scanned {len(site_asset.pages)} pages.")
    
    for url, page in site_asset.pages.items():
        print(f"\nPage: {url}")
        print(f"  Inputs: {len(page.inputs)}")
        print(f"  Clickables: {len(page.clickables)}")
        print(f"  API Calls: {len(page.api_calls)}")
        print(f"  Submissions: {len(page.submissions)}")
        
        # Print details of first few API calls to verify capture quality
        for i, api in enumerate(page.api_calls[:3]):
            print(f"  [API #{i+1}] {api.method} {api.url}")
            print(f"    - Req Body: {api.request_body[:100] if api.request_body else 'None'}")
            print(f"    - Req Headers: {list(api.request_headers.keys())}")
            print(f"    - Resp Status: {api.response_status}")
            print(f"    - Resp Body (len): {len(api.response_body) if api.response_body else 0}")
            
        # Print details of Submissions
        for i, sub in enumerate(page.submissions[:3]):
            print(f"  [Submission #{i+1}] Kind: {sub.kind}")
            print(f"    - API IDs: {sub.api_call_ids}")
            print(f"    - Related Input IDs: {sub.related_input_ids}")

if __name__ == "__main__":
    test_scanner()

from script.scanner.site_scanner import SiteScanner

def test_filtering():
    scanner = SiteScanner(base_url="http://example.com")
    
    test_cases = [
        ("main.js", True),
        ("app.js", True),
        ("runtime.js", False),
        ("polyfills.js", False),
        ("vendor.js", False),
        ("jquery.min.js", False),
        ("bootstrap.js", False),
        ("custom-script.js", True),
        ("react.production.min.js", False),
        ("chunk-vendors.js", False),
        # Cross-origin tests (base_url is example.com)
        ("http://example.com/js/myscript.js", True),
        ("https://cdnjs.cloudflare.com/ajax/libs/cookieconsent/3.1.0/cookieconsent.min.js", False),
        ("http://google-analytics.com/ga.js", False),
        ("//cdn.example.net/lib.js", False),
    ]
    
    print("Testing _is_relevant_script logic:")
    for src, expected in test_cases:
        result = scanner._is_relevant_script(src)
        status = "PASS" if result == expected else "FAIL"
        print(f"[{status}] {src}: {result} (Expected: {expected})")

if __name__ == "__main__":
    test_filtering()

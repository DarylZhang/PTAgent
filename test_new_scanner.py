from script.scanner.new_scanner.scanner import ActiveScanner

def test_active_scanner():
    # Use example.com as a safe target (it has no forms, but we can check if it runs)
    # Or use a local test page if available.
    scanner = ActiveScanner(headless=True)
    surface = scanner.scan_url("http://example.com")
    
    print(f"Scan finished for {surface.url}")
    print(f"Static Assets: {len(surface.assets)}")
    print(f"Mutables: {len(surface.mutables)}")
    print(f"Actions: {len(surface.actions)}")
    
    # Print details
    for m in surface.mutables:
        print(f"  [Mutable] {m.type}: {m.name} = {m.value}")

if __name__ == "__main__":
    test_active_scanner()

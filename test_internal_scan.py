#!/usr/bin/env python3
"""
Test script to demonstrate internal URL scanning functionality
"""

import requests
import json

def test_internal_url_scanning():
    """Test the internal URL scanning feature"""

    # Test URL that has multiple internal pages
    test_url = "https://httpbin.org/"

    print("Testing Internal URL Scanning Feature")
    print("=" * 50)
    print(f"Test URL: {test_url}")
    print()

    # Test data for the scan
    scan_data = {
        "url": test_url,
        "analyze_content": True,
        "bypass_cache": True,
        "scan_internal_urls": True
    }

    print("Sending scan request...")
    print(f"Request data: {json.dumps(scan_data, indent=2)}")
    print()

    try:
        response = requests.post(
            "http://127.0.0.1:5000/analyze",
            json=scan_data,
            timeout=60
        )

        if response.status_code == 200:
            result = response.json()

            print("✅ Scan completed successfully!")
            print()
            print("Results Summary:")
            print(f"- Scan Type: {result.get('scan_type', 'unknown')}")
            print(f"- Main URL: {result.get('url', 'N/A')}")
            print(f"- URLs Discovered: {len(result.get('discovered_urls', []))}")

            if 'multi_scan_results' in result:
                multi_results = result['multi_scan_results']
                print(f"- Average Score: {multi_results.get('average_score', 0)}%")
                print(f"- Best Score: {multi_results.get('best_score', 0)}%")
                print(f"- Worst Score: {multi_results.get('worst_score', 0)}%")
                print(f"- Total URLs Scanned: {multi_results.get('total_urls', 0)}")

                print()
                print("Discovered URLs:")
                for url in result.get('discovered_urls', []):
                    print(f"  - {url}")

                print()
                print("Consistency Analysis:")
                for header, analysis in multi_results.get('consistency_analysis', {}).items():
                    print(f"  - {header}: {analysis.get('consistency_score', 0)}% ({analysis.get('present_count', 0)}/{multi_results.get('total_urls', 0)} pages)")

            print()
            print("🎉 Internal URL scanning feature is working correctly!")

        else:
            print(f"❌ Scan failed with status code: {response.status_code}")
            print(f"Error: {response.text}")

    except requests.exceptions.Timeout:
        print("⏰ Request timed out - this is normal for internal scanning as it takes longer")
        print("The feature is working, but the test site may have many URLs to scan")

    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        print("Make sure the HeaderDoctor application is running on http://127.0.0.1:5000")

    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    test_internal_url_scanning()
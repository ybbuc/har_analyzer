"""Analyze a HAR file to extract useful information about a transaction."""

import argparse
import json
import re
from urllib.parse import urlparse

from haralyzer import HarParser


def load_har_file(file_path):
    """Load and parse the HAR file."""
    with open(file_path, "r", encoding="utf-8") as f:
        har_parser = HarParser(json.loads(f.read()))
    return har_parser


def analyze_communications(har_page):
    """Analyze which websites and components are communicated with."""
    domains = {}

    for entry in har_page.entries:
        url = entry.url
        domain = urlparse(url).netloc

        # Find the content-type header
        content_type = "unknown"
        for header in entry.response.headers:
            if header["name"].lower() == "content-type":
                content_type = header["value"]
                break

        if domain not in domains:
            domains[domain] = {
                "js_files": [],
                "css_files": [],
                "images": [],
                "other": [],
            }

        if "javascript" in content_type.lower():
            domains[domain]["js_files"].append(url)
        elif "css" in content_type.lower():
            domains[domain]["css_files"].append(url)
        elif "image" in content_type.lower():
            domains[domain]["images"].append(url)
        else:
            domains[domain]["other"].append(url)

    return domains


def find_card_number_transmissions(har_page):
    """Find where card numbers might be transmitted and check security."""
    card_transmissions = []

    # Regular expression for potential card number pattern (masked for security)
    card_pattern = r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"

    for entry in har_page.entries:
        # Check if connection is secure
        is_secure = entry.url.startswith("https://")

        # Safely build request data string
        request_data = ""

        # Add headers if they exist
        if hasattr(entry.request, "headers"):
            request_data += str(entry.request.headers)

        # Add request text if it exists
        if hasattr(entry.request, "postData") and hasattr(
            entry.request.postData, "text"
        ):
            request_data += str(entry.request.postData.text)

        if re.search(card_pattern, request_data):
            # Safely get TLS version from headers
            tls_header = None
            if hasattr(entry.response, "headers"):
                for header in entry.response.headers:
                    if header["name"].lower() == "strict-transport-security":
                        tls_header = header["value"]
                        break

            card_transmissions.append(
                {
                    "url": entry.url,
                    "secure": is_secure,
                    "method": entry.request.method,
                    "tls_version": tls_header,
                }
            )

    return card_transmissions


def analyze_card_numbers(har_page):
    """Analyze if card numbers are transmitted securely."""
    card_number_patterns = [
        r"\b4[0-9]{12}(?:[0-9]{3})?\b",  # Visa
        r"\b5[1-5][0-9]{14}\b",  # MasterCard
        r"\b3[47][0-9]{13}\b",  # American Express
        r"\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b",  # Diners Club
        r"\b6(?:011|5[0-9]{2})[0-9]{12}\b",  # Discover
    ]

    findings = []
    for entry in har_page.entries:
        # Safely get URL
        url = getattr(entry, "url", "") or ""

        # Safely get request body
        request_body = ""
        if hasattr(entry, "request"):
            request_data = getattr(entry.request, "postData", None)
            if request_data:
                request_body = getattr(request_data, "text", "") or ""

        # Safely get request headers
        request_headers = ""
        if hasattr(entry, "request") and hasattr(entry.request, "headers"):
            for header in entry.request.headers:
                if isinstance(header, dict):
                    name = header.get("name", "")
                    value = header.get("value", "")
                    request_headers += f"{name}: {value}\n"

        # Combine all text to search
        text_to_search = f"{url} {request_body} {request_headers}"

        for pattern in card_number_patterns:
            matches = re.finditer(pattern, text_to_search)
            for match in matches:
                findings.append(
                    {
                        "url": url,
                        "protocol": urlparse(url).scheme,
                        "card_number": match.group(),
                    }
                )

    return findings


def analyze_dns_dependencies(har_page):
    """Analyze DNS dependencies in the transaction."""
    unique_domains = set()

    for entry in har_page.entries:
        domain = urlparse(entry.url).netloc
        unique_domains.add(domain)

    return list(unique_domains)


def analyze_security_headers(har_page):
    """Analyze security-related headers."""
    security_headers = {
        "Content-Security-Policy": [],
        "Strict-Transport-Security": [],
        "X-Frame-Options": [],
        "X-Content-Type-Options": [],
        "X-XSS-Protection": [],
    }

    for entry in har_page.entries:
        for header_key in security_headers.keys():
            # Get all header names from the response headers
            header_names = [h["name"].lower() for h in entry.response.headers]

            # Check if our security header exists in the response headers
            if header_key.lower() in header_names:
                # Find the matching header and get its value
                for h in entry.response.headers:
                    if h["name"].lower() == header_key.lower():
                        security_headers[header_key].append(
                            {"url": entry.url, "value": h["value"]}
                        )
                        break

    return security_headers


def summarize_page(page, index):
    """Summarize key information about a HAR page."""
    print(f"\n=== Page {index} Analysis ===")
    print(f"Page ID: {getattr(page, 'page_id', 'unknown')}")
    print(f"Start time: {getattr(page, 'startedDateTime', 'unknown')}")
    print(f"Number of entries: {len(page.entries)}")

    # Print all URLs in this page to help identify content
    print("\nURLs in this page:")
    for entry in page.entries:
        print(f"- {entry.request.method} {entry.url}")

    # Check for card transmissions
    card_transmissions = find_card_number_transmissions(page)
    if card_transmissions:
        print("\nFound card transmissions:")
        for transmission in card_transmissions:
            print(f"- URL: {transmission['url']}")
            print(f"- Method: {transmission['method']}")

    # Analyze domains
    domains = analyze_communications(page)
    print("\nDomains accessed:")
    for domain in domains.keys():
        print(f"- {domain}")

    # Check for card numbers
    card_findings = analyze_card_numbers(page)
    if card_findings:
        print("\nFound potential card numbers in:")
        for finding in card_findings:
            print(f"- URL: {finding['url']}")

    # Look for payment-related keywords in URLs and request data
    payment_keywords = ["payment", "checkout", "transaction", "order", "cart", "pay"]
    for entry in page.entries:
        url_lower = entry.url.lower()
        if any(keyword in url_lower for keyword in payment_keywords):
            print(f"\nFound payment-related URL:")
            print(f"- {entry.request.method} {entry.url}")

        # Check POST request data
        if entry.request.method == "POST" and hasattr(entry.request, "postData"):
            post_data = getattr(entry.request.postData, "text", "")
            if any(keyword in post_data.lower() for keyword in payment_keywords):
                print(f"\nFound payment-related POST data:")
                print(f"- URL: {entry.url}")


def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Analyze HAR file for transaction details."
    )
    parser.add_argument(
        "-p", type=int, help="Page number to analyze in detail (0-based index)"
    )
    parser.add_argument(
        "-i", type=str, help="Input HAR file path", default="transaction.har"
    )
    args = parser.parse_args()

    try:
        har_parser = load_har_file(args.i)

        if args.p is not None:
            # Analyze specific page in detail
            if args.p >= len(har_parser.pages):
                print(
                    f"Error: Page index {args.p} is out of range. File has {len(har_parser.pages)} pages."
                )
                return

            page = har_parser.pages[args.p]
            print(f"\nDetailed analysis of page {args.p}:")

            print("\n=== Website Communications Analysis ===")
            domains = analyze_communications(page)
            for domain, resources in domains.items():
                print(f"\nDomain: {domain}")
                print(f"JavaScript files: {len(resources['js_files'])}")
                print(f"CSS files: {len(resources['css_files'])}")
                print(f"Images: {len(resources['images'])}")
                print(f"Other resources: {len(resources['other'])}")

            print("\n=== Card Number Transmission Analysis ===")
            card_transmissions = find_card_number_transmissions(page)
            for transmission in card_transmissions:
                print(f"\nURL: {transmission['url']}")
                print(f"Secure connection: {transmission['secure']}")
                print(f"Method: {transmission['method']}")
                print(f"TLS headers: {transmission['tls_version']}")

            print("\n=== DNS Dependencies ===")
            dns_deps = analyze_dns_dependencies(page)
            print(f"Number of unique domains: {len(dns_deps)}")
            for domain in dns_deps:
                print(f"- {domain}")

            print("\n=== Security Headers Analysis ===")
            security_headers = analyze_security_headers(page)
            for header, occurrences in security_headers.items():
                if occurrences:
                    print(f"\n{header}:")
                    for occurrence in occurrences:
                        print(f"- {occurrence['url']}: {occurrence['value']}")
        else:
            # Summarize all pages
            print(f"Total pages in HAR file: {len(har_parser.pages)}")
            for index, page in enumerate(har_parser.pages):
                summarize_page(page, index)

    except Exception as e:
        print(f"Error analyzing HAR file: {str(e)}")


if __name__ == "__main__":
    main()

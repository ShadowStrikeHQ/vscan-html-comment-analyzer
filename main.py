#!/usr/bin/env python3

import argparse
import logging
import requests
from bs4 import BeautifulSoup
import re
import os  # Import the 'os' module

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="vscan-html-comment-analyzer: Parses HTML files and reports sensitive information in comments.")
    parser.add_argument("input", help="The HTML file to analyze or a URL to fetch the HTML from.")
    parser.add_argument("-o", "--output", help="Output file to save the results (optional).", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    return parser

def fetch_html(url):
    """
    Fetches HTML content from a URL.

    Args:
        url (str): The URL to fetch.

    Returns:
        str: The HTML content, or None if an error occurred.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL: {e}")
        return None

def read_html_file(filepath):
    """
    Reads HTML content from a local file.

    Args:
        filepath (str): Path to the HTML file.

    Returns:
        str: The HTML content, or None if an error occurred.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        return None
    except IOError as e:
        logging.error(f"Error reading file: {e}")
        return None

def analyze_comments(html_content):
    """
    Analyzes HTML comments for sensitive information.

    Args:
        html_content (str): The HTML content to analyze.

    Returns:
        list: A list of tuples, where each tuple contains the comment text and its location.
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    comments = soup.find_all(string=lambda text: isinstance(text, BeautifulSoup.Comment))
    findings = []
    sensitive_patterns = [
        r"(password|pwd|secret|key|token)\s*[:=]\s*[\w\d\-_]+",
        r"jdbc:mysql://[\w\d.:/]+",  # Example: JDBC connection string
        r"api_key\s*=\s*[\w\d\-]+",
        r"database\s*=\s*[\w\d\-]+",
    ]

    for comment in comments:
        for pattern in sensitive_patterns:
            if re.search(pattern, comment, re.IGNORECASE):
                 findings.append((str(comment).strip(), "HTML Comment"))
                 break #Avoid multiple matches on the same comment.

    return findings

def write_results(findings, output_file=None):
    """
    Writes the analysis results to a file or stdout.

    Args:
        findings (list): A list of findings (tuples of comment text and location).
        output_file (str, optional): The output file path. If None, writes to stdout.
    """
    if findings:
        output_string = "Findings:\n"
        for comment, location in findings:
            output_string += f"- Location: {location}\n  Comment: {comment}\n"

        if output_file:
            try:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(output_string)
                logging.info(f"Results written to: {output_file}")
            except IOError as e:
                logging.error(f"Error writing to file: {e}")
        else:
            print(output_string)
    else:
        print("No sensitive information found in HTML comments.")

def is_url(input_string):
    """
    Checks if the input string is a valid URL.

    Args:
        input_string (str): The string to check.

    Returns:
        bool: True if the string is a URL, False otherwise.
    """
    try:
        result = requests.compat.urlparse(input_string)
        return all([result.scheme, result.netloc])
    except:
        return False

def main():
    """
    Main function to execute the HTML comment analyzer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    input_source = args.input
    html_content = None

    if is_url(input_source):
        logging.info(f"Analyzing URL: {input_source}")
        html_content = fetch_html(input_source)
    else:
        logging.info(f"Analyzing file: {input_source}")
        html_content = read_html_file(input_source)

    if html_content:
        findings = analyze_comments(html_content)
        write_results(findings, args.output)
    else:
        logging.error("Failed to retrieve HTML content.")

if __name__ == "__main__":
    main()

# Examples
# 1. Analyze a local HTML file:
#    python vscan-html-comment-analyzer.py index.html

# 2. Analyze an HTML file from a URL:
#    python vscan-html-comment-analyzer.py http://example.com/page.html

# 3. Analyze an HTML file and save the results to a file:
#    python vscan-html-comment-analyzer.py index.html -o results.txt

# 4. Analyze an HTML file with verbose output:
#    python vscan-html-comment-analyzer.py index.html -v
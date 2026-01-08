#!/usr/bin/env python3
"""
Scrape Sliver documentation from official sources.

Sources:
- https://sliver.sh/docs (official documentation)
- https://github.com/BishopFox/sliver/wiki (GitHub wiki)
- https://github.com/BishopFox/sliver/tree/master/client/command (source help)

Output: training/sliver/raw/docs/*.md
"""

import json
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# Configuration
OUTPUT_DIR = Path(__file__).parent.parent / "raw" / "docs"
WIKI_OUTPUT_DIR = Path(__file__).parent.parent / "raw" / "wiki"
RATE_LIMIT_SECONDS = 1  # Be nice to servers

# URLs
SLIVER_DOCS_BASE = "https://sliver.sh/docs"
WIKI_BASE = "https://github.com/BishopFox/sliver/wiki"
WIKI_API = "https://api.github.com/repos/BishopFox/sliver/wiki"


def setup_session() -> requests.Session:
    """Create a requests session with proper headers."""
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "SploitGPT-Training-Scraper/1.0 (https://github.com/richardnixon25/SploitGPT)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
    )
    return session


def scrape_sliver_docs(session: requests.Session) -> dict[str, str]:
    """
    Scrape official Sliver documentation from sliver.sh.

    Returns:
        Dict mapping page names to content
    """
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    docs = {}

    print(f"[*] Scraping Sliver docs from {SLIVER_DOCS_BASE}")

    try:
        # Get the main docs page
        response = session.get(SLIVER_DOCS_BASE)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")

        # Find all documentation links
        # The structure may vary - adjust selectors as needed
        doc_links = set()
        for link in soup.find_all("a", href=True):
            href = link["href"]
            if "/docs" in href and not href.endswith("#"):
                full_url = urljoin(SLIVER_DOCS_BASE, href)
                if "sliver.sh" in full_url:
                    doc_links.add(full_url)

        print(f"[+] Found {len(doc_links)} documentation pages")

        # Scrape each page
        for url in sorted(doc_links):
            time.sleep(RATE_LIMIT_SECONDS)

            try:
                page_response = session.get(url)
                page_response.raise_for_status()

                page_soup = BeautifulSoup(page_response.text, "html.parser")

                # Extract main content (adjust selector for actual site structure)
                content_div = (
                    page_soup.find("main")
                    or page_soup.find("article")
                    or page_soup.find("div", class_="content")
                )

                if content_div:
                    # Convert to text while preserving structure
                    content = extract_text_with_structure(content_div)

                    # Generate filename from URL
                    path = urlparse(url).path
                    filename = path.strip("/").replace("/", "_") + ".md"

                    docs[filename] = content

                    # Save immediately
                    output_path = OUTPUT_DIR / filename
                    output_path.write_text(content)
                    print(f"    [+] Saved: {filename}")

            except requests.RequestException as e:
                print(f"    [!] Error scraping {url}: {e}")

    except requests.RequestException as e:
        print(f"[!] Error accessing docs: {e}")

    return docs


def scrape_github_wiki(session: requests.Session) -> dict[str, str]:
    """
    Scrape Sliver GitHub wiki pages.

    Returns:
        Dict mapping page names to content
    """
    WIKI_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    wiki_pages = {}

    print(f"\n[*] Scraping GitHub wiki from {WIKI_BASE}")

    try:
        # Get wiki sidebar to find all pages
        response = session.get(WIKI_BASE)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")

        # Find wiki page links
        wiki_links = set()
        for link in soup.find_all("a", href=True):
            href = link["href"]
            if "/wiki/" in href and "BishopFox/sliver" in href:
                # Skip special pages
                if any(skip in href for skip in ["/_", "/edit", "/new", "/_history"]):
                    continue
                full_url = urljoin("https://github.com", href)
                wiki_links.add(full_url)

        print(f"[+] Found {len(wiki_links)} wiki pages")

        # Scrape each wiki page
        for url in sorted(wiki_links):
            time.sleep(RATE_LIMIT_SECONDS)

            try:
                page_response = session.get(url)
                page_response.raise_for_status()

                page_soup = BeautifulSoup(page_response.text, "html.parser")

                # Wiki content is in markdown-body class
                content_div = page_soup.find("div", class_="markdown-body")

                if content_div:
                    content = extract_text_with_structure(content_div)

                    # Get page name from URL
                    page_name = url.split("/wiki/")[-1].replace("-", "_") + ".md"

                    wiki_pages[page_name] = content

                    # Save immediately
                    output_path = WIKI_OUTPUT_DIR / page_name
                    output_path.write_text(content)
                    print(f"    [+] Saved: {page_name}")

            except requests.RequestException as e:
                print(f"    [!] Error scraping {url}: {e}")

    except requests.RequestException as e:
        print(f"[!] Error accessing wiki: {e}")

    return wiki_pages


def extract_text_with_structure(element) -> str:
    """
    Extract text from HTML while preserving markdown-like structure.
    """
    lines = []

    for child in element.descendants:
        if child.name == "h1":
            lines.append(f"\n# {child.get_text(strip=True)}\n")
        elif child.name == "h2":
            lines.append(f"\n## {child.get_text(strip=True)}\n")
        elif child.name == "h3":
            lines.append(f"\n### {child.get_text(strip=True)}\n")
        elif child.name == "h4":
            lines.append(f"\n#### {child.get_text(strip=True)}\n")
        elif child.name == "p":
            text = child.get_text(strip=True)
            if text:
                lines.append(f"\n{text}\n")
        elif child.name == "pre" or child.name == "code":
            code = child.get_text()
            if "\n" in code or len(code) > 50:
                lines.append(f"\n```\n{code}\n```\n")
            else:
                lines.append(f"`{code}`")
        elif child.name == "li":
            text = child.get_text(strip=True)
            if text:
                lines.append(f"- {text}")
        elif child.name == "table":
            lines.append(extract_table(child))

    # Clean up excessive newlines
    text = "\n".join(lines)
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


def extract_table(table_element) -> str:
    """Convert HTML table to markdown table."""
    rows = []

    # Get headers
    headers = []
    thead = table_element.find("thead")
    if thead:
        for th in thead.find_all(["th", "td"]):
            headers.append(th.get_text(strip=True))

    # Get body rows
    tbody = table_element.find("tbody") or table_element
    for tr in tbody.find_all("tr"):
        row = []
        for td in tr.find_all(["td", "th"]):
            row.append(td.get_text(strip=True))
        if row:
            rows.append(row)

    if not headers and rows:
        headers = rows.pop(0)

    if not headers:
        return ""

    # Build markdown table
    md_lines = []
    md_lines.append("| " + " | ".join(headers) + " |")
    md_lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for row in rows:
        # Pad row if needed
        while len(row) < len(headers):
            row.append("")
        md_lines.append("| " + " | ".join(row[: len(headers)]) + " |")

    return "\n" + "\n".join(md_lines) + "\n"


def extract_command_help_from_source(session: requests.Session) -> dict[str, str]:
    """
    Extract command help text from Sliver source code.

    The client/command/ directory contains Go files with command definitions
    including help text, flags, and examples.
    """
    output_dir = Path(__file__).parent.parent / "raw" / "docs" / "commands"
    output_dir.mkdir(parents=True, exist_ok=True)

    commands = {}

    print("\n[*] Extracting command help from Sliver source")

    # GitHub API to list files in client/command directory
    api_url = "https://api.github.com/repos/BishopFox/sliver/contents/client/command"

    try:
        response = session.get(api_url)
        response.raise_for_status()

        contents = response.json()

        # Find Go files
        go_files = [f for f in contents if f["name"].endswith(".go") and f["type"] == "file"]

        print(f"[+] Found {len(go_files)} command files")

        for file_info in go_files:
            time.sleep(RATE_LIMIT_SECONDS)

            try:
                # Get file content
                file_response = session.get(file_info["download_url"])
                file_response.raise_for_status()

                content = file_response.text

                # Extract command definitions (basic pattern matching)
                # Look for patterns like: Long: `...help text...`
                help_patterns = extract_go_help_strings(content)

                if help_patterns:
                    filename = file_info["name"].replace(".go", ".md")

                    # Format as markdown
                    md_content = f"# {file_info['name']}\n\n"
                    md_content += "Commands defined in this file:\n\n"

                    for cmd_name, help_text in help_patterns.items():
                        md_content += f"## {cmd_name}\n\n{help_text}\n\n"

                    commands[filename] = md_content

                    output_path = output_dir / filename
                    output_path.write_text(md_content)
                    print(f"    [+] Extracted: {filename} ({len(help_patterns)} commands)")

            except requests.RequestException as e:
                print(f"    [!] Error processing {file_info['name']}: {e}")

    except requests.RequestException as e:
        print(f"[!] Error accessing GitHub API: {e}")

    return commands


def extract_go_help_strings(go_code: str) -> dict[str, str]:
    """
    Extract help strings from Go command definitions.

    Looks for patterns like:
    - Long: `help text`
    - Short: "description"
    - Use: "command"
    """
    commands = {}

    # Pattern for cobra command definitions
    # This is a simplified extraction - may need refinement

    # Look for command variable definitions
    cmd_pattern = r"(\w+)Cmd\s*=\s*&cobra\.Command\s*\{([^}]+)\}"

    for match in re.finditer(cmd_pattern, go_code, re.DOTALL):
        cmd_name = match.group(1)
        cmd_body = match.group(2)

        help_text = []

        # Extract Use
        use_match = re.search(r'Use:\s*["`]([^"`]+)["`]', cmd_body)
        if use_match:
            help_text.append(f"**Usage:** `{use_match.group(1)}`")

        # Extract Short description
        short_match = re.search(r'Short:\s*["`]([^"`]+)["`]', cmd_body)
        if short_match:
            help_text.append(f"\n{short_match.group(1)}")

        # Extract Long description (may be multiline)
        long_match = re.search(r"Long:\s*`([^`]+)`", cmd_body)
        if long_match:
            help_text.append(f"\n{long_match.group(1)}")

        if help_text:
            commands[cmd_name] = "\n".join(help_text)

    return commands


def main():
    """Main entry point."""
    print("=" * 60)
    print("Sliver Documentation Scraper")
    print("=" * 60)

    session = setup_session()

    # Scrape all sources
    docs = scrape_sliver_docs(session)
    wiki = scrape_github_wiki(session)
    commands = extract_command_help_from_source(session)

    # Summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"Documentation pages: {len(docs)}")
    print(f"Wiki pages: {len(wiki)}")
    print(f"Command files: {len(commands)}")
    print(f"\nOutput directories:")
    print(f"  - {OUTPUT_DIR}")
    print(f"  - {WIKI_OUTPUT_DIR}")
    print(f"  - {OUTPUT_DIR / 'commands'}")

    # Save metadata
    metadata = {
        "docs_count": len(docs),
        "wiki_count": len(wiki),
        "commands_count": len(commands),
        "docs_files": list(docs.keys()),
        "wiki_files": list(wiki.keys()),
        "command_files": list(commands.keys()),
    }

    metadata_path = Path(__file__).parent.parent / "raw" / "scrape_metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2))
    print(f"\nMetadata saved to: {metadata_path}")


if __name__ == "__main__":
    main()

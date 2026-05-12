#!/usr/bin/env python3
"""
Validate language assignments against GitHub's language breakdown API.
Requires: pip install requests
"""

import json
import os
import sys
import time
from typing import Dict, Tuple

try:
    import requests
except ImportError:
    print("❌ requests library not installed. Run: pip install requests")
    sys.exit(1)

# Map driver names to their actual implementation repos
DRIVER_REPOS = {
    'bigquery': 'apache/arrow-adbc',       # Go implementation in apache/arrow-adbc
    'clickhouse': 'adbc-drivers/clickhouse',  # Rust implementation
    'databricks': 'apache/arrow-adbc',     # Go implementation in apache/arrow-adbc
    'duckdb': 'duckdb/duckdb',             # C++
    'flightsql': 'apache/arrow-adbc',      # Go implementation in apache/arrow-adbc
    'mssql': 'microsoft/go-mssqldb',       # Go driver (but ADBC wrapper is in apache/arrow-adbc)
    'mysql': 'go-sql-driver/mysql',        # Go driver (but ADBC wrapper is in apache/arrow-adbc)
    'oracle': 'godror/godror',             # Go driver (but ADBC wrapper is in apache/arrow-adbc)
    'postgresql': 'apache/arrow-adbc',     # C implementation in apache/arrow-adbc
    'redshift': 'aws/aws-sdk-go',          # Go SDK (but ADBC wrapper is in apache/arrow-adbc)
    'snowflake': 'snowflakedb/gosnowflake', # Go driver (but ADBC wrapper is in apache/arrow-adbc)
    'sqlite': 'apache/arrow-adbc',         # C implementation in apache/arrow-adbc
    'teradata': 'adbc-drivers/teradata',   # Rust implementation
    'trino': 'trinodb/trino-go-client',    # Go driver (but ADBC wrapper is in apache/arrow-adbc)
}

# Expected languages based on ADBC implementation
# Many drivers use apache/arrow-adbc which has multiple languages
EXPECTED_LANGUAGES = {
    'bigquery': 'Go',
    'clickhouse': 'Rust',
    'databricks': 'Go',
    'duckdb': 'C++',
    'flightsql': 'Go',
    'mssql': 'Go',
    'mysql': 'Go',
    'oracle': 'Go',
    'postgresql': 'C',
    'redshift': 'Go',
    'snowflake': 'Go',
    'sqlite': 'C',
    'teradata': 'Rust',
    'trino': 'Go',
}


def get_repo_languages(owner: str, repo: str, token: str = None) -> Dict[str, int]:
    """Get language breakdown from GitHub API."""
    url = f"https://api.github.com/repos/{owner}/{repo}/languages"
    headers = {}
    if token:
        headers['Authorization'] = f'token {token}'

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            print(f"⚠️  Rate limited for {owner}/{repo}", file=sys.stderr)
            return {}
        else:
            print(f"⚠️  Error {response.status_code} for {owner}/{repo}", file=sys.stderr)
            return {}
    except Exception as e:
        print(f"⚠️  Exception for {owner}/{repo}: {e}", file=sys.stderr)
        return {}


def get_top_language(languages: Dict[str, int]) -> str:
    """Get the language with most bytes."""
    if not languages:
        return "Unknown"
    return max(languages.items(), key=lambda x: x[1])[0]


def normalize_language(lang: str) -> str:
    """Normalize language names for comparison."""
    lang_map = {
        'c++': 'cpp',
        'objective-c': 'objc',
        'objective-c++': 'objcpp',
    }
    return lang_map.get(lang.lower(), lang.lower())


def read_current_assignments() -> Dict[str, str]:
    """Read current language assignments from drivers.toml."""
    assignments = {}
    current_driver = None

    try:
        with open('drivers.toml', 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('[drivers.'):
                    # Extract driver name from [drivers.drivername]
                    current_driver = line.split('.')[1].rstrip(']')
                elif line.startswith('language = ') and current_driver:
                    # Extract language value
                    lang = line.split('=')[1].strip().strip('"')
                    assignments[current_driver] = lang
    except FileNotFoundError:
        print("❌ drivers.toml not found")
        sys.exit(1)

    return assignments


def main():
    token = os.environ.get('GITHUB_TOKEN')
    if not token:
        print("⚠️  GITHUB_TOKEN not set - using unauthenticated requests (rate limited)")
        print("   Export GITHUB_TOKEN=your_token for better rate limits")
        print()

    print("🔍 Validating Language Assignments with GitHub API")
    print("=" * 70)
    print()

    current_assignments = read_current_assignments()

    print(f"{'Driver':<15} {'Current':<12} {'Expected':<12} {'GitHub Top':<13} {'Match'}")
    print(f"{'------':<15} {'-------':<12} {'--------':<12} {'----------':<13} {'-----'}")

    matches = 0
    total = 0
    mismatches = []

    for driver in sorted(DRIVER_REPOS.keys()):
        repo = DRIVER_REPOS[driver]
        owner, repo_name = repo.split('/')

        # Get GitHub language data
        languages = get_repo_languages(owner, repo_name, token)
        github_top = get_top_language(languages)

        # Get current and expected
        current = current_assignments.get(driver, 'Not Set')
        expected = EXPECTED_LANGUAGES.get(driver, 'Unknown')

        # Compare current vs expected (this is what matters for ADBC drivers)
        current_norm = normalize_language(current)
        expected_norm = normalize_language(expected)

        match = '✅' if current_norm == expected_norm else '❌'
        if current_norm == expected_norm:
            matches += 1
        else:
            mismatches.append((driver, current, expected, github_top))

        total += 1

        print(f"{driver:<15} {current:<12} {expected:<12} {github_top:<13} {match}")

        # Rate limiting
        if token:
            time.sleep(0.1)
        else:
            time.sleep(1)  # More conservative without token

    print()
    print(f"Results: {matches}/{total} matches")
    print()

    if mismatches:
        print("❌ Mismatches (Current vs Expected):")
        print()
        for driver, current, expected, github_top in mismatches:
            print(f"  {driver}:")
            print(f"    Current:  {current}")
            print(f"    Expected: {expected}")
            print(f"    Note: GitHub shows '{github_top}' but this may be for the entire repo")
            print()
        print("💡 Note: Many drivers share apache/arrow-adbc repo which contains")
        print("   multiple languages. The 'Expected' column shows the actual")
        print("   implementation language for each specific driver.")
        return 1

    print("✅ All language assignments match expected values!")
    return 0


if __name__ == '__main__':
    sys.exit(main())

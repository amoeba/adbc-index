#!/usr/bin/env python3
"""
Test language detection accuracy against known implementations.

Based on the ADBC driver repositories:
- apache/arrow-adbc: Go drivers (bigquery, flightsql, postgresql, snowflake, databricks, sqlite)
- duckdb/duckdb: C++ (duckdb)
- ClickHouse repos: Rust (clickhouse)
- Teradata/rust-adbc: Rust (teradata)
- Go clients: mssql, mysql, oracle, redshift, trino
"""

import duckdb
import sys

# Known languages based on repository inspection
KNOWN_LANGUAGES = {
    'bigquery': 'Go',
    'databricks': 'Go',
    'flightsql': 'Go',
    'mssql': 'Go',
    'mysql': 'Go',
    'oracle': 'Go',
    'redshift': 'Go',
    'snowflake': 'Go',
    'trino': 'Go',
    'clickhouse': 'Rust',
    'teradata': 'Rust',
    'postgresql': 'C',  # Uses libpq
    'sqlite': 'C',      # SQLite is C
    'duckdb': 'C++',    # DuckDB is C++
}

def main():
    print("🔍 Language Detection Validation")
    print("=" * 60)
    print()

    try:
        conn = duckdb.connect()
        result = conn.execute("""
            SELECT name, language
            FROM read_parquet('dist/drivers.parquet')
            ORDER BY name
        """).fetchall()

        print(f"{'Driver':<15} {'Detected':<12} {'Expected':<12} {'Status'}")
        print("-" * 60)

        correct = 0
        total = 0

        for name, detected in result:
            expected = KNOWN_LANGUAGES.get(name, 'Unknown')
            match = '✅' if detected == expected else '❌'

            if detected == expected:
                correct += 1
            total += 1

            print(f"{name:<15} {detected or 'None':<12} {expected:<12} {match}")

        print()
        print(f"Results: {correct}/{total} correct ({100*correct/total:.1f}%)")
        print()

        # Show mismatches
        mismatches = []
        for name, detected in result:
            expected = KNOWN_LANGUAGES.get(name, 'Unknown')
            if detected != expected:
                mismatches.append((name, detected, expected))

        if mismatches:
            print("❌ Mismatches:")
            for name, detected, expected in mismatches:
                print(f"   {name}: detected '{detected}', expected '{expected}'")
            print()

        # Language distribution
        print("Language Distribution:")
        print("-" * 60)
        lang_dist = conn.execute("""
            SELECT language, COUNT(*) as count
            FROM read_parquet('dist/drivers.parquet')
            GROUP BY language
            ORDER BY count DESC, language
        """).fetchall()

        for lang, count in lang_dist:
            print(f"  {lang or 'None':<12} {count:>2} driver(s)")

        return 0 if correct == total else 1

    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())

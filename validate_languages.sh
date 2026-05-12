#!/bin/bash
# Script to validate language detection by comparing against GitHub's language data

set -e

echo "🔍 Language Detection Validation"
echo "================================"
echo ""

# Check if GITHUB_TOKEN is set
if [ -z "$GITHUB_TOKEN" ]; then
    echo "❌ GITHUB_TOKEN not set. Please export GITHUB_TOKEN=your_token"
    exit 1
fi

# Check if duckdb is installed
if ! command -v duckdb &> /dev/null; then
    echo "❌ duckdb not installed. Please install with: brew install duckdb"
    exit 1
fi

# Extract driver info from parquet
echo "📊 Extracting driver language data from parquet..."
duckdb -c "
SELECT name, language
FROM read_parquet('dist/drivers.parquet')
ORDER BY name
" > /tmp/detected_languages.txt

echo ""
echo "🌐 Fetching GitHub language data..."
echo ""

# Function to get primary language from GitHub repo
get_github_language() {
    local owner=$1
    local repo=$2

    # Query GitHub API for languages
    response=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
        "https://api.github.com/repos/$owner/$repo/languages")

    # Parse JSON to get language with most bytes
    primary=$(echo "$response" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    if data and isinstance(data, dict):
        sorted_langs = sorted(data.items(), key=lambda x: x[1], reverse=True)
        if sorted_langs:
            print(sorted_langs[0][0])
        else:
            print('Unknown')
    else:
        print('Unknown')
except:
    print('Unknown')
")

    echo "$primary"
}

# Map of ADBC driver names to GitHub repos
declare -A REPOS
REPOS[bigquery]="apache/arrow-adbc"
REPOS[clickhouse]="ClickHouse/clickhouse-java"  # Note: clickhouse driver is in ClickHouse repo
REPOS[databricks]="apache/arrow-adbc"
REPOS[duckdb]="duckdb/duckdb"
REPOS[flightsql]="apache/arrow-adbc"
REPOS[mssql]="microsoft/go-mssqldb"
REPOS[mysql]="go-sql-driver/mysql"
REPOS[oracle]="godror/godror"
REPOS[postgresql]="apache/arrow-adbc"
REPOS[redshift]="aws/aws-sdk-go"
REPOS[snowflake]="snowflakedb/gosnowflake"
REPOS[sqlite]="apache/arrow-adbc"
REPOS[teradata]="Teradata/rust-adbc"
REPOS[trino]="trinodb/trino-go-client"

echo "Driver Comparison:"
echo "=================="
printf "%-15s %-15s %-15s %-10s\n" "Driver" "Detected" "GitHub" "Match"
printf "%-15s %-15s %-15s %-10s\n" "------" "--------" "------" "-----"

matches=0
total=0

for driver in "${!REPOS[@]}"; do
    repo="${REPOS[$driver]}"
    owner=$(echo "$repo" | cut -d'/' -f1)
    repo_name=$(echo "$repo" | cut -d'/' -f2)

    # Get detected language from parquet
    detected=$(duckdb -c "SELECT language FROM read_parquet('dist/drivers.parquet') WHERE name = '$driver'" | tail -n 2 | head -n 1 | tr -d ' ')

    # Get GitHub language
    github_lang=$(get_github_language "$owner" "$repo_name")

    # Normalize for comparison
    detected_norm=$(echo "$detected" | tr '[:upper:]' '[:lower:]')
    github_norm=$(echo "$github_lang" | tr '[:upper:]' '[:lower:]')

    # Special case mappings
    if [ "$github_norm" = "c++" ]; then
        github_norm="cpp"
    fi

    # Check match
    match="❌"
    if [[ "$detected_norm" == "$github_norm"* ]] || [[ "$github_norm" == "$detected_norm"* ]]; then
        match="✅"
        ((matches++))
    fi

    ((total++))

    printf "%-15s %-15s %-15s %-10s\n" "$driver" "$detected" "$github_lang" "$match"

    # Rate limit
    sleep 0.5
done

echo ""
echo "Results: $matches/$total matches ($(echo "scale=1; $matches*100/$total" | bc)%)"
echo ""

# Summary by language
echo "Language Distribution:"
echo "====================="
duckdb -c "
SELECT language, COUNT(*) as count
FROM read_parquet('dist/drivers.parquet')
GROUP BY language
ORDER BY count DESC, language
"

#!/bin/bash
# Validate language assignments using GitHub's language breakdown API

set -e

if [ -z "$GITHUB_TOKEN" ]; then
    echo "❌ GITHUB_TOKEN not set. Please export GITHUB_TOKEN=your_token"
    exit 1
fi

echo "🔍 Validating Language Assignments with GitHub API"
echo "=================================================="
echo ""

# Map driver names to their GitHub repos
declare -A REPOS
REPOS[bigquery]="apache/arrow-adbc"
REPOS[clickhouse]="ClickHouse/clickhouse-java"
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

# Special cases where driver comes from specific subproject
declare -A SPECIAL_REPOS
SPECIAL_REPOS[clickhouse]="adbc-drivers/clickhouse"
SPECIAL_REPOS[teradata]="adbc-drivers/teradata"

# Get current assignments from drivers.toml
declare -A CURRENT
while IFS='=' read -r key value; do
    if [[ $key == "language" ]]; then
        value=$(echo "$value" | tr -d ' "' | tr -d '\n')
        CURRENT[$current_driver]=$value
    fi
    if [[ $key =~ ^\[drivers\.([a-z]+)\] ]]; then
        current_driver="${BASH_REMATCH[1]}"
    fi
done < drivers.toml

echo "Driver          Current     GitHub Top    Match"
echo "------          -------     ----------    -----"

matches=0
total=0

for driver in bigquery clickhouse databricks duckdb flightsql mssql mysql oracle postgresql redshift snowflake sqlite teradata trino; do
    # Use special repo if defined, otherwise use main repo
    if [ -n "${SPECIAL_REPOS[$driver]}" ]; then
        repo="${SPECIAL_REPOS[$driver]}"
    else
        repo="${REPOS[$driver]}"
    fi

    owner=$(echo "$repo" | cut -d'/' -f1)
    repo_name=$(echo "$repo" | cut -d'/' -f2)

    # Query GitHub API for languages
    response=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
        "https://api.github.com/repos/$owner/$repo_name/languages")

    # Get the language with most bytes
    github_lang=$(echo "$response" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    if data and isinstance(data, dict) and len(data) > 0:
        # Sort by bytes and get top language
        sorted_langs = sorted(data.items(), key=lambda x: x[1], reverse=True)
        print(sorted_langs[0][0])
    else:
        print('Unknown')
except Exception as e:
    print('Error', file=sys.stderr)
    print('Unknown')
" 2>/dev/null)

    current="${CURRENT[$driver]:-Unknown}"

    # Normalize for comparison
    github_norm=$(echo "$github_lang" | tr '[:upper:]' '[:lower:]')
    current_norm=$(echo "$current" | tr '[:upper:]' '[:lower:]')

    # Handle C++ variants
    if [[ "$github_norm" == "c++" ]]; then
        github_norm="cpp"
    fi
    if [[ "$current_norm" == "c++" ]]; then
        current_norm="cpp"
    fi

    match="❌"
    if [[ "$github_norm" == "$current_norm"* ]] || [[ "$current_norm" == "$github_norm"* ]]; then
        match="✅"
        ((matches++))
    fi

    ((total++))

    printf "%-15s %-11s %-13s %s\n" "$driver" "$current" "$github_lang" "$match"

    # Rate limit
    sleep 0.5
done

echo ""
echo "Results: $matches/$total matches"

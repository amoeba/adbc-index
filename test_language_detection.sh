#!/bin/bash
# Test language detection accuracy against known implementations

echo "🔍 Language Detection Validation"
echo "================================================================"
echo ""

# Known languages based on repository inspection
declare -A KNOWN
KNOWN[bigquery]="Go"
KNOWN[databricks]="Go"
KNOWN[flightsql]="Go"
KNOWN[mssql]="Go"
KNOWN[mysql]="Go"
KNOWN[oracle]="Go"
KNOWN[redshift]="Go"
KNOWN[snowflake]="Go"
KNOWN[trino]="Go"
KNOWN[clickhouse]="Rust"
KNOWN[teradata]="Rust"
KNOWN[postgresql]="C"
KNOWN[sqlite]="C"
KNOWN[duckdb]="C++"

printf "%-15s %-12s %-12s %-8s\n" "Driver" "Detected" "Expected" "Status"
echo "----------------------------------------------------------------"

correct=0
total=0
mismatches=""

# Get all drivers
while IFS='|' read -r name language; do
    # Trim whitespace
    name=$(echo "$name" | tr -d ' ')
    language=$(echo "$language" | tr -d ' ')

    expected="${KNOWN[$name]}"
    if [ -z "$expected" ]; then
        expected="Unknown"
    fi

    match="❌"
    if [ "$language" = "$expected" ]; then
        match="✅"
        ((correct++))
    else
        mismatches="$mismatches\n   $name: detected '$language', expected '$expected'"
    fi

    ((total++))

    printf "%-15s %-12s %-12s %-8s\n" "$name" "$language" "$expected" "$match"

done < <(duckdb -csv -noheader -c "SELECT name, language FROM read_parquet('dist/drivers.parquet') ORDER BY name")

echo ""
echo "Results: $correct/$total correct ($(echo "scale=1; $correct*100/$total" | bc)%)"
echo ""

if [ "$correct" -lt "$total" ]; then
    echo "❌ Mismatches:"
    echo -e "$mismatches"
    echo ""
fi

echo "Language Distribution:"
echo "----------------------------------------------------------------"
duckdb -c "
SELECT language, COUNT(*) as count
FROM read_parquet('dist/drivers.parquet')
GROUP BY language
ORDER BY count DESC, language
"

if [ "$correct" -eq "$total" ]; then
    exit 0
else
    exit 1
fi

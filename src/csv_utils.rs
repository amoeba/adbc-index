/// Parse a CSV line, handling quoted fields and escaped quotes
pub fn parse_csv_line(line: &str) -> Vec<String> {
    let mut cells = Vec::new();
    let mut current_cell = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' => {
                // Check if this is an escaped quote
                if in_quotes && chars.peek() == Some(&'"') {
                    current_cell.push('"');
                    chars.next(); // Skip the second quote
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => {
                cells.push(current_cell.clone());
                current_cell.clear();
            }
            _ => {
                current_cell.push(c);
            }
        }
    }

    // Push the last cell
    if !current_cell.is_empty() || !cells.is_empty() {
        cells.push(current_cell);
    }

    cells
}

/// Format a byte count as a human-readable string
pub fn format_file_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_csv() {
        let line = "foo,bar,baz";
        let result = parse_csv_line(line);
        assert_eq!(result, vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn test_parse_csv_with_quotes() {
        let line = r#""foo","bar","baz""#;
        let result = parse_csv_line(line);
        assert_eq!(result, vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn test_parse_csv_with_escaped_quotes() {
        let line = r#""foo ""bar""","baz""#;
        let result = parse_csv_line(line);
        assert_eq!(result, vec![r#"foo "bar""#, "baz"]);
    }

    #[test]
    fn test_format_file_size_bytes() {
        assert_eq!(format_file_size(500), "500 B");
    }

    #[test]
    fn test_format_file_size_kb() {
        assert_eq!(format_file_size(2048), "2.0 KB");
    }

    #[test]
    fn test_format_file_size_mb() {
        assert_eq!(format_file_size(5242880), "5.0 MB");
    }
}

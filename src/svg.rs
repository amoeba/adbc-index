use crate::csv_utils;
use chrono::NaiveDateTime;

/// Generate an SVG plot showing cumulative driver releases over time
pub fn generate_driver_timeline_svg(timeline_csv: &str) -> String {
    // Parse CSV to extract dates and driver names
    let mut data_points: Vec<(chrono::DateTime<chrono::Utc>, String)> = Vec::new();

    for (idx, line) in timeline_csv.lines().enumerate() {
        if idx == 0 {
            continue; // Skip header
        }

        let cells = csv_utils::parse_csv_line(line);
        if cells.len() >= 2 {
            let _name = &cells[0];
            let date_str = &cells[1];

            // Parse the timestamp (format: "2024-01-15 12:34:56.123" or "2024-01-15 12:34:56")
            let dt_result = NaiveDateTime::parse_from_str(date_str, "%Y-%m-%d %H:%M:%S%.f")
                .or_else(|_| NaiveDateTime::parse_from_str(date_str, "%Y-%m-%d %H:%M:%S"));

            if let Ok(naive_dt) = dt_result {
                let dt = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
                    naive_dt,
                    chrono::Utc,
                );
                data_points.push((dt, _name.clone()));
            }
        }
    }

    if data_points.is_empty() {
        return String::from("<p>No driver release data available</p>");
    }

    // Calculate cumulative counts, grouping by date
    let mut plot_points: Vec<(chrono::DateTime<chrono::Utc>, i32)> = Vec::new();
    let mut current_date: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut count = 0;

    for (date, _) in data_points {
        let date_only = date.date_naive();

        match current_date {
            None => {
                count = 1;
                current_date = Some(date);
                plot_points.push((date, count));
            }
            Some(prev_date) => {
                let prev_date_only = prev_date.date_naive();
                if date_only == prev_date_only {
                    count += 1;
                    if let Some(last) = plot_points.last_mut() {
                        last.1 = count;
                    }
                } else {
                    count += 1;
                    plot_points.push((date, count));
                    current_date = Some(date);
                }
            }
        }
    }

    if plot_points.is_empty() {
        return String::from("<p>No driver release data available</p>");
    }

    // SVG dimensions
    let width = 600.0;
    let height = 300.0;
    let margin_left = 40.0;
    let margin_right = 20.0;
    let margin_top = 40.0;
    let margin_bottom = 50.0;
    let plot_width = width - margin_left - margin_right;
    let plot_height = height - margin_top - margin_bottom;

    // Calculate scales
    let min_date = plot_points.first().unwrap().0;
    let max_date = plot_points.last().unwrap().0;
    let date_range = (max_date - min_date).num_seconds() as f64;
    let max_count = plot_points.last().unwrap().1;

    // Handle edge cases
    if max_count <= 0 {
        return String::from("<p>No driver release data available</p>");
    }

    // If all releases are on the same date, avoid division by zero
    let safe_date_range = if date_range <= 0.0 { 1.0 } else { date_range };

    let mut svg = String::new();
    svg.push_str(&format!("<svg width=\"100%\" height=\"{}\" viewBox=\"0 0 {} {}\" xmlns=\"http://www.w3.org/2000/svg\" style=\"background: transparent; max-width: 100%;\">", height, width, height));
    svg.push('\n');

    // Axes
    svg.push_str(&format!(
        "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#1e3a5f\" stroke-width=\"1\"/>",
        margin_left,
        margin_top + plot_height,
        margin_left + plot_width,
        margin_top + plot_height
    ));
    svg.push('\n');
    svg.push_str(&format!(
        "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#1e3a5f\" stroke-width=\"1\"/>",
        margin_left,
        margin_top,
        margin_left,
        margin_top + plot_height
    ));
    svg.push('\n');

    // Y-axis ticks and grid
    let y_tick_count = 5;
    for i in 0..=y_tick_count {
        let tick_value = (max_count as f64 / y_tick_count as f64 * i as f64).round() as i32;
        let y = margin_top + plot_height - (tick_value as f64 / max_count as f64 * plot_height);

        // Grid line
        if i > 0 && i < y_tick_count {
            svg.push_str(&format!(
                "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#1a2332\" stroke-width=\"0.5\" stroke-dasharray=\"2,2\"/>",
                margin_left, y, margin_left + plot_width, y
            ));
            svg.push('\n');
        }

        // Tick label
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"10\" fill=\"#90caf9\" text-anchor=\"end\" alignment-baseline=\"middle\" font-family=\"JetBrains Mono, monospace\">{}</text>",
            margin_left - 8.0, y, tick_value
        ));
        svg.push('\n');
    }

    // X-axis ticks
    let x_tick_count = 5;
    for i in 0..=x_tick_count {
        let date_offset = safe_date_range * i as f64 / x_tick_count as f64;
        let tick_date = min_date + chrono::Duration::seconds(date_offset as i64);
        let x = margin_left + (plot_width * i as f64 / x_tick_count as f64);

        let date_label = tick_date.format("%Y-%m").to_string();
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"9\" fill=\"#90caf9\" text-anchor=\"end\" transform=\"rotate(-45, {}, {})\" font-family=\"JetBrains Mono, monospace\">{}</text>",
            x, margin_top + plot_height + 10.0, x, margin_top + plot_height + 10.0, date_label
        ));
        svg.push('\n');
    }

    // Plot area fill
    let mut area_points = format!("{},{} ", margin_left, margin_top + plot_height);
    for (date, count) in &plot_points {
        let x = margin_left
            + ((date.signed_duration_since(min_date).num_seconds() as f64 / safe_date_range)
                * plot_width);
        let y = margin_top + plot_height - ((*count as f64 / max_count as f64) * plot_height);
        area_points.push_str(&format!("{},{} ", x, y));
    }
    area_points.push_str(&format!(
        "{},{}",
        margin_left + plot_width,
        margin_top + plot_height
    ));

    svg.push_str(&format!(
        "<polygon points=\"{}\" fill=\"rgba(0, 212, 255, 0.1)\" stroke=\"none\"/>",
        area_points.trim()
    ));
    svg.push('\n');

    // Plot line
    let mut polyline_points = String::new();
    for (date, count) in &plot_points {
        let x = margin_left
            + ((date.signed_duration_since(min_date).num_seconds() as f64 / safe_date_range)
                * plot_width);
        let y = margin_top + plot_height - ((*count as f64 / max_count as f64) * plot_height);
        polyline_points.push_str(&format!("{},{} ", x, y));
    }

    svg.push_str(&format!(
        "<polyline points=\"{}\" fill=\"none\" stroke=\"#00d4ff\" stroke-width=\"2\"/>",
        polyline_points.trim()
    ));
    svg.push('\n');

    // Plot points
    for (date, count) in &plot_points {
        let x = margin_left
            + ((date.signed_duration_since(min_date).num_seconds() as f64 / safe_date_range)
                * plot_width);
        let y = margin_top + plot_height - ((*count as f64 / max_count as f64) * plot_height);
        svg.push_str(&format!(
            "<circle cx=\"{}\" cy=\"{}\" r=\"2.5\" fill=\"#00d4ff\"/>",
            x, y
        ));
        svg.push('\n');
    }

    svg.push_str("</svg>\n");
    svg
}

/// Generate a horizontal bar chart
pub fn generate_bar_chart(csv: &str, title: &str) -> String {
    // Parse CSV to extract names and values
    let mut data: Vec<(String, f64)> = Vec::new();

    for (idx, line) in csv.lines().enumerate() {
        if idx == 0 {
            continue; // Skip header
        }

        let cells = csv_utils::parse_csv_line(line);
        if cells.len() >= 2 {
            let name = &cells[0];
            if let Ok(value) = cells[1].parse::<f64>() {
                data.push((name.clone(), value));
            }
        }
    }

    if data.is_empty() {
        return String::from("<p>No data available</p>");
    }

    // SVG dimensions
    let width = 500.0;
    let bar_height = 20.0;
    let bar_spacing = 5.0;
    let margin_left = 100.0;
    let margin_right = 80.0;
    let margin_top = 30.0;
    let margin_bottom = 10.0;
    let plot_width = width - margin_left - margin_right;

    let total_bars = data.len() as f64;
    let height = margin_top + margin_bottom + (total_bars * (bar_height + bar_spacing));

    let max_value = data.iter().map(|(_, v)| *v).fold(0.0, f64::max);

    // Convert to MB for library sizes
    let is_bytes = title.contains("MB");
    let divisor = if is_bytes { 1_048_576.0 } else { 1.0 };
    let scaled_max = max_value / divisor;

    // Handle case where all values are zero
    if scaled_max <= 0.0 || !scaled_max.is_finite() {
        return String::from("<p>No data available (all values are zero)</p>");
    }

    let mut svg = String::new();
    svg.push_str(&format!("<svg width=\"100%\" height=\"{}\" viewBox=\"0 0 {} {}\" xmlns=\"http://www.w3.org/2000/svg\" style=\"background: transparent; max-width: 100%;\">", height, width, height));
    svg.push('\n');

    // Draw bars
    for (i, (name, value)) in data.iter().enumerate() {
        let y = margin_top + (i as f64 * (bar_height + bar_spacing));
        let scaled_value = value / divisor;
        let bar_width = (scaled_value / scaled_max) * plot_width;

        // Bar background
        svg.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"#1a2332\" opacity=\"0.3\"/>",
            margin_left, y, plot_width, bar_height
        ));
        svg.push('\n');

        // Bar
        svg.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"url(#barGradient)\"/>",
            margin_left, y, bar_width, bar_height
        ));
        svg.push('\n');

        // Bar border
        svg.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"none\" stroke=\"#00d4ff\" stroke-width=\"1\"/>",
            margin_left, y, bar_width, bar_height
        ));
        svg.push('\n');

        // Label
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"10\" fill=\"#e3f2fd\" text-anchor=\"end\" alignment-baseline=\"middle\" font-family=\"JetBrains Mono, monospace\" font-weight=\"500\">{}</text>",
            margin_left - 8.0, y + bar_height / 2.0, name
        ));
        svg.push('\n');

        // Value
        let value_text = if is_bytes {
            format!("{:.1}", scaled_value)
        } else {
            format!("{:.0}", scaled_value)
        };
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"9\" fill=\"#90caf9\" alignment-baseline=\"middle\" font-family=\"JetBrains Mono, monospace\">{}</text>",
            margin_left + bar_width + 8.0, y + bar_height / 2.0, value_text
        ));
        svg.push('\n');
    }

    // Add gradient definition
    svg.insert_str(
        svg.find("<rect").unwrap(),
        "<defs><linearGradient id=\"barGradient\" x1=\"0%\" y1=\"0%\" x2=\"100%\" y2=\"0%\">\
         <stop offset=\"0%\" style=\"stop-color:#0099cc;stop-opacity:1\" />\
         <stop offset=\"100%\" style=\"stop-color:#00d4ff;stop-opacity:1\" />\
         </linearGradient></defs>",
    );

    svg.push_str("</svg>\n");
    svg
}

/// Generate a horizontal box and whisker plot
pub fn generate_box_plot(csv: &str, title: &str) -> String {
    // Parse CSV to extract names and box plot statistics
    // Expected format: name,min,q1,median,q3,max,latest
    let mut data: Vec<(String, f64, f64, f64, f64, f64, f64)> = Vec::new();

    for (idx, line) in csv.lines().enumerate() {
        if idx == 0 {
            continue; // Skip header
        }

        let cells = csv_utils::parse_csv_line(line);
        if cells.len() >= 7 {
            let name = &cells[0];
            if let (Ok(min), Ok(q1), Ok(median), Ok(q3), Ok(max), Ok(latest)) = (
                cells[1].parse::<f64>(),
                cells[2].parse::<f64>(),
                cells[3].parse::<f64>(),
                cells[4].parse::<f64>(),
                cells[5].parse::<f64>(),
                cells[6].parse::<f64>(),
            ) {
                data.push((name.clone(), min, q1, median, q3, max, latest));
            }
        }
    }

    if data.is_empty() {
        return String::from("<p>No data available</p>");
    }

    // SVG dimensions
    let width = 500.0;
    let box_height = 20.0;
    let box_spacing = 5.0;
    let margin_left = 100.0;
    let margin_right = 80.0;
    let margin_top = 60.0;  // Increased for legend
    let margin_bottom = 10.0;
    let plot_width = width - margin_left - margin_right;

    let total_boxes = data.len() as f64;
    let height = margin_top + margin_bottom + (total_boxes * (box_height + box_spacing));

    // Find global min and max for scaling
    let global_max = data
        .iter()
        .map(|(_, _, _, _, _, max, _)| *max)
        .fold(0.0, f64::max);

    // Convert to MB for library sizes
    let is_bytes = title.contains("MB");
    let divisor = if is_bytes { 1_048_576.0 } else { 1.0 };
    let scaled_max = global_max / divisor;

    // Handle case where all values are zero
    if scaled_max <= 0.0 || !scaled_max.is_finite() {
        return String::from("<p>No data available (all values are zero)</p>");
    }

    let mut svg = String::new();
    svg.push_str(&format!("<svg width=\"100%\" height=\"{}\" viewBox=\"0 0 {} {}\" xmlns=\"http://www.w3.org/2000/svg\" style=\"background: transparent; max-width: 100%;\">", height, width, height));
    svg.push('\n');

    // Add legend
    let legend_y = 15.0;
    let legend_x_start = margin_left;
    let legend_spacing = 90.0;

    // Whisker
    svg.push_str(&format!(
        "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#00d4ff\" stroke-width=\"1.5\"/>",
        legend_x_start, legend_y, legend_x_start + 15.0, legend_y
    ));
    svg.push_str(&format!(
        "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#00d4ff\" stroke-width=\"1.5\"/>",
        legend_x_start, legend_y - 3.0, legend_x_start, legend_y + 3.0
    ));
    svg.push_str(&format!(
        "<text x=\"{}\" y=\"{}\" font-size=\"9\" fill=\"#90caf9\" alignment-baseline=\"middle\" font-family=\"JetBrains Mono, monospace\">Min-Max</text>",
        legend_x_start + 20.0, legend_y
    ));
    svg.push('\n');

    // Box
    let box_legend_x = legend_x_start + legend_spacing;
    svg.push_str(&format!(
        "<rect x=\"{}\" y=\"{}\" width=\"15\" height=\"10\" fill=\"url(#boxGradient)\" stroke=\"#00d4ff\" stroke-width=\"1\"/>",
        box_legend_x, legend_y - 5.0
    ));
    svg.push_str(&format!(
        "<text x=\"{}\" y=\"{}\" font-size=\"9\" fill=\"#90caf9\" alignment-baseline=\"middle\" font-family=\"JetBrains Mono, monospace\">Q1-Q3</text>",
        box_legend_x + 20.0, legend_y
    ));
    svg.push('\n');

    // Median
    let median_legend_x = box_legend_x + legend_spacing;
    svg.push_str(&format!(
        "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#ffffff\" stroke-width=\"2\"/>",
        median_legend_x, legend_y - 5.0, median_legend_x, legend_y + 5.0
    ));
    svg.push_str(&format!(
        "<text x=\"{}\" y=\"{}\" font-size=\"9\" fill=\"#90caf9\" alignment-baseline=\"middle\" font-family=\"JetBrains Mono, monospace\">Median</text>",
        median_legend_x + 8.0, legend_y
    ));
    svg.push('\n');

    // Latest release
    let latest_legend_x = median_legend_x + legend_spacing;
    svg.push_str(&format!(
        "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#ffd700\" stroke-width=\"2.5\"/>",
        latest_legend_x, legend_y - 5.0, latest_legend_x, legend_y + 5.0
    ));
    svg.push_str(&format!(
        "<text x=\"{}\" y=\"{}\" font-size=\"9\" fill=\"#90caf9\" alignment-baseline=\"middle\" font-family=\"JetBrains Mono, monospace\">Latest</text>",
        latest_legend_x + 8.0, legend_y
    ));
    svg.push('\n');

    // Draw box plots
    for (i, (name, min, q1, median, q3, max, latest)) in data.iter().enumerate() {
        let y = margin_top + (i as f64 * (box_height + box_spacing));
        let center_y = y + box_height / 2.0;

        // Scale values
        let scaled_min = min / divisor;
        let scaled_q1 = q1 / divisor;
        let scaled_median = median / divisor;
        let scaled_q3 = q3 / divisor;
        let scaled_max_val = max / divisor;
        let scaled_latest = latest / divisor;

        // Calculate positions
        let min_x = margin_left + (scaled_min / scaled_max) * plot_width;
        let q1_x = margin_left + (scaled_q1 / scaled_max) * plot_width;
        let median_x = margin_left + (scaled_median / scaled_max) * plot_width;
        let q3_x = margin_left + (scaled_q3 / scaled_max) * plot_width;
        let max_x = margin_left + (scaled_max_val / scaled_max) * plot_width;
        let latest_x = margin_left + (scaled_latest / scaled_max) * plot_width;

        let box_width = q3_x - q1_x;

        // Whisker line (min to max)
        svg.push_str(&format!(
            "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#00d4ff\" stroke-width=\"1.5\"/>",
            min_x, center_y, max_x, center_y
        ));
        svg.push('\n');

        // Min cap
        svg.push_str(&format!(
            "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#00d4ff\" stroke-width=\"1.5\"/>",
            min_x, y + 5.0, min_x, y + box_height - 5.0
        ));
        svg.push('\n');

        // Max cap
        svg.push_str(&format!(
            "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#00d4ff\" stroke-width=\"1.5\"/>",
            max_x, y + 5.0, max_x, y + box_height - 5.0
        ));
        svg.push('\n');

        // Box (Q1 to Q3)
        svg.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"url(#boxGradient)\" stroke=\"#00d4ff\" stroke-width=\"1.5\"/>",
            q1_x, y, box_width, box_height
        ));
        svg.push('\n');

        // Median line
        svg.push_str(&format!(
            "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#ffffff\" stroke-width=\"2\"/>",
            median_x, y, median_x, y + box_height
        ));
        svg.push('\n');

        // Latest release line (yellow)
        svg.push_str(&format!(
            "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#ffd700\" stroke-width=\"2.5\"/>",
            latest_x, y - 2.0, latest_x, y + box_height + 2.0
        ));
        svg.push('\n');

        // Label
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"10\" fill=\"#e3f2fd\" text-anchor=\"end\" alignment-baseline=\"middle\" font-family=\"JetBrains Mono, monospace\" font-weight=\"500\">{}</text>",
            margin_left - 8.0, center_y, name
        ));
        svg.push('\n');

        // Value range text
        let value_text = if is_bytes {
            format!("{:.1}-{:.1}", scaled_min, scaled_max_val)
        } else {
            format!("{:.0}-{:.0}", scaled_min, scaled_max_val)
        };
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"9\" fill=\"#90caf9\" alignment-baseline=\"middle\" font-family=\"JetBrains Mono, monospace\">{}</text>",
            max_x + 8.0, center_y, value_text
        ));
        svg.push('\n');
    }

    // Add gradient definition
    svg.insert_str(
        svg.find("<line").unwrap(),
        "<defs><linearGradient id=\"boxGradient\" x1=\"0%\" y1=\"0%\" x2=\"100%\" y2=\"0%\">\
         <stop offset=\"0%\" style=\"stop-color:#0099cc;stop-opacity:0.7\" />\
         <stop offset=\"100%\" style=\"stop-color:#00d4ff;stop-opacity:0.7\" />\
         </linearGradient></defs>",
    );

    svg.push_str("</svg>\n");
    svg
}

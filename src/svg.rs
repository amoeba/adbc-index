use crate::csv_utils;
use chrono::NaiveDateTime;
use std::collections::HashMap;

/// Generate an SVG plot showing cumulative driver releases over time.
/// Each driver gets an invisible hit-target circle tagged with `data-driver`
/// so the brushing system can highlight individual drivers.
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

    for (date, _) in data_points.iter() {
        let date_only = date.date_naive();

        match current_date {
            None => {
                count = 1;
                current_date = Some(*date);
                plot_points.push((*date, count));
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
                    plot_points.push((*date, count));
                    current_date = Some(*date);
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

    // Build date → (x, y) mapping for per-driver interactive circles
    let mut date_to_xy: HashMap<chrono::NaiveDate, (f64, f64)> = HashMap::new();
    for (date, count) in &plot_points {
        let date_only = date.date_naive();
        let x = margin_left
            + ((date.signed_duration_since(min_date).num_seconds() as f64 / safe_date_range)
                * plot_width);
        let y = margin_top + plot_height - ((*count as f64 / max_count as f64) * plot_height);
        date_to_xy.insert(date_only, (x, y));
    }

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

    // Plot area fill (class="timeline-bg" so brush CSS can dim it)
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
        "<polygon points=\"{}\" fill=\"rgba(0, 212, 255, 0.1)\" stroke=\"none\" class=\"timeline-bg\"/>",
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
        "<polyline points=\"{}\" fill=\"none\" stroke=\"#00d4ff\" stroke-width=\"2\" class=\"timeline-bg\"/>",
        polyline_points.trim()
    ));
    svg.push('\n');

    // Visible step-point circles (aesthetic, not interactive)
    for (date, count) in &plot_points {
        let x = margin_left
            + ((date.signed_duration_since(min_date).num_seconds() as f64 / safe_date_range)
                * plot_width);
        let y = margin_top + plot_height - ((*count as f64 / max_count as f64) * plot_height);
        svg.push_str(&format!(
            "<circle cx=\"{}\" cy=\"{}\" r=\"2.5\" fill=\"#00d4ff\" class=\"timeline-step-point\"/>",
            x, y
        ));
        svg.push('\n');
    }

    // Per-date interactive circles for brushing.
    // Group all drivers that share a release date into one circle so hovering
    // a multi-driver point brushes every driver on that date simultaneously.
    let mut date_to_drivers: HashMap<chrono::NaiveDate, Vec<String>> = HashMap::new();
    for (date, name) in &data_points {
        date_to_drivers
            .entry(date.date_naive())
            .or_default()
            .push(name.clone());
    }

    for (date_only, drivers) in &date_to_drivers {
        if let Some(&(x, y)) = date_to_xy.get(date_only) {
            let drivers_val = drivers.join(",")
                .replace('&', "&amp;")
                .replace('"', "&quot;");
            svg.push_str(&format!(
                "<circle class=\"chart-row brushable timeline-date-group\" \
                 data-drivers=\"{}\" cx=\"{}\" cy=\"{}\" r=\"8\" \
                 fill=\"transparent\" stroke=\"transparent\"/>",
                drivers_val, x, y
            ));
            svg.push('\n');
        }
    }

    svg.push_str("</svg>\n");
    svg
}

/// Generate a horizontal bar chart.
/// `item_attr` is the data-attribute name used for brushing:
/// use `"driver"` for driver charts and `"language"` for the language breakdown chart.
pub fn generate_bar_chart(csv: &str, title: &str, item_attr: &str) -> String {
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

    // Gradient definition emitted first so later fill references resolve correctly.
    // Multiple SVGs on the page share this ID; they all use identical stops so it's fine.
    svg.push_str(
        "<defs><linearGradient id=\"barGradient\" x1=\"0%\" y1=\"0%\" x2=\"100%\" y2=\"0%\">\
         <stop offset=\"0%\" style=\"stop-color:#0099cc;stop-opacity:1\" />\
         <stop offset=\"100%\" style=\"stop-color:#00d4ff;stop-opacity:1\" />\
         </linearGradient></defs>\n",
    );

    // Draw bars – each row is wrapped in a <g> for CSS-based brushing
    for (i, (name, value)) in data.iter().enumerate() {
        let y = margin_top + (i as f64 * (bar_height + bar_spacing));
        let scaled_value = value / divisor;
        let bar_width = (scaled_value / scaled_max) * plot_width;

        let escaped = name.replace('&', "&amp;").replace('"', "&quot;");
        svg.push_str(&format!(
            "<g data-{}=\"{}\" class=\"chart-row brushable\">\n",
            item_attr, escaped
        ));

        // Bar background (full-width track)
        svg.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"#1a2332\" opacity=\"0.3\"/>\n",
            margin_left, y, plot_width, bar_height
        ));

        // Bar fill
        svg.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"url(#barGradient)\"/>\n",
            margin_left, y, bar_width, bar_height
        ));

        // Bar border
        svg.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"none\" stroke=\"#00d4ff\" stroke-width=\"1\"/>\n",
            margin_left, y, bar_width, bar_height
        ));

        // Driver/language label
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"10\" fill=\"#e3f2fd\" text-anchor=\"end\" alignment-baseline=\"middle\" font-family=\"JetBrains Mono, monospace\" font-weight=\"500\">{}</text>\n",
            margin_left - 8.0,
            y + bar_height / 2.0,
            name
        ));

        // Value label
        let value_text = if is_bytes {
            format!("{:.1}", scaled_value)
        } else {
            format!("{:.0}", scaled_value)
        };
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"9\" fill=\"#90caf9\" alignment-baseline=\"middle\" font-family=\"JetBrains Mono, monospace\">{}</text>\n",
            margin_left + bar_width + 8.0,
            y + bar_height / 2.0,
            value_text
        ));

        svg.push_str("</g>\n");
    }

    svg.push_str("</svg>\n");
    svg
}

/// Generate a horizontal box-and-whisker plot.
/// Each row is wrapped in `<g data-driver="…">` for CSS-based brushing.
pub fn generate_box_plot(csv: &str, title: &str) -> String {
    // Parse CSV to extract names and box plot statistics
    // Expected format: name,min,q1,median,q3,max,latest_min,latest_max
    let mut data: Vec<(String, f64, f64, f64, f64, f64, f64, f64)> = Vec::new();

    for (idx, line) in csv.lines().enumerate() {
        if idx == 0 {
            continue; // Skip header
        }

        let cells = csv_utils::parse_csv_line(line);
        if cells.len() >= 8 {
            let name = &cells[0];
            if let (Ok(min), Ok(q1), Ok(median), Ok(q3), Ok(max), Ok(latest_min), Ok(latest_max)) = (
                cells[1].parse::<f64>(),
                cells[2].parse::<f64>(),
                cells[3].parse::<f64>(),
                cells[4].parse::<f64>(),
                cells[5].parse::<f64>(),
                cells[6].parse::<f64>(),
                cells[7].parse::<f64>(),
            ) {
                data.push((name.clone(), min, q1, median, q3, max, latest_min, latest_max));
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
    let margin_bottom = 30.0;
    let plot_width = width - margin_left - margin_right;

    let total_boxes = data.len() as f64;
    let height = margin_top + margin_bottom + (total_boxes * (box_height + box_spacing));

    // Find global min and max for scaling
    let global_max = data
        .iter()
        .map(|(_, _, _, _, _, max, _, _)| *max)
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

    // Gradient definition upfront
    svg.push_str(
        "<defs><linearGradient id=\"boxGradient\" x1=\"0%\" y1=\"0%\" x2=\"100%\" y2=\"0%\">\
         <stop offset=\"0%\" style=\"stop-color:#0099cc;stop-opacity:0.7\" />\
         <stop offset=\"100%\" style=\"stop-color:#00d4ff;stop-opacity:0.7\" />\
         </linearGradient></defs>\n",
    );

    // Add legend (chart-level, not per-row)
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

    // Latest release (yellow box)
    let latest_legend_x = median_legend_x + legend_spacing;
    svg.push_str(&format!(
        "<rect x=\"{}\" y=\"{}\" width=\"15\" height=\"10\" fill=\"#ffd700\" fill-opacity=\"0.35\" stroke=\"#ffd700\" stroke-width=\"1.5\"/>",
        latest_legend_x, legend_y - 5.0
    ));
    svg.push_str(&format!(
        "<text x=\"{}\" y=\"{}\" font-size=\"9\" fill=\"#90caf9\" alignment-baseline=\"middle\" font-family=\"JetBrains Mono, monospace\">Latest</text>",
        latest_legend_x + 20.0, legend_y
    ));
    svg.push('\n');

    // Draw box plots – each row wrapped in a <g> for brushing
    for (i, (name, min, q1, median, q3, max, latest_min, latest_max)) in data.iter().enumerate() {
        let y = margin_top + (i as f64 * (box_height + box_spacing));
        let center_y = y + box_height / 2.0;

        // Scale values
        let scaled_min = min / divisor;
        let scaled_q1 = q1 / divisor;
        let scaled_median = median / divisor;
        let scaled_q3 = q3 / divisor;
        let scaled_max_val = max / divisor;
        let scaled_latest_min = latest_min / divisor;
        let scaled_latest_max = latest_max / divisor;

        // Calculate positions
        let min_x = margin_left + (scaled_min / scaled_max) * plot_width;
        let q1_x = margin_left + (scaled_q1 / scaled_max) * plot_width;
        let median_x = margin_left + (scaled_median / scaled_max) * plot_width;
        let q3_x = margin_left + (scaled_q3 / scaled_max) * plot_width;
        let max_x = margin_left + (scaled_max_val / scaled_max) * plot_width;
        let latest_min_x = margin_left + (scaled_latest_min / scaled_max) * plot_width;
        let latest_max_x = margin_left + (scaled_latest_max / scaled_max) * plot_width;

        let box_width = q3_x - q1_x;
        let latest_box_width = (latest_max_x - latest_min_x).max(2.0); // min 2px so single-platform is visible

        let escaped = name.replace('&', "&amp;").replace('"', "&quot;");
        svg.push_str(&format!(
            "<g data-driver=\"{}\" class=\"chart-row brushable\">\n",
            escaped
        ));

        // Whisker line (min to max)
        svg.push_str(&format!(
            "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#00d4ff\" stroke-width=\"1.5\"/>\n",
            min_x, center_y, max_x, center_y
        ));

        // Min cap
        svg.push_str(&format!(
            "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#00d4ff\" stroke-width=\"1.5\"/>\n",
            min_x, y + 5.0, min_x, y + box_height - 5.0
        ));

        // Max cap
        svg.push_str(&format!(
            "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#00d4ff\" stroke-width=\"1.5\"/>\n",
            max_x, y + 5.0, max_x, y + box_height - 5.0
        ));

        // Box (Q1 to Q3)
        svg.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"url(#boxGradient)\" stroke=\"#00d4ff\" stroke-width=\"1.5\"/>\n",
            q1_x, y, box_width, box_height
        ));

        // Median line
        svg.push_str(&format!(
            "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#ffffff\" stroke-width=\"2\"/>\n",
            median_x, y, median_x, y + box_height
        ));

        // Latest release box (transparent yellow overlay)
        svg.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"#ffd700\" fill-opacity=\"0.35\" stroke=\"#ffd700\" stroke-width=\"1.5\" rx=\"2\"/>\n",
            latest_min_x, y - 2.0, latest_box_width, box_height + 4.0
        ));

        // Driver label
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"10\" fill=\"#e3f2fd\" text-anchor=\"end\" alignment-baseline=\"middle\" font-family=\"JetBrains Mono, monospace\" font-weight=\"500\">{}</text>\n",
            margin_left - 8.0, center_y, name
        ));

        // Value range text
        let value_text = if is_bytes {
            format!("{:.1}-{:.1}", scaled_min, scaled_max_val)
        } else {
            format!("{:.0}-{:.0}", scaled_min, scaled_max_val)
        };
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"9\" fill=\"#90caf9\" alignment-baseline=\"middle\" font-family=\"JetBrains Mono, monospace\">{}</text>\n",
            max_x + 8.0, center_y, value_text
        ));

        svg.push_str("</g>\n");
    }

    // Add x-axis scale at the bottom (not part of any row group)
    let axis_y = margin_top + (total_boxes * (box_height + box_spacing)) + 5.0;
    let unit = if is_bytes { "MB" } else { "" };

    // Determine nice tick interval
    let raw_interval = scaled_max / 5.0;
    let magnitude = 10.0_f64.powf(raw_interval.log10().floor());
    let nice_interval = (raw_interval / magnitude).ceil() * magnitude;

    let mut tick_val = 0.0;
    while tick_val <= scaled_max * 1.01 {
        let tick_x = margin_left + (tick_val / scaled_max) * plot_width;
        // Tick mark
        svg.push_str(&format!(
            "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#546e7a\" stroke-width=\"1\"/>\n",
            tick_x, axis_y, tick_x, axis_y + 4.0
        ));
        // Label
        let label = if nice_interval >= 1.0 {
            format!("{:.0}{}", tick_val, unit)
        } else {
            format!("{:.1}{}", tick_val, unit)
        };
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"9\" fill=\"#546e7a\" text-anchor=\"middle\" font-family=\"JetBrains Mono, monospace\">{}</text>\n",
            tick_x, axis_y + 14.0, label
        ));
        tick_val += nice_interval;
    }

    // Axis line
    svg.push_str(&format!(
        "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"#546e7a\" stroke-width=\"1\"/>\n",
        margin_left, axis_y, margin_left + plot_width, axis_y
    ));

    svg.push_str("</svg>\n");
    svg
}

use crate::error::{AdbcIndexError, Result};
use adbc_core::constants::*;
use adbc_core::options::{AdbcVersion, InfoCode, OptionDatabase, OptionValue};
use adbc_core::sync::{Connection, Database, Driver};
use adbc_driver_manager::ManagedDriver;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::Path;

/// Detect driver type from library filename and return appropriate connection URI
fn get_dummy_uri_for_driver(library_path: &Path) -> String {
    let filename = library_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Try to detect driver type from filename
    if filename.contains("sqlite") {
        ":memory:".to_string()
    } else if filename.contains("duckdb") {
        ":memory:".to_string()
    } else if filename.contains("postgresql") || filename.contains("postgres") {
        // Use a dummy URI that won't actually connect
        "postgresql://localhost/adbc_test".to_string()
    } else if filename.contains("mysql") {
        // Use a dummy URI that won't actually connect
        "mysql://localhost/adbc_test".to_string()
    } else if filename.contains("snowflake") {
        // Snowflake needs account/user/password but we'll try anyway
        "snowflake://localhost/adbc_test".to_string()
    } else if filename.contains("flight") || filename.contains("flightsql") {
        // Flight SQL needs a grpc:// URI
        "grpc://localhost:12345".to_string()
    } else {
        // Generic fallback - in-memory or minimal URI
        ":memory:".to_string()
    }
}

/// Extract driver info codes from a loaded ADBC driver library
pub fn extract_info_codes(library_path: &Path) -> Result<Value> {
    use std::panic;

    // Catch panics from driver loading and execution
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| -> Result<Value> {
        // Load the driver from the library path
        let mut driver = ManagedDriver::load_dynamic_from_filename(
            library_path,
            None,  // Use default AdbcDriverInit entrypoint
            AdbcVersion::V100,
        ).map_err(|e| AdbcIndexError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to load driver: {}", e)
        )))?;

    // Get appropriate dummy URI for this driver
    let uri = get_dummy_uri_for_driver(library_path);

    // Create a database with the URI option
    let opts = vec![(OptionDatabase::Uri, OptionValue::String(uri))];
    let database = driver.new_database_with_opts(opts)
        .map_err(|e| AdbcIndexError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to create database: {}", e)
        )))?;

    // Create a connection
    let connection = database.new_connection()
        .map_err(|e| AdbcIndexError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to create connection: {}", e)
        )))?;

    // Query all info codes
    let info_codes: HashSet<InfoCode> = [
        // Vendor info codes
        InfoCode::VendorName,
        InfoCode::VendorVersion,
        InfoCode::VendorArrowVersion,
        InfoCode::VendorSql,
        InfoCode::VendorSubstrait,
        InfoCode::VendorSubstraitMinVersion,
        InfoCode::VendorSubstraitMaxVersion,
        // Driver info codes
        InfoCode::DriverName,
        InfoCode::DriverVersion,
        InfoCode::DriverArrowVersion,
        InfoCode::DriverAdbcVersion,
    ].iter().cloned().collect();

    let reader = connection.get_info(Some(info_codes))
        .map_err(|e| AdbcIndexError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to get info codes: {}", e)
        )))?;

    // Convert the result to JSON
    let mut result = json!({});

    // Read all batches from the reader
    for batch_result in reader {
        let batch = batch_result.map_err(|e| AdbcIndexError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to read batch: {}", e)
        )))?;

        // Process each row in the batch
        // Schema: (info_name: u32, info_value: union)
        let num_rows = batch.num_rows();

        for row_idx in 0..num_rows {
            // Extract info code and value from the batch
            // The schema is defined in schemas.rs but we need to handle it generically
            if let Some(info_name_col) = batch.column_by_name("info_name") {
                if let Some(info_name_array) = info_name_col.as_any().downcast_ref::<arrow::array::UInt32Array>() {
                    let info_code: u32 = info_name_array.value(row_idx);
                    if true {
                        // Map the info code to a readable name
                        let code_name = match info_code {
                            ADBC_INFO_VENDOR_NAME => "vendor_name",
                            ADBC_INFO_VENDOR_VERSION => "vendor_version",
                            ADBC_INFO_VENDOR_ARROW_VERSION => "vendor_arrow_version",
                            ADBC_INFO_VENDOR_SQL => "vendor_sql",
                            ADBC_INFO_VENDOR_SUBSTRAIT => "vendor_substrait",
                            ADBC_INFO_VENDOR_SUBSTRAIT_MIN_VERSION => "vendor_substrait_min_version",
                            ADBC_INFO_VENDOR_SUBSTRAIT_MAX_VERSION => "vendor_substrait_max_version",
                            ADBC_INFO_DRIVER_NAME => "driver_name",
                            ADBC_INFO_DRIVER_VERSION => "driver_version",
                            ADBC_INFO_DRIVER_ARROW_VERSION => "driver_arrow_version",
                            ADBC_INFO_DRIVER_ADBC_VERSION => "driver_adbc_version",
                            _ => continue,
                        };

                        // Extract the value from the union column
                        if let Some(info_value_col) = batch.column_by_name("info_value") {
                            let value = extract_union_value(info_value_col, row_idx);
                            if let Some(v) = value {
                                result[code_name] = v;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(result)
    }));

    // If panic occurred, return error
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(AdbcIndexError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Panic occurred while extracting info codes from: {}", library_path.display())
        ))),
    }
}

/// Extract value from a union array at a given index
fn extract_union_value(array: &arrow::array::ArrayRef, index: usize) -> Option<Value> {
    use arrow::array::*;

    // Try different array types
    if let Some(str_array) = array.as_any().downcast_ref::<StringArray>() {
        if !str_array.is_null(index) {
            return Some(json!(str_array.value(index)));
        }
    }

    if let Some(int_array) = array.as_any().downcast_ref::<Int64Array>() {
        if !int_array.is_null(index) {
            return Some(json!(int_array.value(index)));
        }
    }

    if let Some(bool_array) = array.as_any().downcast_ref::<BooleanArray>() {
        if !bool_array.is_null(index) {
            return Some(json!(bool_array.value(index)));
        }
    }

    // Handle union arrays (the actual schema uses dense union)
    if let Some(union_array) = array.as_any().downcast_ref::<UnionArray>() {
        let type_id = union_array.type_id(index);
        let value_offset = union_array.value_offset(index);

        // Get the child array for this type
        let child_array = union_array.child(type_id);

        // Recursively extract the value
        return extract_union_value(child_array, value_offset);
    }

    None
}

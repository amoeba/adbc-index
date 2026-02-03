use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use std::sync::Arc;

/// Create the Arrow schema for driver records (one row per driver)
pub fn create_drivers_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("name", DataType::Utf8, false),
        Field::new("repo_owner", DataType::Utf8, false),
        Field::new("repo_name", DataType::Utf8, false),
        Field::new("release_count", DataType::Int64, false),
        Field::new("library_count", DataType::Int64, false),
        Field::new(
            "first_release_date",
            DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
            false,
        ),
        Field::new("first_release_version", DataType::Utf8, true),
        Field::new(
            "latest_release_date",
            DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
            false,
        ),
        Field::new("latest_release_version", DataType::Utf8, true),
    ]))
}

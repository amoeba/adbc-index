use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use std::sync::Arc;

/// Create the Arrow schema for library records (one row per shared library)
pub fn create_libraries_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("name", DataType::Utf8, false),
        Field::new("release_tag", DataType::Utf8, false),
        Field::new("version", DataType::Utf8, true),
        Field::new(
            "published_date",
            DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
            false,
        ),
        Field::new("os", DataType::Utf8, false),
        Field::new(
            "arch",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            false,
        ),
        Field::new("library_name", DataType::Utf8, false),
        Field::new("library_size_bytes", DataType::Int64, false),
        Field::new("library_sha256", DataType::Utf8, false),
        Field::new("artifact_name", DataType::Utf8, false),
        Field::new("artifact_url", DataType::Utf8, false),
    ]))
}

use arrow::array::{ArrayRef, BooleanArray, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use std::sync::Arc;

pub fn info_codes_schema() -> Schema {
    Schema::new(vec![
        Field::new("name", DataType::Utf8, false),
        Field::new("release_tag", DataType::Utf8, false),
        Field::new("version", DataType::Utf8, true),
        Field::new("os", DataType::Utf8, false),
        Field::new("arch", DataType::Utf8, false),
        Field::new("library_name", DataType::Utf8, false),
        Field::new("success", DataType::Boolean, false),
        Field::new("error_message", DataType::Utf8, true),
        Field::new("info_codes", DataType::Utf8, true),
    ])
}

pub fn build_info_codes_batch(
    names: Vec<String>,
    release_tags: Vec<String>,
    versions: Vec<Option<String>>,
    os_vec: Vec<String>,
    arch_vec: Vec<String>,
    library_names: Vec<String>,
    success: Vec<bool>,
    error_messages: Vec<Option<String>>,
    info_codes: Vec<Option<String>>,
) -> Vec<ArrayRef> {
    vec![
        Arc::new(StringArray::from(names)) as ArrayRef,
        Arc::new(StringArray::from(release_tags)) as ArrayRef,
        Arc::new(StringArray::from(versions)) as ArrayRef,
        Arc::new(StringArray::from(os_vec)) as ArrayRef,
        Arc::new(StringArray::from(arch_vec)) as ArrayRef,
        Arc::new(StringArray::from(library_names)) as ArrayRef,
        Arc::new(BooleanArray::from(success)) as ArrayRef,
        Arc::new(StringArray::from(error_messages)) as ArrayRef,
        Arc::new(StringArray::from(info_codes)) as ArrayRef,
    ]
}

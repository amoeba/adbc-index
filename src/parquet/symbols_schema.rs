use arrow::array::{ArrayRef, BooleanArray, Int64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use std::sync::Arc;

pub fn symbols_schema() -> Schema {
    Schema::new(vec![
        Field::new("name", DataType::Utf8, false),
        Field::new("release_tag", DataType::Utf8, false),
        Field::new("version", DataType::Utf8, true),
        Field::new("os", DataType::Utf8, false),
        Field::new("arch", DataType::Utf8, false),
        Field::new("library_name", DataType::Utf8, false),
        Field::new("symbol", DataType::Utf8, false),
        Field::new("symbol_index", DataType::Int64, false),
        Field::new("is_stub", DataType::Boolean, false),
        Field::new("constant_return", DataType::Int64, true),
        Field::new("return_status", DataType::Utf8, true),
    ])
}

pub fn build_symbols_batch(
    names: Vec<String>,
    release_tags: Vec<String>,
    versions: Vec<Option<String>>,
    os_vec: Vec<String>,
    arch_vec: Vec<String>,
    library_names: Vec<String>,
    symbols: Vec<String>,
    symbol_indices: Vec<i64>,
    is_stubs: Vec<bool>,
    constant_returns: Vec<Option<i64>>,
    return_statuses: Vec<Option<String>>,
) -> Vec<ArrayRef> {
    vec![
        Arc::new(StringArray::from(names)) as ArrayRef,
        Arc::new(StringArray::from(release_tags)) as ArrayRef,
        Arc::new(StringArray::from(versions)) as ArrayRef,
        Arc::new(StringArray::from(os_vec)) as ArrayRef,
        Arc::new(StringArray::from(arch_vec)) as ArrayRef,
        Arc::new(StringArray::from(library_names)) as ArrayRef,
        Arc::new(StringArray::from(symbols)) as ArrayRef,
        Arc::new(Int64Array::from(symbol_indices)) as ArrayRef,
        Arc::new(BooleanArray::from(is_stubs)) as ArrayRef,
        Arc::new(Int64Array::from(constant_returns)) as ArrayRef,
        Arc::new(StringArray::from(return_statuses)) as ArrayRef,
    ]
}

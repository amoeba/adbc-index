use arrow::array::{ArrayRef, BooleanArray, Int64Array, ListBuilder, StringArray, StringBuilder};
use arrow::datatypes::{DataType, Field, Schema};
use std::sync::Arc;

/// Data for building a symbols batch
pub struct SymbolsBatchData {
    pub names: Vec<String>,
    pub release_tags: Vec<String>,
    pub versions: Vec<Option<String>>,
    pub os_vec: Vec<String>,
    pub arch_vec: Vec<Vec<String>>,
    pub library_names: Vec<String>,
    pub symbols: Vec<String>,
    pub symbol_indices: Vec<i64>,
    pub is_stubs: Vec<bool>,
    pub constant_returns: Vec<Option<i64>>,
    pub return_statuses: Vec<Option<String>>,
}

pub fn symbols_schema() -> Schema {
    Schema::new(vec![
        Field::new("name", DataType::Utf8, false),
        Field::new("release_tag", DataType::Utf8, false),
        Field::new("version", DataType::Utf8, true),
        Field::new("os", DataType::Utf8, false),
        Field::new(
            "arch",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            false,
        ),
        Field::new("library_name", DataType::Utf8, false),
        Field::new("symbol", DataType::Utf8, false),
        Field::new("symbol_index", DataType::Int64, false),
        Field::new("is_stub", DataType::Boolean, false),
        Field::new("constant_return", DataType::Int64, true),
        Field::new("return_status", DataType::Utf8, true),
    ])
}

pub fn build_symbols_batch(data: SymbolsBatchData) -> Vec<ArrayRef> {
    // Build arch list array
    let mut arch_builder = ListBuilder::new(StringBuilder::new());
    for arch_list in data.arch_vec {
        let values_builder = arch_builder.values();
        for arch_val in arch_list {
            values_builder.append_value(&arch_val);
        }
        arch_builder.append(true);
    }
    let arch_array = arch_builder.finish();

    vec![
        Arc::new(StringArray::from(data.names)) as ArrayRef,
        Arc::new(StringArray::from(data.release_tags)) as ArrayRef,
        Arc::new(StringArray::from(data.versions)) as ArrayRef,
        Arc::new(StringArray::from(data.os_vec)) as ArrayRef,
        Arc::new(arch_array) as ArrayRef,
        Arc::new(StringArray::from(data.library_names)) as ArrayRef,
        Arc::new(StringArray::from(data.symbols)) as ArrayRef,
        Arc::new(Int64Array::from(data.symbol_indices)) as ArrayRef,
        Arc::new(BooleanArray::from(data.is_stubs)) as ArrayRef,
        Arc::new(Int64Array::from(data.constant_returns)) as ArrayRef,
        Arc::new(StringArray::from(data.return_statuses)) as ArrayRef,
    ]
}

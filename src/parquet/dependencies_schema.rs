use arrow::array::{ArrayRef, BooleanArray, Int64Array, ListBuilder, StringArray, StringBuilder};
use arrow::datatypes::{DataType, Field, Schema};
use std::sync::Arc;

/// Data for building a dependencies batch
pub struct DependenciesBatchData {
    pub names: Vec<String>,
    pub release_tags: Vec<String>,
    pub versions: Vec<Option<String>>,
    pub os_vec: Vec<String>,
    pub arch_vec: Vec<Vec<String>>,
    pub library_names: Vec<String>,
    pub dependencies: Vec<String>,
    pub dependency_basenames: Vec<String>,
    pub dependency_indices: Vec<i64>,
    pub is_systems: Vec<bool>,
    pub is_latests: Vec<bool>,
}

pub fn dependencies_schema() -> Schema {
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
        Field::new("dependency", DataType::Utf8, false),
        Field::new("dependency_basename", DataType::Utf8, false),
        Field::new("dependency_index", DataType::Int64, false),
        Field::new("is_system", DataType::Boolean, false),
        Field::new("is_latest", DataType::Boolean, false),
    ])
}

pub fn build_dependencies_batch(data: DependenciesBatchData) -> Vec<ArrayRef> {
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
        Arc::new(StringArray::from(data.dependencies)) as ArrayRef,
        Arc::new(StringArray::from(data.dependency_basenames)) as ArrayRef,
        Arc::new(Int64Array::from(data.dependency_indices)) as ArrayRef,
        Arc::new(BooleanArray::from(data.is_systems)) as ArrayRef,
        Arc::new(BooleanArray::from(data.is_latests)) as ArrayRef,
    ]
}

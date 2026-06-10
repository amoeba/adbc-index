use crate::error::Result;
use crate::models::DependencyRecord;
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use super::dependencies_schema::{build_dependencies_batch, dependencies_schema, DependenciesBatchData};

pub struct DependenciesWriter {
    writer: ArrowWriter<File>,
    batch: Vec<DependencyRecord>,
    batch_size: usize,
}

impl DependenciesWriter {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::create(path)?;
        let schema = Arc::new(dependencies_schema());
        let props = WriterProperties::builder()
            .set_compression(parquet::basic::Compression::SNAPPY)
            .build();
        let writer = ArrowWriter::try_new(file, schema, Some(props))?;

        Ok(Self {
            writer,
            batch: Vec::new(),
            batch_size: 10000,
        })
    }

    pub fn add_record(&mut self, record: DependencyRecord) -> Result<()> {
        self.batch.push(record);

        if self.batch.len() >= self.batch_size {
            self.flush()?;
        }

        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.batch.is_empty() {
            return Ok(());
        }

        let mut names = Vec::new();
        let mut release_tags = Vec::new();
        let mut versions = Vec::new();
        let mut os_vec = Vec::new();
        let mut arch_vec = Vec::new();
        let mut library_names = Vec::new();
        let mut dependencies = Vec::new();
        let mut dependency_basenames = Vec::new();
        let mut dependency_indices = Vec::new();
        let mut is_systems = Vec::new();
        let mut is_latests = Vec::new();

        for record in &self.batch {
            names.push(record.name.clone());
            release_tags.push(record.release_tag.clone());
            versions.push(record.version.clone());
            os_vec.push(record.os.clone());
            arch_vec.push(record.arch.clone());
            library_names.push(record.library_name.clone());
            dependencies.push(record.dependency.clone());
            dependency_basenames.push(record.dependency_basename.clone());
            dependency_indices.push(record.dependency_index);
            is_systems.push(record.is_system);
            is_latests.push(record.is_latest);
        }

        let arrays = build_dependencies_batch(DependenciesBatchData {
            names,
            release_tags,
            versions,
            os_vec,
            arch_vec,
            library_names,
            dependencies,
            dependency_basenames,
            dependency_indices,
            is_systems,
            is_latests,
        });

        let batch = RecordBatch::try_new(Arc::new(dependencies_schema()), arrays)?;
        self.writer.write(&batch)?;
        self.batch.clear();

        Ok(())
    }

    pub fn close(mut self) -> Result<()> {
        self.flush()?;
        self.writer.close()?;
        Ok(())
    }
}

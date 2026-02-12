use crate::error::Result;
use crate::models::InfoCodeRecord;
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use super::info_codes_schema::{build_info_codes_batch, info_codes_schema};

pub struct InfoCodesWriter {
    writer: ArrowWriter<File>,
    batch: Vec<InfoCodeRecord>,
    batch_size: usize,
}

impl InfoCodesWriter {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::create(path)?;
        let schema = Arc::new(info_codes_schema());
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

    pub fn add_record(&mut self, record: InfoCodeRecord) -> Result<()> {
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
        let mut success = Vec::new();
        let mut error_messages = Vec::new();
        let mut info_codes = Vec::new();

        for record in &self.batch {
            names.push(record.name.clone());
            release_tags.push(record.release_tag.clone());
            versions.push(record.version.clone());
            os_vec.push(record.os.clone());
            arch_vec.push(record.arch.clone());
            library_names.push(record.library_name.clone());
            success.push(record.success);
            error_messages.push(record.error_message.clone());
            info_codes.push(record.info_codes.clone());
        }

        let arrays = build_info_codes_batch(
            names,
            release_tags,
            versions,
            os_vec,
            arch_vec,
            library_names,
            success,
            error_messages,
            info_codes,
        );

        let batch = RecordBatch::try_new(Arc::new(info_codes_schema()), arrays)?;
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

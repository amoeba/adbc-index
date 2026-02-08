use crate::error::Result;
use crate::models::SymbolRecord;
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use super::symbols_schema::{build_symbols_batch, symbols_schema};

pub struct SymbolsWriter {
    writer: ArrowWriter<File>,
    batch: Vec<SymbolRecord>,
    batch_size: usize,
}

impl SymbolsWriter {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::create(path)?;
        let schema = Arc::new(symbols_schema());
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

    pub fn add_record(&mut self, record: SymbolRecord) -> Result<()> {
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
        let mut symbols = Vec::new();
        let mut symbol_indices = Vec::new();

        for record in &self.batch {
            names.push(record.name.clone());
            release_tags.push(record.release_tag.clone());
            versions.push(record.version.clone());
            os_vec.push(record.os.clone());
            arch_vec.push(record.arch.clone());
            library_names.push(record.library_name.clone());
            symbols.push(record.symbol.clone());
            symbol_indices.push(record.symbol_index);
        }

        let arrays = build_symbols_batch(
            names,
            release_tags,
            versions,
            os_vec,
            arch_vec,
            library_names,
            symbols,
            symbol_indices,
        );

        let batch = RecordBatch::try_new(Arc::new(symbols_schema()), arrays)?;
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

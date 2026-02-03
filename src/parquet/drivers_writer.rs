use crate::error::Result;
use crate::models::DriverRecord;
use crate::parquet::drivers_schema::create_drivers_schema;
use arrow::array::{ArrayRef, Int64Array, StringArray, TimestampMillisecondArray};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

const BATCH_SIZE: usize = 1024;

pub struct DriversWriter {
    writer: ArrowWriter<File>,
    schema: Arc<arrow::datatypes::Schema>,
    buffer: Vec<DriverRecord>,
}

impl DriversWriter {
    pub fn new(path: &Path) -> Result<Self> {
        let schema = create_drivers_schema();
        let file = File::create(path)?;

        let props = WriterProperties::builder()
            .set_compression(Compression::SNAPPY)
            .build();

        let writer = ArrowWriter::try_new(file, schema.clone(), Some(props))?;

        Ok(Self {
            writer,
            schema,
            buffer: Vec::new(),
        })
    }

    pub fn add_record(&mut self, record: DriverRecord) -> Result<()> {
        self.buffer.push(record);

        if self.buffer.len() >= BATCH_SIZE {
            self.flush_buffer()?;
        }

        Ok(())
    }

    fn flush_buffer(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let batch = self.create_record_batch()?;
        self.writer.write(&batch)?;
        self.buffer.clear();

        Ok(())
    }

    fn create_record_batch(&self) -> Result<RecordBatch> {
        let names: StringArray = self
            .buffer
            .iter()
            .map(|r| Some(r.name.as_str()))
            .collect();

        let repo_owners: StringArray = self
            .buffer
            .iter()
            .map(|r| Some(r.repo_owner.as_str()))
            .collect();

        let repo_names: StringArray = self
            .buffer
            .iter()
            .map(|r| Some(r.repo_name.as_str()))
            .collect();

        let release_counts: Int64Array = self
            .buffer
            .iter()
            .map(|r| Some(r.release_count))
            .collect();

        let library_counts: Int64Array = self
            .buffer
            .iter()
            .map(|r| Some(r.library_count))
            .collect();

        let first_release_dates = TimestampMillisecondArray::from(
            self.buffer
                .iter()
                .map(|r| Some(r.first_release_date.timestamp_millis()))
                .collect::<Vec<_>>()
        ).with_timezone("UTC");

        let first_release_versions: StringArray = self
            .buffer
            .iter()
            .map(|r| r.first_release_version.as_deref())
            .collect();

        let latest_release_dates = TimestampMillisecondArray::from(
            self.buffer
                .iter()
                .map(|r| Some(r.latest_release_date.timestamp_millis()))
                .collect::<Vec<_>>()
        ).with_timezone("UTC");

        let latest_release_versions: StringArray = self
            .buffer
            .iter()
            .map(|r| r.latest_release_version.as_deref())
            .collect();

        let columns: Vec<ArrayRef> = vec![
            Arc::new(names),
            Arc::new(repo_owners),
            Arc::new(repo_names),
            Arc::new(release_counts),
            Arc::new(library_counts),
            Arc::new(first_release_dates),
            Arc::new(first_release_versions),
            Arc::new(latest_release_dates),
            Arc::new(latest_release_versions),
        ];

        Ok(RecordBatch::try_new(self.schema.clone(), columns)?)
    }

    pub fn close(mut self) -> Result<()> {
        self.flush_buffer()?;
        self.writer.close()?;
        Ok(())
    }
}

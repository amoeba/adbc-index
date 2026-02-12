use crate::error::Result;
use crate::models::ReleaseRecord;
use crate::parquet::releases_schema::create_releases_schema;
use arrow::array::{ArrayRef, StringArray, TimestampMillisecondArray};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

const BATCH_SIZE: usize = 1024;

pub struct ReleasesWriter {
    writer: ArrowWriter<File>,
    schema: Arc<arrow::datatypes::Schema>,
    buffer: Vec<ReleaseRecord>,
}

impl ReleasesWriter {
    pub fn new(path: &Path) -> Result<Self> {
        let schema = create_releases_schema();
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

    pub fn add_record(&mut self, record: ReleaseRecord) -> Result<()> {
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
        let names: StringArray = self.buffer.iter().map(|r| Some(r.name.as_str())).collect();

        let release_tags: StringArray = self
            .buffer
            .iter()
            .map(|r| Some(r.release_tag.as_str()))
            .collect();

        let versions: StringArray = self.buffer.iter().map(|r| r.version.as_deref()).collect();

        let published_dates = TimestampMillisecondArray::from(
            self.buffer
                .iter()
                .map(|r| Some(r.published_date.timestamp_millis()))
                .collect::<Vec<_>>(),
        )
        .with_timezone("UTC");

        let release_urls: StringArray = self
            .buffer
            .iter()
            .map(|r| Some(r.release_url.as_str()))
            .collect();

        // Build os list array
        use arrow::array::{ListBuilder, StringBuilder};

        let mut os_builder = ListBuilder::new(StringBuilder::new());
        for record in &self.buffer {
            let values_builder = os_builder.values();
            for os_val in &record.os {
                values_builder.append_value(os_val);
            }
            os_builder.append(true);
        }
        let os = os_builder.finish();

        // Build arch list array
        let mut arch_builder = ListBuilder::new(StringBuilder::new());
        for record in &self.buffer {
            let values_builder = arch_builder.values();
            for arch_val in &record.arch {
                values_builder.append_value(arch_val);
            }
            arch_builder.append(true);
        }
        let arch = arch_builder.finish();

        let columns: Vec<ArrayRef> = vec![
            Arc::new(names),
            Arc::new(release_tags),
            Arc::new(versions),
            Arc::new(published_dates),
            Arc::new(release_urls),
            Arc::new(os),
            Arc::new(arch),
        ];

        Ok(RecordBatch::try_new(self.schema.clone(), columns)?)
    }

    pub fn close(mut self) -> Result<()> {
        self.flush_buffer()?;
        self.writer.close()?;
        Ok(())
    }
}

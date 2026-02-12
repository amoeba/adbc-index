use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::sync::Arc;

/// Hierarchical progress tracker for CLI commands
pub struct ProgressTracker {
    multi: Arc<MultiProgress>,
    main_bar: ProgressBar,
}

impl ProgressTracker {
    /// Create a new progress tracker with a main progress bar
    pub fn new(total: u64, prefix: &str) -> Self {
        let multi = Arc::new(MultiProgress::new());
        let main_bar = multi.add(ProgressBar::new(total));

        main_bar.set_style(
            ProgressStyle::default_bar()
                .template(&format!(
                    "{{spinner}} {} [{{bar:40}}] {{pos}}/{{len}} {{msg}}",
                    prefix
                ))
                .unwrap()
                .progress_chars("█▓░"),
        );

        Self { multi, main_bar }
    }

    /// Update the main progress bar message
    pub fn set_message(&self, msg: &str) {
        self.main_bar.set_message(msg.to_string());
    }

    /// Increment the main progress bar
    pub fn inc(&self, delta: u64) {
        self.main_bar.inc(delta);
    }

    /// Set position directly
    pub fn set_position(&self, pos: u64) {
        self.main_bar.set_position(pos);
    }

    /// Create a sub-progress bar for a specific task with known total
    #[allow(dead_code)]
    pub fn add_subtask(&self, total: u64, name: &str) -> ProgressBar {
        let pb = self.multi.add(ProgressBar::new(total));

        pb.set_style(
            ProgressStyle::default_bar()
                .template(&format!(
                    "  ├─ {} [{{bar:30}}] {{pos}}/{{len}} {{msg}}",
                    name
                ))
                .unwrap()
                .progress_chars("█▓░"),
        );

        pb
    }

    /// Create a spinner subtask for tasks without known total
    pub fn add_spinner(&self, name: &str, message: &str) -> ProgressBar {
        let pb = self.multi.add(ProgressBar::new_spinner());

        pb.set_style(
            ProgressStyle::default_spinner()
                .template(&format!("  ├─ {{spinner}} {} {{msg}}", name))
                .unwrap(),
        );
        pb.set_message(message.to_string());
        pb.enable_steady_tick(std::time::Duration::from_millis(100));

        pb
    }

    /// Finish the main progress bar with a message
    pub fn finish_with_message(&self, msg: &str) {
        self.main_bar.finish_with_message(msg.to_string());
    }

    /// Finish the main progress bar and clear it
    #[allow(dead_code)]
    pub fn finish_and_clear(&self) {
        self.main_bar.finish_and_clear();
    }

    /// Get a reference to the MultiProgress for advanced usage
    pub fn multi(&self) -> Arc<MultiProgress> {
        self.multi.clone()
    }
}

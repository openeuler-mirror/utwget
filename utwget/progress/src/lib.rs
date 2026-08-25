pub mod bar;
pub mod dot;
pub mod silent;
pub mod verbose;

pub use ut_core::ProgressStyle;

use std::time::Duration;

pub trait ProgressDisplay: Send {
    fn begin(&mut self, url: &str, total_size: Option<u64>, resume_from: Option<u64>);
    fn update(&mut self, downloaded: u64, elapsed: Duration);
    fn finish(&mut self, status: FinishStatus);
    fn set_redirected(&mut self, new_url: &str);
    fn reset(&mut self);
    fn is_interactive(&self) -> bool;
}

#[derive(Debug)]
pub enum FinishStatus {
    Success { downloaded: u64, elapsed: Duration },
    Error(String),
    AlreadyExists,
    NotModified,
    Redirected(String),
}

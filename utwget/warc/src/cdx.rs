//! CDX index helpers extracted from `writer.rs` (arch review 3.2):
//! dedup-table parsing (`--warc-dedup`), CDX line formatting, and CDX
//! file writing — all mirroring GNU wget's warc.c CDX handling.

use std::io::Write as _;
use std::path::Path;

use crate::{Result, WarcError};

/// CDX header line, matching GNU wget (warc.c:938).
pub(crate) const CDX_HEADER: &str = " CDX a b a m s k r M V g u\n";

/// Parse a CDX dedup file into (payload-digest → (uuid, date)) and
/// (payload-digest → original URI) tables.
///
/// Field layout (11 fields): url ts url mime response_code checksum
/// redirect - offset filename record_uuid.
pub(crate) fn parse_cdx_dedup(
    path: &Path,
) -> Result<(std::collections::HashMap<String, (String, String)>, std::collections::HashMap<String, String>)> {
    let data = std::fs::read_to_string(path).map_err(WarcError::Io)?;
    let mut table = std::collections::HashMap::new();
    let mut urls = std::collections::HashMap::new();
    for line in data.lines() {
        // Skip the CDX header line.
        if line.starts_with(" CDX") || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.len() != 11 {
            continue;
        }
        let url = fields[0];
        let date = fields[1];
        let checksum = fields[5];
        let uuid = fields[10];
        if checksum == "-" || uuid == "-" || uuid.is_empty() {
            continue;
        }
        // Re-add the sha1: prefix stripped when the CDX was written.
        let key = format!("sha1:{}", checksum);
        table.insert(key.clone(), (uuid.to_string(), date.to_string()));
        // Keep the target URI for revisit WARC-Target-URI.
        urls.insert(key, url.to_string());
    }
    log::info!("CDX dedup table loaded: {} entries from {}", table.len(), path.display());
    Ok((table, urls))
}

/// Format one CDX index line (11 space-separated fields).
#[allow(clippy::too_many_arguments)]
pub(crate) fn cdx_line(
    url: &str,
    ts: &str,
    mime: &str,
    response_code: u16,
    checksum: &str,
    redirect: &str,
    offset: u64,
    filename: &str,
    record_id: &str,
) -> String {
    format!(
        "{} {} {} {} {} {} {} - {} {} {}",
        url,
        ts,
        url,
        mime,
        response_code,
        checksum,
        redirect,
        offset,
        filename,
        record_id,
    )
}

/// Write the accumulated CDX entries to `<warc-file>.cdx`.
pub(crate) fn write_cdx_file(warc_filename: &str, entries: &[String]) -> Result<()> {
    let cdx_name = format!("{}.cdx", warc_filename);
    let mut cdx_file = super::writer::create_restricted_file(Path::new(&cdx_name)).map_err(WarcError::Io)?;
    cdx_file
        .write_all(CDX_HEADER.as_bytes())
        .map_err(WarcError::Io)?;
    for entry in entries {
        cdx_file.write_all(entry.as_bytes()).map_err(WarcError::Io)?;
        cdx_file.write_all(b"\n").map_err(WarcError::Io)?;
    }
    Ok(())
}

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

static RUST_DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);
static UDP_TRACE_ENABLED: AtomicBool = AtomicBool::new(false);
static DEBUG_FLAGS_INIT: OnceLock<()> = OnceLock::new();
static UDP_TRACE_PATH: OnceLock<PathBuf> = OnceLock::new();

fn parse_bool_env(name: &str) -> Option<bool> {
  std::env::var(name).ok().map(|raw| {
    matches!(
      raw.trim().to_ascii_lowercase().as_str(),
      "1" | "true" | "yes" | "on"
    )
  })
}

fn init_flags_once() {
  DEBUG_FLAGS_INIT.get_or_init(|| {
    if let Some(v) = parse_bool_env("YAT_RUST_DEBUG") {
      RUST_DEBUG_ENABLED.store(v, Ordering::Relaxed);
    }
    if let Some(v) = parse_bool_env("YAT_UDP_TRACE") {
      UDP_TRACE_ENABLED.store(v, Ordering::Relaxed);
    }
  });
}

pub fn set_rust_debug_enabled(enabled: bool) {
  init_flags_once();
  RUST_DEBUG_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn set_udp_trace_enabled(enabled: bool) {
  init_flags_once();
  UDP_TRACE_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_udp_trace_enabled() -> bool {
  init_flags_once();
  UDP_TRACE_ENABLED.load(Ordering::Relaxed)
}

pub fn udp_trace_log_path() -> &'static Path {
  UDP_TRACE_PATH.get_or_init(|| {
    if let Ok(raw) = std::env::var("YAT_UDP_TRACE_FILE") {
      let trimmed = raw.trim();
      if !trimmed.is_empty() {
        return PathBuf::from(trimmed);
      }
    }
    std::env::temp_dir().join("yat-udp-trace.log")
  })
}

pub fn clear_udp_trace_log_file() -> std::io::Result<()> {
  let path = udp_trace_log_path();
  match fs::remove_file(path) {
    Ok(()) => Ok(()),
    Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
    Err(err) => Err(err),
  }
}

pub fn append_udp_trace_line(line: &str) {
  if !is_udp_trace_enabled() {
    return;
  }

  let path = udp_trace_log_path();
  if let Some(parent) = path.parent() {
    let _ = fs::create_dir_all(parent);
  }

  if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
    let ts = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map(|d| d.as_millis())
      .unwrap_or(0);
    let _ = writeln!(file, "{} {}", ts, line);
  }
}

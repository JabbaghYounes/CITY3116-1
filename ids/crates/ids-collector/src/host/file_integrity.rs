use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use ids_common::config::FileIntegrityConfig;
use ids_common::types::{FileChangeEvent, FileChangeType, HostEvent, SecurityEvent};

/// File Integrity Monitor (FIM).
///
/// Watches configured directories for filesystem changes, computes SHA-256
/// hashes of affected files, and emits `FileChangeEvent` records through a
/// channel. On startup it optionally builds a baseline of all monitored files
/// so that subsequent modifications can report the old hash.
pub struct FileIntegrityMonitor {
    config: FileIntegrityConfig,
    /// Baseline mapping from canonical path to hex-encoded SHA-256 hash.
    baseline: HashMap<PathBuf, String>,
}

impl FileIntegrityMonitor {
    /// Create a new monitor from the given configuration.
    pub fn new(config: FileIntegrityConfig) -> Self {
        Self {
            config,
            baseline: HashMap::new(),
        }
    }

    /// Build the initial hash baseline for all regular files under the
    /// configured watch paths (non-recursive single-level scan for
    /// directories, direct hash for files).
    pub fn build_baseline(&mut self) -> Result<()> {
        info!("Building file integrity baseline");

        let watch_paths: Vec<PathBuf> = self.config.watch_paths.clone();
        for watch_path in &watch_paths {
            if watch_path.is_file() {
                if let Some(hash) = compute_sha256(watch_path) {
                    debug!(path = %watch_path.display(), hash = %hash, "Baselined file");
                    self.baseline.insert(watch_path.clone(), hash);
                }
            } else if watch_path.is_dir() {
                self.baseline_directory(watch_path)?;
            } else {
                warn!(path = %watch_path.display(), "Watch path does not exist, skipping baseline");
            }
        }

        info!(file_count = self.baseline.len(), "Baseline complete");
        Ok(())
    }

    /// Recursively walk a directory and hash every regular file.
    fn baseline_directory(&mut self, dir: &Path) -> Result<()> {
        let walker = walkdir(dir);
        for entry in walker {
            if entry.is_file() {
                if let Some(hash) = compute_sha256(&entry) {
                    self.baseline.insert(entry, hash);
                }
            }
        }
        Ok(())
    }

    /// Start the file-system watcher and run until the sender is dropped.
    ///
    /// This is an async method that spawns a blocking `notify` watcher and
    /// bridges events into the tokio world via an internal mpsc channel.
    pub async fn start(mut self, tx: mpsc::Sender<SecurityEvent>) -> Result<()> {
        if self.config.baseline_on_startup {
            self.build_baseline()?;
        }

        // Internal synchronous channel for the notify callback.
        let (notify_tx, mut notify_rx) = mpsc::channel::<Event>(512);

        let mut watcher: RecommendedWatcher = notify::recommended_watcher(
            move |res: std::result::Result<Event, notify::Error>| match res {
                Ok(event) => {
                    let _ = notify_tx.blocking_send(event);
                }
                Err(e) => {
                    error!(error = %e, "Filesystem watcher error");
                }
            },
        )
        .context("Failed to create filesystem watcher")?;

        for path in &self.config.watch_paths {
            if path.exists() {
                watcher
                    .watch(path, RecursiveMode::Recursive)
                    .with_context(|| format!("Failed to watch path: {}", path.display()))?;
                info!(path = %path.display(), "Watching path for changes");
            } else {
                warn!(path = %path.display(), "Watch path does not exist, skipping");
            }
        }

        info!("File integrity monitor running");

        // Keep watcher alive by holding the binding. Process events.
        while let Some(event) = notify_rx.recv().await {
            let change_type = match event.kind {
                EventKind::Create(_) => FileChangeType::Created,
                EventKind::Modify(_) => FileChangeType::Modified,
                EventKind::Remove(_) => FileChangeType::Deleted,
                _ => continue,
            };

            for path in event.paths {
                let old_hash = self.baseline.get(&path).cloned();
                let new_hash = if change_type != FileChangeType::Deleted {
                    compute_sha256(&path)
                } else {
                    None
                };

                // Skip if the hash hasn't actually changed (e.g. metadata-only
                // modify events).
                if change_type == FileChangeType::Modified
                    && old_hash.is_some()
                    && old_hash == new_hash
                {
                    continue;
                }

                // Read file permissions (Unix).
                let file_permissions = file_permissions(&path);

                let change_event = FileChangeEvent {
                    timestamp: Utc::now(),
                    path: path.clone(),
                    change_type,
                    old_hash: old_hash.clone(),
                    new_hash: new_hash.clone(),
                    file_permissions,
                };

                debug!(
                    path = %path.display(),
                    change = ?change_type,
                    "File change detected"
                );

                // Update baseline.
                match change_type {
                    FileChangeType::Deleted => {
                        self.baseline.remove(&path);
                    }
                    _ => {
                        if let Some(ref h) = new_hash {
                            self.baseline.insert(path.clone(), h.clone());
                        }
                    }
                }

                let event = SecurityEvent::Host(HostEvent::FileChange(change_event));
                if tx.send(event).await.is_err() {
                    debug!("Receiver dropped — stopping file integrity monitor");
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    /// Return the current baseline (useful for testing / diagnostics).
    pub fn baseline(&self) -> &HashMap<PathBuf, String> {
        &self.baseline
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the SHA-256 digest of a file, returning the hex string.
/// Returns `None` if the file cannot be read.
fn compute_sha256(path: &Path) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let digest = hasher.finalize();
    Some(format!("{:x}", digest))
}

/// Simple recursive directory walker (avoids pulling in the `walkdir` crate).
fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                results.extend(walkdir(&path));
            } else if path.is_file() {
                results.push(path);
            }
        }
    }
    results
}

/// Read Unix file permissions, returning the mode bits.
#[cfg(unix)]
fn file_permissions(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode())
}

#[cfg(not(unix))]
fn file_permissions(_path: &Path) -> Option<u32> {
    None
}

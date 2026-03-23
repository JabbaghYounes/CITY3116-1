//! CNN+LSTM inference via a Python subprocess running ONNX Runtime.
//!
//! Spawns a Python process that loads the ONNX model and scaler, then
//! communicates via JSON Lines over stdin/stdout. This avoids native ONNX
//! Runtime build dependencies in Rust while using the already-installed
//! Python `onnxruntime` package.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use anyhow::{bail, Context, Result};
use ids_common::types::AttackCategory;
use tracing::{error, info};

/// Label names matching the 5-class training scheme (index → category).
const CLASS_NAMES: [AttackCategory; 5] = [
    AttackCategory::Normal,
    AttackCategory::DoS,
    AttackCategory::Probe,
    AttackCategory::R2L,
    AttackCategory::U2R,
];

/// Prediction result from the ML inference pipeline.
#[derive(Debug, Clone)]
pub struct Prediction {
    /// Predicted attack category.
    pub category: AttackCategory,
    /// Softmax confidence for the predicted class (0.0–1.0).
    pub confidence: f64,
    /// Index of the predicted class.
    pub class_index: usize,
    /// Which model produced this prediction ("cnn-lstm" or "modbus-anomaly").
    pub model_source: String,
}

/// CNN+LSTM model wrapper that delegates inference to a Python subprocess.
pub struct CnnLstmClassifier {
    child: Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
    n_features: usize,
}

impl CnnLstmClassifier {
    /// Spawn the Python inference server and load the model.
    ///
    /// `model_path` should point to the `.onnx` file. `scaler_path` points
    /// to the `scaler.json` file.
    pub fn load(model_path: &Path, scaler_path: &Path) -> Result<Self> {
        // Find the inference_server.py script relative to the binary or in
        // the source tree.
        let script = find_inference_script()
            .context("could not find inference_server.py")?;

        info!(
            script = %script.display(),
            model = %model_path.display(),
            scaler = %scaler_path.display(),
            "Spawning Python inference server"
        );

        let mut child = Command::new("python3")
            .arg(&script)
            .arg(model_path)
            .arg(scaler_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("failed to spawn python3 inference server")?;

        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout);

        // Wait for the "ready" message
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .context("failed to read ready message from inference server")?;

        let ready: serde_json::Value =
            serde_json::from_str(line.trim()).context("invalid ready message")?;

        if ready.get("status").and_then(|v| v.as_str()) != Some("ready") {
            bail!(
                "inference server did not report ready: {}",
                line.trim()
            );
        }

        let n_features = ready
            .get("n_features")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;

        info!(n_features, "CNN+LSTM inference server ready");

        Ok(Self {
            child,
            stdin,
            reader,
            n_features,
        })
    }

    /// Number of input features this model expects.
    pub fn n_features(&self) -> usize {
        self.n_features
    }

    /// Run inference on a single feature vector.
    ///
    /// The input `features` slice must have exactly `n_features` elements
    /// (raw, unscaled values — scaling is done by the Python server).
    pub fn predict(&mut self, features: &[f64]) -> Result<Prediction> {
        assert_eq!(
            features.len(),
            self.n_features,
            "expected {} features, got {}",
            self.n_features,
            features.len()
        );

        // Send request
        let req = serde_json::json!({ "features": features });
        writeln!(self.stdin, "{}", req).context("failed to write to inference server")?;
        self.stdin.flush().context("failed to flush stdin")?;

        // Read response
        let mut line = String::new();
        self.reader
            .read_line(&mut line)
            .context("failed to read inference response")?;

        let resp: serde_json::Value =
            serde_json::from_str(line.trim()).context("invalid inference response")?;

        if let Some(err) = resp.get("error").and_then(|v| v.as_str()) {
            bail!("inference error: {}", err);
        }

        let class_index = resp
            .get("class")
            .and_then(|v| v.as_u64())
            .context("missing 'class' in response")? as usize;

        let confidence = resp
            .get("confidence")
            .and_then(|v| v.as_f64())
            .context("missing 'confidence' in response")?;

        let category = if class_index < CLASS_NAMES.len() {
            CLASS_NAMES[class_index]
        } else {
            AttackCategory::Unknown
        };

        let model_source = resp
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("cnn-lstm")
            .to_string();

        Ok(Prediction {
            category,
            confidence,
            class_index,
            model_source,
        })
    }
}

impl Drop for CnnLstmClassifier {
    fn drop(&mut self) {
        // Kill the Python process and wait for it to exit.
        if let Err(e) = self.child.kill() {
            error!(error = %e, "failed to kill inference server");
        }
        let _ = self.child.wait();
    }
}

/// Find the inference_server.py script.
///
/// Searches in order:
/// 1. Next to the running binary
/// 2. In the source tree (for development)
/// 3. In the current directory
fn find_inference_script() -> Option<std::path::PathBuf> {
    // Next to the binary
    if let Ok(exe) = std::env::current_exe() {
        let beside_exe = exe.parent().unwrap().join("inference_server.py");
        if beside_exe.exists() {
            return Some(beside_exe);
        }
    }

    // Source tree locations
    let candidates = [
        "crates/ids-engine/src/inference_server.py",
        "ids/crates/ids-engine/src/inference_server.py",
        "src/inference_server.py",
        "inference_server.py",
    ];
    for c in &candidates {
        let p = std::path::PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }

    None
}

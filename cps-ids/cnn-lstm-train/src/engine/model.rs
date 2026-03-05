//! CNN+LSTM network for tabular IDS classification.
//!
//! Architecture:
//!   Input (batch, n_features)
//!     → reshape to (batch, 1, n_features)
//!     → Conv1d(1, 64, k=3, pad=1) + ReLU + BatchNorm1d
//!     → Conv1d(64, 128, k=3, pad=1) + ReLU + BatchNorm1d
//!     → permute to (batch, n_features, 128)
//!     → LSTM(128, 128, layers=2, dropout=0.3, batch_first=true)
//!     → last hidden state (batch, 128)
//!     → Linear(128, 64) + ReLU + Dropout(0.3)
//!     → Linear(64, n_classes)

use tch::{nn, nn::Module, Tensor};

pub struct CnnLstmConfig {
    pub n_features: i64,
    pub n_classes: i64,
    pub cnn_channels: [i64; 2],
    pub kernel_size: i64,
    pub lstm_hidden: i64,
    pub lstm_layers: i64,
    pub dropout: f64,
    pub fc_hidden: i64,
}

impl Default for CnnLstmConfig {
    fn default() -> Self {
        Self {
            n_features: 122,
            n_classes: 5,
            cnn_channels: [64, 128],
            kernel_size: 3,
            lstm_hidden: 128,
            lstm_layers: 2,
            dropout: 0.3,
            fc_hidden: 64,
        }
    }
}

pub struct CnnLstm {
    conv1: nn::Conv1D,
    bn1: nn::BatchNorm,
    conv2: nn::Conv1D,
    bn2: nn::BatchNorm,
    lstm: nn::LSTM,
    fc1: nn::Linear,
    fc2: nn::Linear,
    dropout: f64,
    lstm_layers: i64,
}

impl CnnLstm {
    pub fn new(vs: &nn::Path, cfg: &CnnLstmConfig) -> Self {
        let padding = (cfg.kernel_size - 1) / 2;

        let conv_cfg = nn::ConvConfig {
            padding,
            ..Default::default()
        };

        let conv1 = nn::conv1d(vs / "conv1", 1, cfg.cnn_channels[0], cfg.kernel_size, conv_cfg);
        let bn1 = nn::batch_norm1d(vs / "bn1", cfg.cnn_channels[0], Default::default());

        let conv2 = nn::conv1d(
            vs / "conv2",
            cfg.cnn_channels[0],
            cfg.cnn_channels[1],
            cfg.kernel_size,
            conv_cfg,
        );
        let bn2 = nn::batch_norm1d(vs / "bn2", cfg.cnn_channels[1], Default::default());

        let rnn_cfg = nn::RNNConfig {
            num_layers: cfg.lstm_layers,
            dropout: cfg.dropout,
            batch_first: true,
            ..Default::default()
        };
        let lstm = nn::lstm(vs / "lstm", cfg.cnn_channels[1], cfg.lstm_hidden, rnn_cfg);

        let fc1 = nn::linear(vs / "fc1", cfg.lstm_hidden, cfg.fc_hidden, Default::default());
        let fc2 = nn::linear(vs / "fc2", cfg.fc_hidden, cfg.n_classes, Default::default());

        CnnLstm {
            conv1,
            bn1,
            conv2,
            bn2,
            lstm,
            fc1,
            fc2,
            dropout: cfg.dropout,
            lstm_layers: cfg.lstm_layers,
        }
    }

    /// Forward pass. `train` toggles dropout and batch norm behaviour.
    pub fn forward_t(&self, xs: &Tensor, train: bool) -> Tensor {
        // (batch, n_features) → (batch, 1, n_features)
        let xs = xs.unsqueeze(1);

        // CNN block 1
        let xs = xs.apply(&self.conv1).relu();
        let xs = xs.apply_t(&self.bn1, train);

        // CNN block 2
        let xs = xs.apply(&self.conv2).relu();
        let xs = xs.apply_t(&self.bn2, train);

        // (batch, channels, seq_len) → (batch, seq_len, channels) for LSTM
        let xs = xs.permute([0, 2, 1]);

        // LSTM — seq returns (output, (h, c))
        let batch_size = xs.size()[0];
        let lstm_out = self.lstm.seq_init(&xs, &self.lstm.zero_state(batch_size));

        // Extract last layer hidden state: h shape is (num_layers, batch, hidden)
        let h = lstm_out.1.h();
        let h = h.select(0, self.lstm_layers - 1); // (batch, hidden)

        // FC head
        let xs = h.apply(&self.fc1).relu();
        let xs = xs.dropout(self.dropout, train);
        xs.apply(&self.fc2) // raw logits
    }
}

"""CNN+LSTM network for tabular IDS classification (exact Rust replica).

Architecture:
  Input (batch, n_features)
    -> unsqueeze -> (batch, 1, n_features)
    -> Conv1d(1, 64, k=3, pad=1) + ReLU + BatchNorm1d(64)
    -> Conv1d(64, 128, k=3, pad=1) + ReLU + BatchNorm1d(128)
    -> permute -> (batch, n_features, 128)
    -> LSTM(128, 128, layers=2, dropout=0.3, batch_first=True)
    -> h_n[-1] -> (batch, 128)
    -> Linear(128, 64) + ReLU + Dropout(0.3)
    -> Linear(64, n_classes)
"""

import torch
import torch.nn as nn


class CnnLstmConfig:
    def __init__(
        self,
        n_features=122,
        n_classes=5,
        cnn_channels=(64, 128),
        kernel_size=3,
        lstm_hidden=128,
        lstm_layers=2,
        dropout=0.3,
        fc_hidden=64,
    ):
        self.n_features = n_features
        self.n_classes = n_classes
        self.cnn_channels = cnn_channels
        self.kernel_size = kernel_size
        self.lstm_hidden = lstm_hidden
        self.lstm_layers = lstm_layers
        self.dropout = dropout
        self.fc_hidden = fc_hidden


class CnnLstm(nn.Module):
    def __init__(self, cfg: CnnLstmConfig):
        super().__init__()
        padding = (cfg.kernel_size - 1) // 2

        self.conv1 = nn.Conv1d(1, cfg.cnn_channels[0], cfg.kernel_size, padding=padding)
        self.bn1 = nn.BatchNorm1d(cfg.cnn_channels[0])
        self.conv2 = nn.Conv1d(cfg.cnn_channels[0], cfg.cnn_channels[1], cfg.kernel_size, padding=padding)
        self.bn2 = nn.BatchNorm1d(cfg.cnn_channels[1])

        self.lstm = nn.LSTM(
            input_size=cfg.cnn_channels[1],
            hidden_size=cfg.lstm_hidden,
            num_layers=cfg.lstm_layers,
            dropout=cfg.dropout if cfg.lstm_layers > 1 else 0.0,
            batch_first=True,
        )

        self.fc1 = nn.Linear(cfg.lstm_hidden, cfg.fc_hidden)
        self.fc2 = nn.Linear(cfg.fc_hidden, cfg.n_classes)
        self.dropout = nn.Dropout(cfg.dropout)

    def forward(self, x):
        # (batch, n_features) -> (batch, 1, n_features)
        x = x.unsqueeze(1)

        # CNN block 1
        x = torch.relu(self.conv1(x))
        x = self.bn1(x)

        # CNN block 2
        x = torch.relu(self.conv2(x))
        x = self.bn2(x)

        # (batch, channels, seq_len) -> (batch, seq_len, channels)
        x = x.permute(0, 2, 1)

        # LSTM
        _, (h_n, _) = self.lstm(x)
        # h_n: (num_layers, batch, hidden) -> last layer
        x = h_n[-1]

        # FC head
        x = torch.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.fc2(x)
        return x

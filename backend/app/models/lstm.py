"""
models/lstm.py

Pure temporal LSTM encoder.
Consumes a sequence of GAT graph embeddings and outputs a temporal summary state.
No prediction heads are implemented here.
"""

from __future__ import annotations

import torch
import torch.nn as nn
from app import config

def set_seed(seed: int | None = None) -> None:
    s = seed if seed is not None else config.GLOBAL_SEED
    torch.manual_seed(s)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(s)

class LSTMEncoder(nn.Module):
    def __init__(
        self,
        input_dim: int,
        hidden_dim: int,
        num_layers: int = 1,
        dropout: float = 0.0,
    ):
        super().__init__()
        
        if input_dim <= 0 or hidden_dim <= 0 or num_layers <= 0:
            raise ValueError("Dimensions and layers must be > 0.")
        if not (0.0 <= dropout < 1.0):
            raise ValueError("dropout must be in [0, 1).")

        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        # If num_layers == 1, PyTorch's LSTM expects dropout=0
        actual_dropout = dropout if num_layers > 1 else 0.0
        
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=actual_dropout,
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass through the LSTM.
        
        Parameters
        ----------
        x : torch.Tensor
            Sequence of GAT embeddings.
            Expected shape: [batch_size, seq_len, input_dim].
            Supports variable length sequences natively (including seq_len=1).
            Does not enforce config.SEQUENCE_LENGTH.
            
        Returns
        -------
        summary_state : torch.Tensor
            The final hidden state of the LAST layer for each sequence in the batch.
            Expected shape: [batch_size, hidden_dim].
        """
        # x shape: [batch, seq_len, input_dim]
        # output shape: [batch, seq_len, hidden_dim]
        # h_n shape: [num_layers, batch, hidden_dim]
        # c_n shape: [num_layers, batch, hidden_dim]
        output, (h_n, c_n) = self.lstm(x)
        
        # Extract the hidden state from the final layer
        # h_n[-1] has shape [batch, hidden_dim]
        summary_state = h_n[-1]
        
        return summary_state

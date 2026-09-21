"""
tests/test_lstm.py

Tests for the pure temporal LSTM encoder.
"""

import sys
from pathlib import Path

import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.models.lstm import LSTMEncoder, set_seed


class TestLSTMEncoder:
    def test_model_initialization_and_validation(self):
        # Valid
        model = LSTMEncoder(input_dim=16, hidden_dim=32, num_layers=2, dropout=0.1)
        assert model.lstm.hidden_size == 32
        
        # Invalid dimensions
        with pytest.raises(ValueError, match="Dimensions and layers must be > 0"):
            LSTMEncoder(input_dim=0, hidden_dim=32)
            
        with pytest.raises(ValueError, match="Dimensions and layers must be > 0"):
            LSTMEncoder(input_dim=16, hidden_dim=-1)

        # Invalid dropout
        with pytest.raises(ValueError, match="dropout must be in"):
            LSTMEncoder(input_dim=16, hidden_dim=32, dropout=1.5)

    def test_forward_pass_synthetic_sequence(self):
        """Tests that a standard sequence passes through cleanly."""
        model = LSTMEncoder(input_dim=16, hidden_dim=32, num_layers=1)
        
        # [batch_size=2, seq_len=5, input_dim=16]
        x = torch.randn(2, 5, 16)
        
        out = model(x)
        
        # Expected: [batch_size, hidden_dim]
        assert out.shape == (2, 32)

    def test_output_shape_across_lengths(self):
        """Shape must remain [batch, hidden] regardless of seq_len."""
        model = LSTMEncoder(input_dim=16, hidden_dim=32, num_layers=2)
        
        # Length 3
        x1 = torch.randn(4, 3, 16)
        out1 = model(x1)
        assert out1.shape == (4, 32)
        
        # Length 10
        x2 = torch.randn(4, 10, 16)
        out2 = model(x2)
        assert out2.shape == (4, 32)

    def test_short_sequence_handling(self):
        """Sequence of length 1 must not crash and produces expected shape."""
        model = LSTMEncoder(input_dim=16, hidden_dim=32, num_layers=1)
        
        # Length 1
        x = torch.randn(3, 1, 16)
        out = model(x)
        assert out.shape == (3, 32)

    def test_determinism_identical_inputs(self):
        """Two identical forward passes with seeded model produce bit-identical output."""
        x = torch.randn(2, 4, 16)
        
        set_seed(42)
        model1 = LSTMEncoder(input_dim=16, hidden_dim=32, num_layers=2)
        model1.eval()
        out1 = model1(x)
        
        set_seed(42)
        model2 = LSTMEncoder(input_dim=16, hidden_dim=32, num_layers=2)
        model2.eval()
        out2 = model2(x)
        
        assert torch.allclose(out1, out2, atol=1e-7, rtol=1e-5)

"""
models/seeding.py

The single set_seed implementation.

gat.py, lstm.py and world_model.py each used to define their own copy that
seeded torch only. Anything that reached for the gat.py or lstm.py version got
a partial seeding, and train.py's `random.shuffle` of the training pool was
never seeded at all — so runs were not reproducible even though the
determinism check reported that they were.

Importing from one place means a future RNG (a sampler, an augmentation) gets
added once rather than in three files that can drift.
"""

from __future__ import annotations

import random

import numpy as np
import torch

from app import config


def set_seed(seed: int | None = None) -> None:
    """Seed Python, NumPy and torch (CPU and CUDA). Call before model construction."""
    s = seed if seed is not None else config.GLOBAL_SEED
    random.seed(s)
    np.random.seed(s)
    torch.manual_seed(s)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(s)

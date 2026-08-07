"""Hard ceilings for region analysis.

A VAD region can be hundreds of megabytes of high-entropy data. Every analyzer
takes a Budget and stops at it, so a pathological region degrades into a partial
answer rather than pinning the worker for the length of its time limit.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Budget:
    max_bytes: int = 256 * 1024        # bytes handed to the decoders
    max_instructions: int = 20000
    max_blocks: int = 512
    max_functions: int = 256
    max_strings: int = 400
    max_hexdump_bytes: int = 4096
    entropy_windows: int = 256

    @classmethod
    def deep(cls) -> "Budget":
        """For the single highest-attention region."""
        return cls()

    @classmethod
    def shallow(cls) -> "Budget":
        """For the runners-up: enough to characterize, not to fully map."""
        return cls(
            max_bytes=64 * 1024,
            max_instructions=4000,
            max_blocks=128,
            max_functions=64,
            max_strings=120,
            max_hexdump_bytes=1024,
            entropy_windows=128,
        )

"""MemTriage — combined memory-forensics + explainable malware-classification pipeline.

This package wraps two independently-citable components — VolMemLyzer3 (memory
artifact/IoC extraction over Volatility 3) and VADViT (an explainable Vision
Transformer for malware classification) — into a single upload-a-memory-image →
consolidated-investigation-report service. It does not fork or rewrite either
component; both are imported/invoked as dependencies.
"""

__version__ = "0.1.0"

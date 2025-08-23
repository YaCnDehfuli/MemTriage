"""Central configuration for MemTriage.

All tunables live here so the API and the Celery worker share one source of
truth. Values are overridable via environment variables (prefix ``MEMTRIAGE_``)
or a ``.env`` file, which is what docker-compose injects.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MEMTRIAGE_",
        env_file=".env",
        extra="ignore",
    )

    # --- service ---
    app_name: str = "MemTriage"
    environment: str = "local"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])

    # --- storage ---
    # Multi-GB dumps and all derived artifacts live on disk under data_dir,
    # never in the database and never fully in memory.
    data_dir: Path = Path("/data")

    # --- infrastructure ---
    database_url: str = "postgresql+psycopg://memtriage:memtriage@postgres:5432/memtriage"
    redis_url: str = "redis://redis:6379/0"

    # --- upload limits (DoS controls) ---
    # 4GB+ dumps are a first-class case; the cap is per dump.
    max_upload_bytes: int = 48 * 1024 * 1024 * 1024  # 48 GiB per dump
    upload_chunk_bytes: int = 8 * 1024 * 1024  # 8 MiB streamed writes
    allowed_extensions: list[str] = Field(
        default_factory=lambda: [
            ".raw", ".mem", ".vmem", ".lime", ".dmp", ".core",
            ".elf", ".bin", ".img", ".vmsn", ".vmss", ".dump",
        ]
    )

    # --- interval snapshots ---
    # An investigation is one atomic dump OR several interval-collected snapshots
    # of the same host (VADViT's training used 5 per sample). For a selected
    # process, MemTriage assembles that PID's VAD regions from each snapshot and
    # consolidates by choosing the snapshot with the most regions (matching
    # VADViT's dump_selector). A single dump is trivially "consolidated".
    max_dumps_per_investigation: int = 5

    # --- per-process analysis guards ---
    max_regions_per_process: int = 512  # guard against pathological VAD counts

    # --- Volatility 3 ---
    # None => VolMemLyzer auto-resolves `vol`/`vol.py`/`python -m volatility3`.
    vol_path: str | None = None
    vol_timeout_s: int = 1800  # per-plugin subprocess timeout

    # --- VADViT model (brought-your-own weights) ---
    model_checkpoint_path: Path = Path("/models/Multi_32_224_6f_3u.pt")
    labels_path: Path = Path("/models/labels.json")
    model_name: str = "vit_base_patch32_224"
    num_classes: int = 9  # Benign + 8 families
    device: str = "cpu"  # demo runs CPU-only; set "cuda" if a GPU is present

    # --- grid geometry (VADViT preprocessing; see pipeline/grid_render.py) ---
    # Default matches the vit_base_patch32_224 model + the "32_224" dataset.
    # Parameterizable to 384/16 pending confirmation against real training PNGs.
    patch_size: int = 32
    image_size: int = 224

    @property
    def grid_size(self) -> int:
        """Patches per grid side (image_size // patch_size)."""
        return self.image_size // self.patch_size

    @property
    def num_patches(self) -> int:
        """Max VAD regions rendered per process (grid_size ** 2)."""
        return self.grid_size**2

    @property
    def investigations_dir(self) -> Path:
        return self.data_dir / "investigations"


@lru_cache
def get_settings() -> Settings:
    return Settings()

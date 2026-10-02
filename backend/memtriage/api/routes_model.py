"""Bundled VADViT model status and optional operator checkpoint management."""
from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from ..config import get_settings
from ..pipeline.vadvit_model import model_status

router = APIRouter(prefix="/api", tags=["model"])
logger = logging.getLogger(__name__)

# torch.save writes a zip archive; a mistyped file is usually the give-away.
_ZIP_MAGIC = b"PK\x03\x04"


def _upload_dir() -> Path:
    # get_settings() per call, not the module-level `settings`: that one is bound
    # at import, and these are filesystem paths rather than static policy text.
    path = Path(get_settings().model_upload_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


async def _store_upload(upload: UploadFile, target: Path, limit: int) -> int:
    """Stream to a temp file beside the target, then swap it in atomically.

    Streamed because a checkpoint is hundreds of megabytes and reading it into
    memory would let one upload take the API process out. Swapped atomically
    because the worker resolves this exact path on every classify: a half-written
    file must never be reachable under the real name.
    """
    temporary = target.parent / f".upload_{uuid.uuid4().hex}.part"
    total = 0
    try:
        with temporary.open("wb") as handle:
            while chunk := await upload.read(4 * 1024 * 1024):
                total += len(chunk)
                if total > limit:
                    raise HTTPException(
                        status_code=413,
                        detail=(f"Checkpoint exceeds the {limit // (1024 * 1024)} MB "
                                f"limit for an uploaded model."),
                    )
                handle.write(chunk)
        if total == 0:
            raise HTTPException(status_code=400, detail="The uploaded file is empty.")
        temporary.replace(target)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return total


@router.get("/model")
def model_state() -> dict:
    """Which weights are active, and what an upload would need to look like."""
    return model_status()


@router.post("/model/weights", status_code=201)
async def upload_model_weights(
    checkpoint: UploadFile = File(..., description="VADViT .pt state_dict"),
    labels: UploadFile | None = File(None, description="Optional labels.json"),
) -> dict:
    """Install operator-supplied VADViT weights for this deployment."""
    current = get_settings()
    name = Path(checkpoint.filename or "").name
    if not name.endswith(".pt"):
        raise HTTPException(status_code=400,
                            detail="Expected a PyTorch checkpoint with a .pt extension.")

    head = await checkpoint.read(len(_ZIP_MAGIC))
    if head != _ZIP_MAGIC:
        raise HTTPException(
            status_code=400,
            detail=("That file is not a PyTorch checkpoint — torch.save writes a zip "
                    "archive and this does not start like one."),
        )
    await checkpoint.seek(0)

    directory = _upload_dir()
    # Stored under the configured checkpoint name, not the uploaded one, so the
    # worker resolves it without being told and a re-upload replaces rather than
    # accumulates.
    target = directory / Path(current.model_checkpoint_path).name
    size = await _store_upload(checkpoint, target, current.max_model_upload_bytes)

    labels_stored = False
    if labels is not None and (labels.filename or "").strip():
        raw = await labels.read()
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=400,
                                detail=f"labels.json is not valid JSON ({exc}).") from exc
        if not isinstance(parsed, list) or not all(isinstance(x, str) for x in parsed):
            raise HTTPException(status_code=400,
                                detail="labels.json must be a JSON array of strings.")
        (directory / Path(current.labels_path).name).write_text(
            json.dumps(parsed, indent=2), encoding="utf-8")
        labels_stored = True

    logger.info("model weights uploaded (%d bytes, labels=%s)", size, labels_stored)
    status = model_status()
    # The weights are only loaded when something classifies, in the worker. This
    # says the file is in place, not that it produced a verdict.
    return {"stored": True, "size_bytes": size, "labels_stored": labels_stored,
            "model": status}


@router.delete("/model/weights")
def delete_model_weights() -> dict:
    """Remove uploaded weights and fall back to whatever ranks next."""
    current = get_settings()
    directory = Path(current.model_upload_dir)
    removed = False
    for name in (Path(current.model_checkpoint_path).name,
                 Path(current.labels_path).name):
        candidate = directory / name
        if candidate.exists():
            candidate.unlink()
            removed = True
    return {"removed": removed, "model": model_status()}



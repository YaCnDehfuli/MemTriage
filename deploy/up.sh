#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

if [ ! -f components/volmemlyzer/pyproject.toml ] || [ ! -f components/vadvit/models/ViT_model.py ]; then
  git submodule update --init --recursive
fi

MODEL=models/Multi_32_224_6f_3u.pt
if [ ! -f "$MODEL" ] || head -c 128 "$MODEL" | grep -q '^version https://git-lfs.github.com/spec/v1$'; then
  if ! git lfs version >/dev/null 2>&1; then
    echo "Install Git LFS, then run git lfs install and git lfs pull to fetch the bundled model." >&2
    exit 1
  fi
  git lfs pull --include="$MODEL"
fi
if [ ! -f "$MODEL" ] || head -c 128 "$MODEL" | grep -q '^version https://git-lfs.github.com/spec/v1$'; then
  echo "The bundled VADViT checkpoint is missing. Run git lfs pull and retry." >&2
  exit 1
fi

if [ "$#" -eq 0 ]; then
  set -- up --build
fi

exec docker compose -f deploy/docker-compose.yml "$@"

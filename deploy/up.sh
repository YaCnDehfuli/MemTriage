#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

if [ ! -f components/volmemlyzer/pyproject.toml ] || [ ! -f components/vadvit/models/ViT_model.py ]; then
  git submodule update --init --recursive
fi

if [ "$#" -eq 0 ]; then
  set -- up --build
fi

exec docker compose -f deploy/docker-compose.yml "$@"

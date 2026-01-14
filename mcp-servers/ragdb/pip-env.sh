#!/usr/bin/env bash
set -euo pipefail

python -m pip install --index-url https://download.pytorch.org/whl/cpu torch
python -m pip install psycopg2-binary pgvector sentence-transformers transformers

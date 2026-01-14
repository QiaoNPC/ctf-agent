#!/usr/bin/env python3
"""
ragdb/server.py — MCP stdio server for crypto template RAG (Postgres + pgvector)

Fixes:
- Uses pgvector.Vector for query embeddings so Postgres sees a REAL `vector`, not `numeric[]`
  (prevents: operator does not exist: vector <=> numeric[])

Notes:
- Logs go to STDERR only (stdout is reserved for MCP protocol)
- Embedding model is lazy-loaded so Codex doesn't time out on startup
"""

import os
import sys
import logging
from typing import Any, Dict, List, Optional

import psycopg2
from pgvector.psycopg2 import register_vector
from pgvector import Vector
from fastmcp import FastMCP

# IMPORTANT: do NOT print to stdout; MCP uses stdout for protocol.
logging.basicConfig(stream=sys.stderr, level=logging.INFO)
log = logging.getLogger("ragdb")

DB_HOST = os.getenv("PGHOST", "127.0.0.1")
DB_PORT = int(os.getenv("PGPORT", "5432"))
DB_NAME = os.getenv("PGDATABASE", "vectordb")
DB_USER = os.getenv("PGUSER", "vectoruser")
DB_PASS = os.getenv("PGPASSWORD", "vectorpass")

MODEL_NAME = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")
TABLE_NAME = os.getenv("TEMPLATE_TABLE", "crypto_templates")

mcp = FastMCP("ragdb (crypto templates, stdio)")

# Lazy-loaded embedder to avoid Codex startup timeout
_embedder = None


def _get_embedder():
    global _embedder
    if _embedder is None:
        log.info("Loading embedding model: %s", MODEL_NAME)
        from sentence_transformers import SentenceTransformer  # lazy import
        _embedder = SentenceTransformer(MODEL_NAME)
        log.info("Embedding model loaded.")
    return _embedder


def _connect():
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
    )
    register_vector(conn)
    return conn


@mcp.tool
def healthcheck() -> Dict[str, Any]:
    """Quick sanity check: DB connectivity + table existence (no model load)."""
    try:
        conn = _connect()
        cur = conn.cursor()
        cur.execute("SELECT 1;")
        cur.execute(f"SELECT COUNT(*)::bigint FROM {TABLE_NAME};")
        count = cur.fetchone()[0]
        cur.close()
        conn.close()
        return {
            "ok": True,
            "db": f"{DB_HOST}:{DB_PORT}/{DB_NAME}",
            "table": TABLE_NAME,
            "rows": int(count),
        }
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "db": f"{DB_HOST}:{DB_PORT}/{DB_NAME}",
            "table": TABLE_NAME,
        }


@mcp.tool
def list_families() -> List[Dict[str, Any]]:
    """List all families with counts (fast)."""
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        f"""
        SELECT family, COUNT(*)::bigint
        FROM {TABLE_NAME}
        GROUP BY family
        ORDER BY COUNT(*) DESC, family ASC
        """
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [{"family": r[0], "count": int(r[1])} for r in rows]


@mcp.tool
def list_family(family: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Browse templates within a family (rsa/cbc/ecc/etc) for inspiration."""
    fam = (family or "").strip().lower()
    if not fam:
        return []
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        f"""
        SELECT collection, source_path, title, summary, technique, tags, entry_points, language, file_type
        FROM {TABLE_NAME}
        WHERE family = %s
        ORDER BY title ASC
        LIMIT %s
        """,
        (fam, limit),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [
        {
            "collection": r[0],
            "source_path": r[1],
            "title": r[2],
            "summary": r[3],
            "technique": r[4],
            "tags": r[5] or [],
            "entry_points": r[6] or [],
            "language": r[7],
            "file_type": r[8],
        }
        for r in rows
    ]


@mcp.tool
def search_templates(
    query: str,
    family: Optional[str] = None,
    tags: Optional[List[str]] = None,
    top_k: int = 8,
    include_code: bool = False,
) -> List[Dict[str, Any]]:
    """
    Semantic search over card embeddings.

    IMPORTANT FIX:
    - vec is wrapped as pgvector.Vector so psycopg2 binds it as `vector`
      (prevents Postgres error: vector <=> numeric[])
    """
    q = (query or "").strip()
    if not q:
        return []

    fam = family.strip().lower() if family else None
    tags_norm = [t.strip().lower() for t in tags] if tags else None

    embedder = _get_embedder()
    vec = Vector(embedder.encode(q).tolist())

    where = []
    params: List[Any] = []
    if fam:
        where.append("family = %s")
        params.append(fam)
    if tags_norm:
        where.append("tags @> %s")
        params.append(tags_norm)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        f"""
        SELECT
          collection,
          source_path,
          title,
          summary,
          technique,
          tags,
          entry_points,
          language,
          file_type,
          card_md,
          CASE WHEN %s THEN code ELSE NULL END AS code,
          1 - (embedding <=> %s) AS similarity
        FROM {TABLE_NAME}
        {where_sql}
        ORDER BY embedding <=> %s
        LIMIT %s
        """,
        [include_code, vec] + params + [vec, top_k],
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    return [
        {
            "collection": r[0],
            "source_path": r[1],
            "title": r[2],
            "summary": r[3],
            "technique": r[4],
            "tags": r[5] or [],
            "entry_points": r[6] or [],
            "language": r[7],
            "file_type": r[8],
            "card_md": r[9],
            "code": r[10],
            "similarity": float(r[11]),
        }
        for r in rows
    ]


@mcp.tool
def get_template(source_path: str, collection: str = "default") -> Optional[Dict[str, Any]]:
    """
    Fetch a specific template.

    Accepts either:
      A) collection="crypto-attacks", source_path="attacks/cbc/padding_oracle.py"
      B) source_path="crypto-attacks/attacks/cbc/padding_oracle.py" (collection omitted)
    """
    sp = (source_path or "").strip()
    coll = (collection or "default").strip()

    if not sp:
        return None

    # If user passed "collection/rest/of/path", split it automatically.
    if "/" in sp:
        first, rest = sp.split("/", 1)
        # If caller left collection as default, treat the first segment as collection.
        # Also handle if caller mistakenly included collection prefix in source_path.
        if coll == "default" or sp.startswith(coll + "/"):
            # If they passed coll but also included coll in source_path, normalize.
            if sp.startswith(coll + "/"):
                sp = sp[len(coll) + 1 :]
            else:
                coll, sp = first, rest

    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        f"""
        SELECT collection, source_path, title, summary, technique, tags, entry_points,
               language, file_type, card_md, code, sha256
        FROM {TABLE_NAME}
        WHERE collection = %s AND source_path = %s
        """,
        (coll, sp),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return None

    return {
        "collection": row[0],
        "source_path": row[1],
        "title": row[2],
        "summary": row[3],
        "technique": row[4],
        "tags": row[5] or [],
        "entry_points": row[6] or [],
        "language": row[7],
        "file_type": row[8],
        "card_md": row[9],
        "code": row[10],
        "sha256": row[11],
    }


if __name__ == "__main__":
    # Codex launches MCP servers via stdio.
    mcp.run(transport="stdio")

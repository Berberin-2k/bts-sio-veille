"""Partition and retain Veille articles without a database.

This module is intentionally side-effect-free except for read/write helpers,
so boundary and migration behaviour can be unit tested offline.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Iterable

RECENT_DAYS = 60
ARCHIVE_DAYS = 365
MAX_STORED = 1000
SCHEMA_VERSION = 2


def parsed_date(value: str | None) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=dt.timezone.utc)
    return result.astimezone(dt.timezone.utc)


def article_date(article: dict) -> dt.datetime | None:
    return parsed_date(article.get("published_at")) or parsed_date(article.get("collected_at"))


def partition_articles(
    items: Iterable[dict], now: dt.datetime, *,
    recent_days: int = RECENT_DAYS,
    archive_days: int = ARCHIVE_DAYS,
    max_stored: int = MAX_STORED,
) -> tuple[list[dict], list[dict]]:
    if now.tzinfo is None:
        raise ValueError("now must have a timezone")
    now = now.astimezone(dt.timezone.utc)
    recent_cutoff = now - dt.timedelta(days=recent_days)
    archive_cutoff = now - dt.timedelta(days=archive_days)
    valid: dict[str, dict] = {}
    for article in items:
        if not isinstance(article, dict):
            continue
        url, title = article.get("url"), article.get("title")
        published = article_date(article)
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            continue
        if not isinstance(title, str) or not title.strip() or published is None:
            continue
        if published < archive_cutoff or published > now + dt.timedelta(days=1):
            continue
        current = valid.get(url)
        if current is None or published > article_date(current):
            valid[url] = article

    ordered = sorted(
        valid.values(),
        key=lambda article: (article_date(article), article["url"]),
        reverse=True,
    )[:max_stored]
    recent = [article for article in ordered if article_date(article) >= recent_cutoff]
    archive = [article for article in ordered if article_date(article) < recent_cutoff]
    return recent, archive


def read_articles(path: Path) -> list[dict]:
    if not path.exists():
        raise FileNotFoundError(f"Fichier de veille manquant : {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise RuntimeError(f"Fichier JSON corrompu : {path}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("articles"), list):
        raise RuntimeError(f"Structure JSON invalide : {path}")
    return payload["articles"]


def load_history(data_dir: Path) -> list[dict]:
    recent = data_dir / "recent.json"
    archives = data_dir / "archives.json"
    legacy = data_dir / "articles.json"
    if recent.exists() and archives.exists():
        return read_articles(recent) + read_articles(archives)
    if recent.exists() or archives.exists():
        raise RuntimeError("Migration incomplète : recent.json et archives.json doivent coexister.")
    if legacy.exists():
        return read_articles(legacy)
    return []  # New, empty repository only.


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
    # The Actions job commits only after all files validate and the collector succeeds.
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(serialized, encoding="utf-8")
    temp.replace(path)


def save_feeds(data_dir: Path, recent_payload: dict, archives: list[dict]) -> None:
    archives_payload = {
        "version": SCHEMA_VERSION,
        "retention_days": ARCHIVE_DAYS,
        "articles": archives,
    }
    write_json(data_dir / "recent.json", recent_payload)
    write_json(data_dir / "archives.json", archives_payload)
    # Temporary compatibility: previously published Framer embeds read articles.json.
    # It contains recent items only, not a duplicate of the full archives.
    write_json(data_dir / "articles.json", recent_payload)

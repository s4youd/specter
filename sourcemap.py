#!/usr/bin/env python3
"""
sourcemap.py - Source-map consumption for Specter.

A `.map` file often embeds the ORIGINAL pre-bundle sources
(`sourcesContent`) - that is where the highest-value secrets and comments
live, since minified bundles strip context. This module recovers those
sources so the engine can scan each one with proper file attribution
instead of regex-scanning the raw map JSON as one giant line.

Only stdlib is used. Anything unparseable returns None/[] - the caller
falls back to legacy raw scanning.
"""

import json
from typing import Any, Dict, List, Optional

# practical bounds: a map is already capped at fetch time; these bound CPU.
MAX_SOURCES = 25
MIN_SOURCE_LEN = 100
MAX_SOURCE_LEN = 500_000
MAX_PATHS = 200


def parse_sourcemap(text: str) -> Optional[Dict[str, Any]]:
    """Parse map JSON. Returns None unless it quacks like a source map."""
    if not text or 'mappings' not in text[:200000]:
        return None
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    if 'mappings' not in obj or 'sources' not in obj:
        return None
    if not isinstance(obj['sources'], list):
        return None
    return obj


def source_paths(map_text: str) -> List[str]:
    """All original paths from `sources`, even without embedded content."""
    obj = parse_sourcemap(map_text)
    if not obj:
        return []
    out = []
    for s in obj['sources'][:MAX_PATHS]:
        if isinstance(s, str) and s and len(s) < 500:
            out.append(s)
    return out


def iter_original_sources(map_text: str) -> List[Dict[str, str]]:
    """Recover embedded originals: [{path, content}]. Capped + size-gated."""
    obj = parse_sourcemap(map_text)
    if not obj:
        return []
    contents = obj.get('sourcesContent')
    if not isinstance(contents, list):
        return []
    sources = obj['sources']
    out: List[Dict[str, str]] = []
    for path, content in zip(sources, contents):
        if len(out) >= MAX_SOURCES:
            break
        if not isinstance(path, str) or not isinstance(content, str):
            continue
        if len(content) < MIN_SOURCE_LEN:
            continue
        if len(content) > MAX_SOURCE_LEN:
            content = content[:MAX_SOURCE_LEN]
        out.append({'path': path, 'content': content})
    return out


def is_sourcemap(text: str) -> bool:
    """Cheap check: does this text parse as a source map?"""
    return parse_sourcemap(text) is not None

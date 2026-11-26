"""Keyed, non-reversible pseudonyms: PSN- + 8 Crockford base32 characters of HMAC-SHA256.

Same cluster key + same secret -> same pseudonym in every file. A different secret gives a
different pseudonym (cross-release unlinkability, attack A7). Because the key is secret, a
dictionary of hashed originals cannot invert it (attack A6).
"""
from __future__ import annotations

from ..secure.secret import keyed

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford: no I, L, O, U


def _encode(digest: bytes, length: int) -> str:
    n = int.from_bytes(digest, "big")
    return "".join(_ALPHABET[(n >> (5 * i)) & 31] for i in range(length))


class PseudonymIssuer:
    """Issues pseudonyms and guarantees no two cluster keys share one (collisions extend length)."""

    def __init__(self, length: int = 8):
        self.length = length
        self._by_key: dict[str, str] = {}
        self._taken: dict[str, str] = {}

    def get(self, cluster_key: str) -> str:
        if cluster_key in self._by_key:
            return self._by_key[cluster_key]
        digest = keyed("psn", cluster_key)
        length = self.length
        while True:
            psn = "PSN-" + _encode(digest, length)
            owner = self._taken.get(psn)
            if owner is None or owner == cluster_key:
                break
            length += 1  # deterministic: depends only on keys issued, which are processed in sorted order
        self._taken[psn] = cluster_key
        self._by_key[cluster_key] = psn
        return psn

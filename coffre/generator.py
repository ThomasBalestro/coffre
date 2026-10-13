"""Générateur de mots de passe basé sur `secrets` (aléa cryptographique du système)."""

from __future__ import annotations

import math
import secrets
import string

SYMBOLS = "!#$%&*+-=?@^_~.:;"
AMBIGUOUS = set("0O1lI|")


def generate(length: int = 20, upper: bool = True, lower: bool = True, digits: bool = True,
             symbols: bool = True, avoid_ambiguous: bool = False) -> str:
    """Génère un mot de passe contenant au moins un caractère de chaque famille choisie."""
    if not 8 <= length <= 256:
        raise ValueError("La longueur doit être comprise entre 8 et 256.")
    pools = []
    if upper:
        pools.append(string.ascii_uppercase)
    if lower:
        pools.append(string.ascii_lowercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(SYMBOLS)
    if not pools:
        raise ValueError("Choisissez au moins une famille de caractères.")
    if avoid_ambiguous:
        pools = ["".join(c for c in pool if c not in AMBIGUOUS) for pool in pools]

    alphabet = "".join(pools)
    chars = [secrets.choice(pool) for pool in pools]          # une de chaque famille
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    # Mélange de Fisher-Yates avec un aléa cryptographique
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def entropy_bits(length: int, alphabet_size: int) -> float:
    return length * math.log2(alphabet_size) if alphabet_size > 1 else 0.0

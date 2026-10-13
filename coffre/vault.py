"""Modèle du coffre : entrées, lecture/écriture atomique du fichier chiffré."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .crypto import CoffreError, CorruptVaultError, KdfParams, decrypt, encrypt


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Entry:
    name: str
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    created: str = field(default_factory=_now)
    updated: str = field(default_factory=_now)

    @classmethod
    def from_dict(cls, d: dict) -> "Entry":
        known = {k: str(d[k]) for k in cls.__dataclass_fields__ if k in d}
        if not known.get("name"):
            raise CorruptVaultError("Entrée sans nom dans le coffre.")
        return cls(**known)


class Vault:
    """Coffre déverrouillé en mémoire. Les noms d'entrées sont insensibles à la casse."""

    def __init__(self, path: Path, password: str, entries: dict[str, Entry] | None = None,
                 params: KdfParams | None = None):
        self.path = Path(path)
        self._password = password
        self._params = params
        self.entries: dict[str, Entry] = entries or {}

    # ── Cycle de vie ─────────────────────────────────────────────
    @classmethod
    def create(cls, path: Path, password: str, kdf_n: int | None = None) -> "Vault":
        path = Path(path)
        if path.exists():
            raise CoffreError(f"Un coffre existe déjà : {path}")
        vault = cls(path, password, params=KdfParams.new(kdf_n) if kdf_n else KdfParams.new())
        vault.save()
        return vault

    @classmethod
    def open(cls, path: Path, password: str) -> "Vault":
        path = Path(path)
        if not path.exists():
            raise CoffreError(f"Aucun coffre trouvé : {path} (lancez « coffre init »)")
        try:
            blob = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CorruptVaultError("Le fichier n'est pas un coffre lisible.") from exc
        plaintext, params = decrypt(blob, password)
        try:
            data = json.loads(plaintext.decode("utf-8"))
            entries = {k: Entry.from_dict(v) for k, v in data.get("entries", {}).items()}
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as exc:
            raise CorruptVaultError("Contenu déchiffré invalide.") from exc
        return cls(path, password, entries, params)

    def save(self) -> None:
        """Écriture atomique : on écrit dans un fichier temporaire puis on le renomme.
        Une coupure pendant la sauvegarde ne peut donc pas corrompre le coffre existant."""
        payload = json.dumps({"entries": {k: asdict(e) for k, e in self.entries.items()}}).encode("utf-8")
        blob = encrypt(payload, self._password, self._params)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".coffre-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(blob, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def change_password(self, new_password: str) -> None:
        if not new_password:
            raise CoffreError("Le nouveau mot de passe ne peut pas être vide.")
        self._password = new_password
        # Nouveau sel à chaque changement : l'ancienne clé dérivée devient inutile
        self._params = KdfParams.new(self._params.n) if self._params else KdfParams.new()
        self.save()

    # ── Entrées ──────────────────────────────────────────────────
    @staticmethod
    def _key(name: str) -> str:
        key = name.strip().lower()
        if not key:
            raise CoffreError("Le nom de l'entrée ne peut pas être vide.")
        return key

    def add(self, entry: Entry, overwrite: bool = False) -> None:
        key = self._key(entry.name)
        if key in self.entries and not overwrite:
            raise CoffreError(f"L'entrée « {entry.name} » existe déjà (utilisez --force pour la remplacer).")
        if key in self.entries:
            entry.created = self.entries[key].created
            entry.updated = _now()
        self.entries[key] = entry

    def get(self, name: str) -> Entry:
        try:
            return self.entries[self._key(name)]
        except KeyError:
            raise CoffreError(f"Aucune entrée nommée « {name} ».") from None

    def remove(self, name: str) -> Entry:
        key = self._key(name)
        if key not in self.entries:
            raise CoffreError(f"Aucune entrée nommée « {name} ».")
        return self.entries.pop(key)

    def search(self, query: str = "") -> list[Entry]:
        q = query.strip().lower()
        hits = [e for e in self.entries.values()
                if not q or q in e.name.lower() or q in e.username.lower() or q in e.url.lower()]
        return sorted(hits, key=lambda e: e.name.lower())

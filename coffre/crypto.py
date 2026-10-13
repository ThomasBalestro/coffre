"""Chiffrement du coffre.

Choix techniques :
- Dérivation de clé : scrypt (résistant aux attaques par GPU grâce à son coût mémoire).
- Chiffrement : AES-256-GCM (chiffrement authentifié : toute modification est détectée).
- L'en-tête (version, paramètres scrypt, sel) est passé en « données associées » à GCM :
  modifier les paramètres dans le fichier fait échouer le déchiffrement, comme modifier
  le contenu chiffré lui-même.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

FORMAT_VERSION = 1
KEY_LEN = 32          # AES-256
SALT_LEN = 16
NONCE_LEN = 12        # taille recommandée pour GCM

# Paramètres scrypt par défaut : ~64 Mo de mémoire, environ 0,2 s par dérivation.
DEFAULT_N = 2 ** 16
DEFAULT_R = 8
DEFAULT_P = 1


class CoffreError(Exception):
    """Erreur générique du coffre."""


class WrongPasswordError(CoffreError):
    """Mot de passe maître incorrect, ou fichier modifié."""


class CorruptVaultError(CoffreError):
    """Le fichier n'est pas un coffre valide."""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as exc:
        raise CorruptVaultError("Encodage base64 invalide dans le coffre.") from exc


@dataclass(frozen=True)
class KdfParams:
    salt: bytes
    n: int = DEFAULT_N
    r: int = DEFAULT_R
    p: int = DEFAULT_P

    @classmethod
    def new(cls, n: int = DEFAULT_N) -> "KdfParams":
        return cls(salt=os.urandom(SALT_LEN), n=n)

    def to_dict(self) -> dict:
        return {"name": "scrypt", "n": self.n, "r": self.r, "p": self.p, "salt": _b64(self.salt)}

    @classmethod
    def from_dict(cls, d: dict) -> "KdfParams":
        if not isinstance(d, dict) or d.get("name") != "scrypt":
            raise CorruptVaultError("Algorithme de dérivation inconnu.")
        try:
            n, r, p = int(d["n"]), int(d["r"]), int(d["p"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CorruptVaultError("Paramètres scrypt manquants ou invalides.") from exc
        # Bornes : empêchent un fichier piégé de demander une dérivation démesurée (déni de service).
        if not (2 ** 10 <= n <= 2 ** 20 and n & (n - 1) == 0 and 1 <= r <= 32 and 1 <= p <= 16):
            raise CorruptVaultError("Paramètres scrypt hors des bornes autorisées.")
        salt = _unb64(d.get("salt", ""))
        if len(salt) != SALT_LEN:
            raise CorruptVaultError("Sel de longueur invalide.")
        return cls(salt=salt, n=n, r=r, p=p)


def derive_key(password: str, params: KdfParams) -> bytes:
    if not password:
        raise CoffreError("Le mot de passe maître ne peut pas être vide.")
    kdf = Scrypt(salt=params.salt, length=KEY_LEN, n=params.n, r=params.r, p=params.p)
    return kdf.derive(password.encode("utf-8"))


def _associated_data(params: KdfParams) -> bytes:
    header = {"version": FORMAT_VERSION, "kdf": params.to_dict()}
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def encrypt(plaintext: bytes, password: str, params: KdfParams | None = None) -> dict:
    """Chiffre `plaintext` et renvoie la structure JSON du fichier coffre."""
    params = params or KdfParams.new()
    key = derive_key(password, params)
    nonce = os.urandom(NONCE_LEN)  # jamais réutilisé : un nouveau à chaque sauvegarde
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _associated_data(params))
    return {
        "version": FORMAT_VERSION,
        "kdf": params.to_dict(),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
    }


def decrypt(blob: dict, password: str) -> tuple[bytes, KdfParams]:
    """Déchiffre une structure de coffre. Lève WrongPasswordError si la clé ou le fichier est faux."""
    if not isinstance(blob, dict) or blob.get("version") != FORMAT_VERSION:
        raise CorruptVaultError("Version de coffre non prise en charge.")
    params = KdfParams.from_dict(blob.get("kdf"))
    nonce = _unb64(blob.get("nonce", ""))
    ciphertext = _unb64(blob.get("ciphertext", ""))
    if len(nonce) != NONCE_LEN:
        raise CorruptVaultError("Nonce de longueur invalide.")
    key = derive_key(password, params)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, _associated_data(params)), params
    except InvalidTag as exc:
        raise WrongPasswordError("Mot de passe incorrect ou coffre modifié.") from exc

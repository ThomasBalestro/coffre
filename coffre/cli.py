"""Interface en ligne de commande de Coffre.

Exemples :
    coffre init
    coffre add github --user thomas --generate
    coffre list
    coffre get github --show
    coffre generate --length 32
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from . import __version__
from .crypto import CoffreError
from .generator import generate
from .vault import Entry, Vault

DEFAULT_PATH = Path(os.environ.get("COFFRE_PATH", Path.home() / ".coffre" / "coffre.json"))


def ask_password(prompt: str = "Mot de passe maître : ") -> str:
    return getpass.getpass(prompt)


def ask_new_password() -> str:
    first = ask_password("Nouveau mot de passe maître : ")
    if len(first) < 10:
        raise CoffreError("Choisissez un mot de passe maître d'au moins 10 caractères.")
    if first != ask_password("Confirmez : "):
        raise CoffreError("Les deux saisies ne correspondent pas.")
    return first


def mask(secret: str) -> str:
    return "•" * min(len(secret), 12) if secret else "(vide)"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="coffre", description="Gestionnaire de mots de passe chiffré (AES-256-GCM).")
    p.add_argument("--vault", type=Path, default=DEFAULT_PATH, help=f"chemin du coffre (défaut : {DEFAULT_PATH})")
    p.add_argument("--version", action="version", version=f"coffre {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="créer un nouveau coffre")

    a = sub.add_parser("add", help="ajouter ou remplacer une entrée")
    a.add_argument("name")
    a.add_argument("--user", default="")
    a.add_argument("--url", default="")
    a.add_argument("--notes", default="")
    g = a.add_mutually_exclusive_group()
    g.add_argument("--generate", action="store_true", help="générer un mot de passe fort")
    g.add_argument("--password-stdin", action="store_true", help="lire le mot de passe sur l'entrée standard")
    a.add_argument("--length", type=int, default=24)
    a.add_argument("--force", action="store_true", help="remplacer une entrée existante")

    gt = sub.add_parser("get", help="afficher une entrée")
    gt.add_argument("name")
    gt.add_argument("--show", action="store_true", help="afficher le mot de passe en clair")

    ls = sub.add_parser("list", help="lister les entrées")
    ls.add_argument("query", nargs="?", default="", help="filtre sur le nom, l'identifiant ou l'URL")

    rm = sub.add_parser("remove", help="supprimer une entrée")
    rm.add_argument("name")
    rm.add_argument("--yes", action="store_true", help="ne pas demander de confirmation")

    gen = sub.add_parser("generate", help="générer un mot de passe sans l'enregistrer")
    gen.add_argument("--length", type=int, default=20)
    gen.add_argument("--no-symbols", action="store_true")
    gen.add_argument("--no-ambiguous", action="store_true", help="exclure 0 O 1 l I |")

    sub.add_parser("passwd", help="changer le mot de passe maître")
    return p


def run(args: argparse.Namespace, out=None) -> int:
    out = out or sys.stdout  # résolu à l'appel (pas à l'import) : la sortie reste redirigeable
    if args.command == "generate":
        print(generate(args.length, symbols=not args.no_symbols, avoid_ambiguous=args.no_ambiguous), file=out)
        return 0

    if args.command == "init":
        Vault.create(args.vault, ask_new_password())
        print(f"Coffre créé : {args.vault}", file=out)
        return 0

    vault = Vault.open(args.vault, ask_password())

    if args.command == "add":
        if args.generate:
            secret = generate(args.length)
        elif args.password_stdin:
            secret = sys.stdin.readline().rstrip("\n")
        else:
            secret = ask_password(f"Mot de passe pour « {args.name} » : ")
        vault.add(Entry(args.name, args.user, secret, args.url, args.notes), overwrite=args.force)
        vault.save()
        print(f"Entrée « {args.name} » enregistrée." + (f" Mot de passe généré : {secret}" if args.generate else ""), file=out)

    elif args.command == "get":
        e = vault.get(args.name)
        print(f"Nom         : {e.name}", file=out)
        print(f"Identifiant : {e.username or '—'}", file=out)
        print(f"Mot de passe: {e.password if args.show else mask(e.password)}", file=out)
        if e.url:
            print(f"URL         : {e.url}", file=out)
        if e.notes:
            print(f"Notes       : {e.notes}", file=out)
        print(f"Modifié le  : {e.updated}", file=out)

    elif args.command == "list":
        entries = vault.search(args.query)
        if not entries:
            print("Aucune entrée." if not args.query else "Aucun résultat.", file=out)
        width = max((len(e.name) for e in entries), default=0)
        for e in entries:
            print(f"{e.name.ljust(width)}  {e.username or '—'}  {e.url}".rstrip(), file=out)

    elif args.command == "remove":
        if not args.yes and input(f"Supprimer « {args.name} » ? [o/N] ").strip().lower() not in ("o", "oui", "y"):
            print("Annulé.", file=out)
            return 1
        vault.remove(args.name)
        vault.save()
        print(f"Entrée « {args.name} » supprimée.", file=out)

    elif args.command == "passwd":
        vault.change_password(ask_new_password())
        print("Mot de passe maître changé. Le coffre a été rechiffré avec un nouveau sel.", file=out)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except CoffreError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print("\nInterrompu.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())

"""Tests de Coffre : chemins nominaux ET cas d'échec (mauvais mot de passe, fichier altéré…)."""

import base64
import json
import string

import pytest

from coffre import cli
from coffre.crypto import (CoffreError, CorruptVaultError, KdfParams, WrongPasswordError, decrypt, encrypt)
from coffre.generator import SYMBOLS, generate
from coffre.vault import Entry, Vault

FAST_N = 2 ** 10  # scrypt allégé pour des tests rapides (les vrais coffres utilisent 2^16)
PWD = "correct horse battery staple"


@pytest.fixture
def vault_path(tmp_path):
    return tmp_path / "coffre.json"


@pytest.fixture
def vault(vault_path):
    return Vault.create(vault_path, PWD, kdf_n=FAST_N)


# ── Cryptographie ────────────────────────────────────────────────
def test_chiffrement_aller_retour():
    blob = encrypt(b"secret", PWD, KdfParams.new(FAST_N))
    plaintext, _ = decrypt(blob, PWD)
    assert plaintext == b"secret"


def test_le_texte_clair_napparait_pas_dans_le_fichier():
    blob = encrypt(b"mon-super-secret", PWD, KdfParams.new(FAST_N))
    assert b"mon-super-secret" not in json.dumps(blob).encode()


def test_deux_chiffrements_donnent_des_resultats_differents():
    params = KdfParams.new(FAST_N)
    assert encrypt(b"x", PWD, params)["ciphertext"] != encrypt(b"x", PWD, params)["ciphertext"]


def test_mauvais_mot_de_passe():
    blob = encrypt(b"secret", PWD, KdfParams.new(FAST_N))
    with pytest.raises(WrongPasswordError):
        decrypt(blob, "mauvais mot de passe")


def test_contenu_chiffre_altere_est_detecte():
    blob = encrypt(b"secret", PWD, KdfParams.new(FAST_N))
    raw = bytearray(base64.b64decode(blob["ciphertext"]))
    raw[0] ^= 0x01
    blob["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(WrongPasswordError):
        decrypt(blob, PWD)


def test_parametres_scrypt_alteres_sont_detectes():
    blob = encrypt(b"secret", PWD, KdfParams.new(FAST_N))
    blob["kdf"]["r"] = 9  # l'en-tête est authentifié : la modification doit être refusée
    with pytest.raises(WrongPasswordError):
        decrypt(blob, PWD)


def test_parametres_scrypt_demesures_refuses():
    blob = encrypt(b"secret", PWD, KdfParams.new(FAST_N))
    blob["kdf"]["n"] = 2 ** 30  # tentative de déni de service
    with pytest.raises(CorruptVaultError):
        decrypt(blob, PWD)


@pytest.mark.parametrize("bad", [None, {}, {"version": 99}, {"version": 1, "kdf": {"name": "md5"}}])
def test_fichiers_invalides(bad):
    with pytest.raises(CorruptVaultError):
        decrypt(bad, PWD)


def test_mot_de_passe_vide_refuse():
    with pytest.raises(CoffreError):
        encrypt(b"x", "", KdfParams.new(FAST_N))


# ── Coffre ───────────────────────────────────────────────────────
def test_entrees_persistees(vault, vault_path):
    vault.add(Entry("GitHub", "thomas", "s3cr3t!", "https://github.com"))
    vault.save()
    reopened = Vault.open(vault_path, PWD)
    e = reopened.get("github")  # insensible à la casse
    assert (e.name, e.username, e.password) == ("GitHub", "thomas", "s3cr3t!")


def test_doublon_refuse_sauf_force(vault):
    vault.add(Entry("mail", password="a"))
    with pytest.raises(CoffreError):
        vault.add(Entry("MAIL", password="b"))
    vault.add(Entry("MAIL", password="b"), overwrite=True)
    assert vault.get("mail").password == "b"


def test_suppression_et_entree_inconnue(vault):
    vault.add(Entry("x"))
    vault.remove("x")
    with pytest.raises(CoffreError):
        vault.get("x")
    with pytest.raises(CoffreError):
        vault.remove("x")


def test_recherche(vault):
    for n, u in [("GitHub", "thomas"), ("Gmail", "t.b"), ("Banque", "")]:
        vault.add(Entry(n, u))
    assert [e.name for e in vault.search("g")] == ["GitHub", "Gmail"]
    assert len(vault.search()) == 3


def test_creation_refusee_si_coffre_existe(vault, vault_path):
    with pytest.raises(CoffreError):
        Vault.create(vault_path, PWD, kdf_n=FAST_N)


def test_fichier_corrompu(vault_path):
    vault_path.write_text("ceci n'est pas du json")
    with pytest.raises(CorruptVaultError):
        Vault.open(vault_path, PWD)


def test_changement_de_mot_de_passe(vault, vault_path):
    vault.add(Entry("x", password="y"))
    vault.save()
    old_salt = json.loads(vault_path.read_text())["kdf"]["salt"]
    vault.change_password("nouveau mot de passe solide")
    assert json.loads(vault_path.read_text())["kdf"]["salt"] != old_salt
    with pytest.raises(WrongPasswordError):
        Vault.open(vault_path, PWD)
    assert Vault.open(vault_path, "nouveau mot de passe solide").get("x").password == "y"


def test_aucun_fichier_temporaire_laisse(vault, vault_path):
    vault.add(Entry("x"))
    vault.save()
    assert [p.name for p in vault_path.parent.iterdir()] == ["coffre.json"]


# ── Générateur ───────────────────────────────────────────────────
def test_generateur_longueur_et_familles():
    for _ in range(50):
        pw = generate(16)
        assert len(pw) == 16
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in SYMBOLS for c in pw)


def test_generateur_sans_ambigus():
    assert not set("0O1lI|") & set("".join(generate(64, avoid_ambiguous=True) for _ in range(20)))


@pytest.mark.parametrize("length", [4, 7, 1000])
def test_generateur_longueurs_invalides(length):
    with pytest.raises(ValueError):
        generate(length)


def test_generateur_sans_famille():
    with pytest.raises(ValueError):
        generate(12, upper=False, lower=False, digits=False, symbols=False)


# ── Interface en ligne de commande ───────────────────────────────
@pytest.fixture
def fake_input(monkeypatch):
    answers = []
    monkeypatch.setattr(cli, "ask_password", lambda prompt="": answers.pop(0))
    monkeypatch.setattr("coffre.vault.KdfParams.new", classmethod(lambda cls, n=FAST_N: KdfParams(salt=b"s" * 16, n=FAST_N)))
    return answers


def test_cli_parcours_complet(vault_path, fake_input, capsys):
    fake_input += [PWD, PWD]
    assert cli.main(["--vault", str(vault_path), "init"]) == 0
    fake_input += [PWD, "motdepasse-github"]
    assert cli.main(["--vault", str(vault_path), "add", "GitHub", "--user", "thomas"]) == 0
    fake_input += [PWD]
    assert cli.main(["--vault", str(vault_path), "get", "github"]) == 0
    out = capsys.readouterr().out
    assert "thomas" in out and "motdepasse-github" not in out  # masqué par défaut
    fake_input += [PWD]
    cli.main(["--vault", str(vault_path), "get", "github", "--show"])
    assert "motdepasse-github" in capsys.readouterr().out


def test_cli_mauvais_mot_de_passe(vault_path, fake_input, capsys):
    fake_input += [PWD, PWD]
    cli.main(["--vault", str(vault_path), "init"])
    fake_input += ["faux"]
    assert cli.main(["--vault", str(vault_path), "list"]) == 2
    assert "Mot de passe incorrect" in capsys.readouterr().err


def test_cli_mot_de_passe_maitre_trop_court(vault_path, fake_input, capsys):
    fake_input += ["court", "court"]
    assert cli.main(["--vault", str(vault_path), "init"]) == 2
    assert not vault_path.exists()

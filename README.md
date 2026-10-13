# Coffre 🔐

Gestionnaire de mots de passe **en ligne de commande**, local et chiffré.
Vos identifiants restent dans un seul fichier sur votre disque, illisible sans le mot de passe maître.

```
$ coffre add github --user thomas --generate
Mot de passe maître :
Entrée « github » enregistrée. Mot de passe généré : d3LS3K5xlO8rD6eh:oAam+oQ

$ coffre list
GitHub  thomas
```

## Installation

Prérequis : Python 3.10 ou plus récent.

```bash
cd coffre
python -m venv .venv
.venv\Scripts\activate          # Windows  (Linux/macOS : source .venv/bin/activate)
pip install -e ".[dev]"
```

## Utilisation

| Commande | Effet |
|---|---|
| `coffre init` | crée le coffre (`~/.coffre/coffre.json`) |
| `coffre add NOM [--user U] [--url URL] [--generate]` | ajoute une entrée (mot de passe saisi ou généré) |
| `coffre get NOM [--show]` | affiche une entrée (mot de passe masqué par défaut) |
| `coffre list [FILTRE]` | liste ou recherche les entrées |
| `coffre remove NOM` | supprime une entrée (avec confirmation) |
| `coffre generate [--length 32]` | génère un mot de passe sans l'enregistrer |
| `coffre passwd` | change le mot de passe maître (rechiffre tout avec un nouveau sel) |

Un autre emplacement de coffre : option `--vault chemin` ou variable d'environnement `COFFRE_PATH`.

## Conception et sécurité

| Choix | Pourquoi |
|---|---|
| **scrypt** (N = 2¹⁶, r = 8, p = 1) pour dériver la clé | Coûteux en mémoire : rend les attaques par force brute sur GPU très lentes. |
| **AES-256-GCM** | Chiffrement *authentifié* : toute modification du fichier est détectée au déchiffrement. |
| **En-tête authentifié** (version + paramètres scrypt + sel en données associées) | Un attaquant ne peut pas affaiblir les paramètres dans le fichier sans que cela se voie. |
| **Bornes sur les paramètres scrypt lus** | Un fichier piégé ne peut pas imposer une dérivation démesurée (déni de service). |
| **Nonce aléatoire neuf à chaque sauvegarde** | Ne jamais réutiliser un nonce avec la même clé, condition de sécurité de GCM. |
| **Écriture atomique** (fichier temporaire + `os.replace`) | Une coupure pendant la sauvegarde ne corrompt pas le coffre existant. |
| **`secrets`** pour le générateur + mélange Fisher-Yates | Aléa cryptographique du système, au moins un caractère de chaque famille. |
| Mot de passe masqué par défaut, saisie via `getpass` | Rien ne s'affiche à l'écran ni dans l'historique du terminal. |

Une seule dépendance : [`cryptography`](https://cryptography.io), la bibliothèque de référence en Python. Aucune primitive cryptographique n'est réimplémentée à la main.

## Tests

```bash
python -m pytest -q
```

29 tests couvrent les chemins nominaux **et les cas d'échec** : mauvais mot de passe, contenu chiffré altéré,
paramètres d'en-tête modifiés, paramètres démesurés, fichier corrompu, doublons, entrées inconnues,
mot de passe maître trop court, absence de fichier temporaire résiduel.

## Limites connues et pistes

- Pas de copie automatique dans le presse-papiers (éviterait d'afficher le mot de passe) : nécessiterait une dépendance par système.
- Le mot de passe maître reste en mémoire le temps d'une commande ; Python ne permet pas d'effacer une chaîne de façon garantie.
- Pistes : verrouillage automatique, export chiffré, interface graphique, vérification des fuites via l'API *k-anonymat* de Have I Been Pwned.

---
Projet réalisé par **Thomas Balestro** — licence MIT.

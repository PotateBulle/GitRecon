"""
Gestion de la configuration générale de GitRecon.

Ce module centralise les paramètres nécessaires au fonctionnement
de l'application, notamment les informations utilisées pour communiquer
avec l'API REST de GitHub.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv

# Chargement des variables définies dans le fichier .env.
#
# Cette opération permet notamment de récupérer le jeton GitHub sans
# l'inscrire directement dans le code source.
load_dotenv()


GITHUB_API_URL = "https://api.github.com"

# Version de l'API REST GitHub utilisée par l'application.
#
# La version est volontairement définie ici afin de pouvoir être modifiée
# facilement si GitHub introduit une nouvelle version de son API.
GITHUB_API_VERSION = "2026-03-10"


def get_github_token() -> str | None:
    """
    Récupère le jeton d'authentification GitHub.

    Returns:
        Le jeton GitHub lorsqu'il est défini dans l'environnement,
        sinon ``None``.
    """

    return os.getenv("GITHUB_TOKEN")

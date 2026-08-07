"""
Client HTTP utilisé pour communiquer avec l'API REST GitHub.

Ce module fournit une couche d'abstraction entre GitRecon et GitHub.
Les autres composants de l'application n'ont ainsi pas besoin de gérer
directement HTTPX, les en-têtes HTTP, l'authentification ou la pagination.
"""

from __future__ import annotations

from typing import Any

import httpx

from gitrecon.config import (
    GITHUB_API_URL,
    GITHUB_API_VERSION,
    get_github_token,
)


class GitHubAPIError(Exception):
    """
    Exception levée lorsqu'une requête adressée à GitHub échoue.
    """


class GitHubClient:
    """
    Client permettant d'effectuer des requêtes vers l'API REST GitHub.

    Le client configure automatiquement les en-têtes recommandés par
    GitHub ainsi que l'authentification lorsqu'un jeton est disponible.
    """

    def __init__(self) -> None:
        """
        Initialise le client HTTP GitHub.
        """

        self.token = get_github_token()

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "User-Agent": "GitRecon",
        }

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        self.client = httpx.Client(
            base_url=GITHUB_API_URL,
            headers=headers,
            timeout=15.0,
        )

    def _handle_response(
        self,
        response: httpx.Response,
    ) -> Any:
        """
        Valide une réponse GitHub et retourne son contenu JSON.

        Args:
            response:
                Réponse HTTP reçue depuis GitHub.

        Returns:
            Contenu JSON désérialisé.

        Raises:
            GitHubAPIError:
                Lorsque GitHub retourne une erreur HTTP.
        """

        try:
            response.raise_for_status()

        except httpx.HTTPStatusError as exc:
            response = exc.response

            try:
                error_data = response.json()
                message = error_data.get(
                    "message",
                    "Erreur GitHub non documentée.",
                )
            except ValueError:
                message = "Réponse GitHub non lisible."

            accepted_permissions = response.headers.get("X-Accepted-GitHub-Permissions")

            error_message = (
                f"GitHub a retourné une erreur HTTP "
                f"{response.status_code} pour "
                f"{response.request.url}: {message}"
            )

            if accepted_permissions:
                error_message += f" Permissions attendues : {accepted_permissions}."

            raise GitHubAPIError(error_message) from exc

        return response.json()

    def get(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """
        Effectue une requête HTTP GET auprès de GitHub.
        """

        try:
            response = self.client.get(
                endpoint,
                params=params,
            )

            return self._handle_response(response)

        except httpx.RequestError as exc:
            raise GitHubAPIError(
                f"Impossible de contacter l'API GitHub : {exc}"
            ) from exc

    def get_paginated(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        per_page: int = 100,
        max_pages: int | None = None,
    ) -> list[Any]:
        """
        Récupère automatiquement toutes les pages d'un endpoint GitHub.

        Args:
            endpoint:
                Endpoint relatif de l'API GitHub.

            params:
                Paramètres supplémentaires envoyés avec chaque requête.

            per_page:
                Nombre maximal d'éléments demandé par page.

            max_pages:
                Limite optionnelle du nombre de pages récupérées.
                Lorsque ``None``, la pagination continue jusqu'à ce
                que GitHub retourne une page incomplète ou vide.

        Returns:
            Liste contenant l'ensemble des éléments récupérés.

        Raises:
            GitHubAPIError:
                Lorsqu'une requête échoue.
        """

        results: list[Any] = []
        page = 1

        request_params = dict(params or {})
        request_params["per_page"] = per_page

        while True:
            request_params["page"] = page

            data = self.get(
                endpoint,
                params=request_params,
            )

            if not isinstance(data, list):
                raise GitHubAPIError(
                    "La pagination GitHub attendait une liste "
                    f"pour l'endpoint {endpoint}."
                )

            if not data:
                break

            results.extend(data)

            if len(data) < per_page:
                break

            if max_pages is not None and page >= max_pages:
                break

            page += 1

        return results

    def close(self) -> None:
        """
        Ferme proprement les connexions HTTP ouvertes.
        """

        self.client.close()

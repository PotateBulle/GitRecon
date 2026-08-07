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

    Attributes:
        status_code:
            Code HTTP retourné par GitHub lorsqu'il est disponible.

        url:
            URL de la requête ayant échoué lorsqu'elle est disponible.

        accepted_permissions:
            Permissions annoncées par GitHub dans l'en-tête
            ``X-Accepted-GitHub-Permissions`` lorsqu'il est présent.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        url: str | None = None,
        accepted_permissions: str | None = None,
    ) -> None:
        super().__init__(message)

        self.status_code = status_code
        self.url = url
        self.accepted_permissions = accepted_permissions


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

        Raises:
            GitHubAPIError:
                Lorsque GitHub retourne une erreur HTTP ou une réponse
                JSON invalide.
        """

        try:
            response.raise_for_status()

        except httpx.HTTPStatusError as exc:
            error_response = exc.response

            try:
                error_data = error_response.json()

                if isinstance(error_data, dict):
                    message = error_data.get(
                        "message",
                        "Erreur GitHub non documentée.",
                    )
                else:
                    message = "Erreur GitHub non documentée."

            except ValueError:
                message = "Réponse GitHub non lisible."

            accepted_permissions = error_response.headers.get(
                "X-Accepted-GitHub-Permissions"
            )

            request_url = str(error_response.request.url)

            error_message = (
                "GitHub a retourné une erreur HTTP "
                f"{error_response.status_code} pour "
                f"{request_url}: {message}"
            )

            if accepted_permissions:
                error_message += f" Permissions attendues : {accepted_permissions}."

            raise GitHubAPIError(
                error_message,
                status_code=error_response.status_code,
                url=request_url,
                accepted_permissions=accepted_permissions,
            ) from exc

        try:
            return response.json()

        except ValueError as exc:
            raise GitHubAPIError(
                "GitHub a retourné une réponse JSON invalide pour "
                f"{response.request.url}.",
                status_code=response.status_code,
                url=str(response.request.url),
            ) from exc

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
            request_url = None

            if exc.request is not None:
                request_url = str(exc.request.url)

            raise GitHubAPIError(
                f"Impossible de contacter l'API GitHub : {exc}",
                url=request_url,
            ) from exc

    def get_paginated(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        per_page: int = 100,
        max_pages: int | None = None,
    ) -> list[Any]:
        """
        Récupère automatiquement les pages d'un endpoint GitHub.

        Args:
            endpoint:
                Endpoint GitHub à interroger.

            params:
                Paramètres supplémentaires transmis à la requête.

            per_page:
                Nombre d'éléments demandés par page.

            max_pages:
                Nombre maximal de pages à récupérer. Lorsque ``None``,
                la pagination continue jusqu'à la dernière page.

        Returns:
            Liste contenant les éléments récupérés.

        Raises:
            ValueError:
                Lorsque les paramètres de pagination sont invalides.

            GitHubAPIError:
                Lorsque GitHub retourne une structure inattendue.
        """

        if per_page < 1 or per_page > 100:
            raise ValueError("per_page doit être compris entre 1 et 100.")

        if max_pages is not None and max_pages < 1:
            raise ValueError("max_pages doit être supérieur ou égal à 1.")

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

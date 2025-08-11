import httpx
from contextlib import asynccontextmanager
from typing import Optional
import threading

from loguru import logger
from httpx import Auth, Request
from rdflib import Graph, Namespace, URIRef
from solid_client_credentials import DpopTokenProvider
from socli.utils import async_lru_cache
from socli.user.database import UserDB, User, Token


class HttpxSolidClientCredentialsAuth(Auth):
    def __init__(self, dpop_token_provider: DpopTokenProvider) -> None:
        self._token_provider = dpop_token_provider

    def auth_flow(self, request: Request):
        method = request.method
        url = str(request.url)

        access_token = self._token_provider.get_uptodate_access_token()
        dpop_header = self._token_provider.get_dpop_header(url, method)

        request.headers["Authorization"] = f"DPoP {access_token}"
        request.headers["DPoP"] = dpop_header

        yield request


class AuthClient:
    """Thread-safe singleton HTTP client with connection pooling for authentication operations."""

    _instance: Optional["AuthClient"] = None
    _client: Optional[httpx.AsyncClient] = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    @asynccontextmanager
    async def get_client(self):
        """Get or create the shared HTTP client with connection pooling."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                limits=httpx.Limits(
                    max_keepalive_connections=10,
                    max_connections=20,
                    keepalive_expiry=30.0,
                ),
                timeout=httpx.Timeout(30.0),
            )
        try:
            yield self._client
        except Exception:
            raise

    async def close(self):
        """Close the HTTP client and cleanup connections."""
        if self._client:
            await self._client.aclose()
            self._client = None


_auth_client = AuthClient()


async def auth_user(name, password, oidc):
    """Authenticate a user against the OIDC provider."""
    try:
        async with _auth_client.get_client() as client:
            index_response = await client.get(f"{oidc}/.account/")
            index_response.raise_for_status()

            controls = index_response.json().get("controls", {})
            login_url = controls.get("password", {}).get("login")

            if not login_url:
                logger.error("Login URL not found in account controls")
                return None

            login_response = await client.post(
                login_url,
                headers={"Content-Type": "application/json"},
                json={"email": name, "password": password},
            )
            login_response.raise_for_status()

            return login_response.json().get("authorization")
    except httpx.HTTPStatusError as e:
        logger.error(
            f"HTTP error during authentication: {e.response.status_code} - {e}"
        )
        return None
    except httpx.RequestError as e:
        logger.error(f"Request error during authentication: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during authentication: {e}")
        return None


async def authenticate(user: User) -> Token:
    authorization = await auth_user(user.email, user.password, user.oidc)
    session_token = None

    try:
        potential_token = user.token
        tokens = await get_all_tokens(authorization, user.oidc)

        if tokens and potential_token and potential_token.id in tokens:
            session_token = potential_token
        else:
            raise ValueError("No valid token for provided credentials found.")

    except (ImportError, KeyError, ValueError) as e:
        session_token = await create_new_oidc_token(
            user.email, user.password, user.webid, user.oidc
        )

    return session_token


async def build_session(session_token, oidc) -> HttpxSolidClientCredentialsAuth:
    auth = await generate_dpop_token(session_token, oidc)
    return auth


async def get_all_tokens(authorization, oidc):
    """
    Retrieve all client credentials tokens for the authenticated user.

    Args:
        authorization: User authorization token
        oidc: URL of the OIDC provider

    Returns:
        List of tokens or None if retrieval fails
    """
    client_credential_url = await get_client_credential_url(authorization, oidc)
    if not client_credential_url:
        return None

    try:
        async with _auth_client.get_client() as client:
            response = await client.get(
                client_credential_url,
                headers={"authorization": f"CSS-Account-Token {authorization}"},
            )
            response.raise_for_status()
            return response.json().get("clientCredentials")
    except httpx.HTTPError as e:
        logger.error(f"Error retrieving tokens: {e}")
        return None


async def get_client_credential_url(authorization, oidc):
    """
    Get the client credentials URL from the OIDC provider.

    Args:
        authorization: User authorization token
        oidc: URL of the OIDC provider

    Returns:
        Client credentials URL or None if retrieval fails
    """
    try:
        async with _auth_client.get_client() as client:
            response = await client.get(
                f"{oidc}/.account/",
                headers={"authorization": f"CSS-Account-Token {authorization}"},
            )
            response.raise_for_status()

            controls = response.json().get("controls", {})
            return controls.get("account", {}).get("clientCredentials")
    except httpx.HTTPError as e:
        logger.error(f"HTTP error retrieving client credentials URL: {e}")
        return None
    except Exception as e:
        logger.error(f"Error retrieving client credentials URL: {e}")
        return None


async def create_new_oidc_token(name, password, webid, oidc) -> Token:
    """Create a new OIDC token for the user."""
    authorization = await auth_user(name, password, oidc)
    async with _auth_client.get_client() as client:
        try:
            auth_headers = {
                "authorization": f"CSS-Account-Token {authorization}",
                "Content-Type": "application/json",
            }
            index_response = await client.get(
                f"{oidc}/.account/",
                headers={"authorization": auth_headers["authorization"]},
            )
            controls = index_response.json().get("controls", {})

            client_credentials_url = controls.get("account", {}).get(
                "clientCredentials"
            )
            client_response = await client.post(
                client_credentials_url,
                headers=auth_headers,
                json={"name": "my-token", "webId": webid},
            )
            credentials = client_response.json()

            token = Token(
                id=credentials.get("id"),
                secret=credentials.get("secret"),
                resource=credentials.get("resource"),
            )
            logger.info(f"Token created: {token.id}")
            return token

        except httpx.HTTPError as e:
            logger.error(f"HTTP error occurred: {e}")
            raise
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            raise


async def generate_dpop_token(
    token: Token, oidc: str
) -> HttpxSolidClientCredentialsAuth:
    """Generate a DPoP token for the provided token and OIDC URL."""
    token_provider = DpopTokenProvider(
        issuer_url=oidc, client_id=token.id, client_secret=token.secret
    )
    auth = HttpxSolidClientCredentialsAuth(token_provider)
    return auth


@async_lru_cache(maxsize=32)
async def identify(role: str) -> tuple[User, HttpxSolidClientCredentialsAuth]:
    """Fetch user by role and authenticate."""

    user = await UserDB.get_user_by_role_from_file(role)
    if user is None:
        raise ValueError(f"User '{role}' not found in database.")

    token = await authenticate(user)
    auth = await build_session(token, user.oidc)
    return (user, auth)


async def authenticated_put(
    role: str, content: str, endpoint_url: str
) -> httpx.Response:
    """Authenticated PUT request with proper resource management and error handling."""
    _, auth = await identify(role)

    if endpoint_url.endswith(".jsonld"):
        headers = {"Content-Type": "application/ld+json"}
    else:
        headers = {"Content-Type": "text/turtle"}

    auth_client = AuthClient()
    try:
        async with auth_client.get_client() as client:
            response = await client.put(
                endpoint_url, headers=headers, content=content, auth=auth
            )
            response.raise_for_status()
            return response
    except httpx.HTTPStatusError as e:
        raise Exception(
            f"HTTP {e.response.status_code} error putting to {endpoint_url}: {e.response.text}"
        ) from e
    except httpx.RequestError as e:
        raise Exception(f"HTTP request error putting to {endpoint_url}: {e}") from e
    except Exception as e:
        raise Exception(f"Unexpected error when putting to {endpoint_url}: {e}") from e


async def authenticated_get(
    role: str, endpoint_url: str, headers: dict | None = None
) -> httpx.Response:
    """Authenticated GET request with proper resource management and error handling."""
    _, auth = await identify(role)
    if headers is None:
        headers = {"Accept": "text/turtle"}

    auth_client = AuthClient()
    try:
        async with auth_client.get_client() as client:
            response = await client.get(endpoint_url, headers=headers, auth=auth)
            response.raise_for_status()
            return response
    except httpx.HTTPStatusError as e:
        raise Exception(
            f"HTTP {e.response.status_code} error getting from {endpoint_url}: {e.response.text}"
        ) from e
    except httpx.RequestError as e:
        raise Exception(f"HTTP request error getting from {endpoint_url}: {e}") from e
    except Exception as e:
        raise Exception(
            f"Unexpected error when getting from {endpoint_url}: {e}"
        ) from e

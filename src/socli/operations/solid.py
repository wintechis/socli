import httpx
import click
from typing import Any

from loguru import logger
from rdflib import Graph, URIRef, Namespace

from rdflib.namespace import DCAT
from socli.user.database import UserDB, User
from socli.operations.http import authenticated_get, authenticated_put
from socli.operations.rdf import set_acl, append_index


# TODO: Refactor to one configuration
ACL = Namespace("http://www.w3.org/ns/auth/acl#")
SOLID = Namespace("http://www.w3.org/ns/solid/terms#")
DPROD = Namespace("https://ekgf.github.io/dprod/")
LDP = Namespace("http://www.w3.org/ns/ldp#")


async def get_type_index(role: str, webid: str) -> tuple[str | None, str | None]:
    """
    Get public and private type indexes from a WebID profile document.

    Args:
        role: User role for authentication
        webid: WebID URI (e.g., "https://example.com/user/profile/card#me")

    Returns:
        Tuple of (public_type_index, private_type_index) URLs, either can be None

    Raises:
        httpx.HTTPStatusError: For HTTP errors (4xx, 5xx)
        Exception: For WebID loading or parsing errors
    """
    profile_doc_url = webid.split("#")[0]
    headers = {"Accept": "text/turtle"}

    try:
        res = await authenticated_get(role, profile_doc_url, headers=headers)
        res.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise Exception(
            f"Error loading WebID profile: HTTP {e.response.status_code}"
        ) from e
    except Exception as e:
        raise Exception(f"Error loading WebID profile: {e}") from e

    try:
        g = Graph()
        g.parse(data=res.text, format="turtle", publicID=profile_doc_url)
        SOLID = Namespace("http://www.w3.org/ns/solid/terms#")
        me = URIRef(webid)

        public_index = None
        private_index = None

        for _, _, o in g.triples((me, SOLID.publicTypeIndex, None)):
            public_index = str(o)
        for _, _, o in g.triples((me, SOLID.privateTypeIndex, None)):
            private_index = str(o)

        return (public_index, private_index)
    except Exception as e:
        raise Exception(f"Error parsing WebID profile document: {e}") from e


async def display_type_index(
    role: str, index_uri: str, index_type: str
) -> Graph | None:
    """Display and parse a type index."""
    res = await authenticated_get(role, index_uri)
    if res.status_code != 200:
        logger.warning(f"Failed to fetch {index_type} index: {res.status_code}")
        return
    g = await parse_rdf_response(res, index_uri)
    if not g:
        return None

    return g


async def parse_rdf_response(
    response: httpx.Response, base_uri: str, format: str = "turtle"
) -> Graph | None:
    """Parse RDF response into a graph.

    Args:
        response: HTTP response object
        base_uri: Base URI for parsing
        format: RDF format (default: turtle)

    Returns:
        Graph object or None if parsing fails
    """
    if response.status_code != 200:
        logger.error(f"Failed to fetch {base_uri}: {response.status_code}")
        return None

    try:
        g = Graph()
        g.parse(data=response.text, format=format, publicID=base_uri)
        return g
    except Exception as e:
        logger.error(f"Failed to parse RDF from {base_uri}: {e}")
        return None


async def get_inbox_items(role: str, inbox_uri: str) -> list[str]:
    """Get all items from an inbox container.

    Args:
        role: User role for authentication
        inbox_uri: URI of the inbox container

    Returns:
        List of item URIs
    """
    res = await authenticated_get(role, inbox_uri)
    g = await parse_rdf_response(res, inbox_uri)

    if not g:
        return []

    items = []
    for _, _, obj in g.triples((None, LDP.contains, None)):
        items.append(str(obj))

    return sorted(items)


def parse_access_decision(decision: str) -> tuple[list[str], bool]:
    """Parse user access decision into ACL permissions."""
    permissions = []
    valid = False

    access_map = {"r": "Read", "a": "Append", "w": "Write"}

    for code, permission in access_map.items():
        if code in decision.lower():
            permissions.append(permission)
            valid = True

    return permissions, valid


async def apply_acl_permissions(
    role: str, user: User, resource_uri: str, permissions: list[str]
) -> bool:
    """Apply ACL permissions to a resource."""
    acl_config = {
        "public": [],
        "authenticated": permissions,
        "owner": ["Read", "Write", "Control"],
    }

    acl_content = set_acl(resource_uri, user.webid, acl_config)
    acl_uri = f"{resource_uri}.acl"

    try:
        res = await authenticated_put(role, acl_content, acl_uri)
        return 200 <= res.status_code < 300
    except Exception as e:
        logger.error(f"Failed to apply ACL: {e}")
        return False


async def process_inbox_item(role: str, item_uri: str) -> dict[str, Any] | None:
    """Process a single inbox item and extract relevant data."""
    res = await authenticated_get(role, item_uri)
    g = await parse_rdf_response(res, item_uri)

    if not g:
        return None

    click.echo("\n")
    click.echo(g.serialize(format="turtle"))
    item_data: dict[str, Any] = {"uri": item_uri, "graph": g, "access_urls": []}

    access_urls: list[str] = []
    for _, _, obj in g.triples((None, DCAT.accessURL, None)):
        access_urls.append(str(obj))
    item_data["access_urls"] = access_urls

    return item_data


def display_inbox_items(items: list[str]) -> None:
    """Display numbered list of inbox items."""
    click.echo(f"\nFound {len(items)} items in inbox:")
    for idx, item in enumerate(items, 1):
        click.echo(f"{idx}. {item}")


def get_user_selection() -> tuple[int | None, bool]:
    """Get user selection for inbox item."""
    user_input = (
        click.prompt("\nSelect item number (0 or q to exit)", type=str, default="0")
        .strip()
        .lower()
    )
    if user_input in ["q", "quit", "exit"]:
        return None, True
    try:
        selection = int(user_input)
        return selection, False
    except ValueError:
        click.echo("Please enter a valid number or 'q' to quit.", err=True)
        return None, False


async def handle_access_url(role: str, access_url: str) -> bool:
    """Handle permission granting for a single access URL."""
    click.echo(f"\nAccess URL: {access_url}")

    decision = click.prompt(
        "Grant access? (r=read, a=append, w=write, s=skip, 0=back, q=quit)",
        type=str,
        default="s",
    ).lower()

    if decision in ["q", "quit"]:
        return False
    elif decision == "0":
        return False
    elif decision == "s":
        return True

    permissions, valid = parse_access_decision(decision)

    if not valid:
        click.echo("No valid permissions specified.", err=True)
        return True

    user = await UserDB.get_user_by_role_from_file(role)
    if not user:
        click.echo(f"User '{role}' not found.", err=True)
        return True

    click.echo(f"Applying permissions: {', '.join(permissions)}...")

    _, private_index = await get_type_index(role, user.webid)
    if private_index:
        await apply_acl_permissions(
            role,
            user,
            private_index,
            ["Read"],
        )

    success = await apply_acl_permissions(role, user, access_url, permissions)

    if success:
        click.echo(f"Successfully applied permissions to {access_url}")
    else:
        click.echo("Failed to apply permissions", err=True)

    return True


async def upload_with_index(
    role: str, user: User, content: str, uri: str, visibility: str
) -> bool:
    """Upload content and update the appropriate type index."""
    accepted_status_codes = [200, 201, 204, 205]
    res = await authenticated_put(role, content, uri)
    if res.status_code not in accepted_status_codes:
        click.echo(f"Failed to upload content: {res.status_code}", err=True)
        return False

    public_index, private_index = await get_type_index(role, user.webid)

    if visibility == "public":
        if not public_index:
            logger.error("✗ No public type index found", err=True)
            return False

        acl_content = set_acl(uri, user.webid)
        acl_res = await authenticated_put(role, acl_content, f"{uri}.acl")
        if acl_res.status_code not in accepted_status_codes:
            logger.error(f"Failed to set public ACL: {acl_res.status_code}", err=True)

        index_res = await authenticated_get(role, public_index)
        updated_index = await append_index(public_index, index_res, uri)
        update_res = await authenticated_put(role, updated_index, public_index)

        return update_res.status_code in accepted_status_codes

    else:
        if not private_index:
            logger.error("✗ No private type index found", err=True)
            return False
        index_res = await authenticated_get(role, private_index)
        updated_index = await append_index(private_index, index_res, uri)
        update_res = await authenticated_put(role, updated_index, private_index)

        return update_res.status_code in accepted_status_codes

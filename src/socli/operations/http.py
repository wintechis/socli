import httpx
from loguru import logger
from socli.operations.rdf import set_acl, append_index
from socli.user import User, identify, AuthClient


async def authenticated_put(
    role: str, content: str, endpoint_url: str
) -> httpx.Response:
    """Put content to endpoint using managed client with proper error handling."""
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
    """Get content from endpoint using managed client with proper error handling."""
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


async def upload_with_index(
    role: str, user: User, content: str, uri: str, visibility: str
) -> bool:
    """Upload content and update the appropriate type index."""
    res = await authenticated_put(role, content, uri)
    if res.status_code not in [200, 201, 204, 205]:
        logger.warning(f"Failed to upload content: {res.status_code}", err=True)
        return False

    from socli.operations.solid import get_type_index

    public_index, private_index = await get_type_index(role, user.webid)

    if visibility == "public":
        if not public_index:
            logger.error("✗ No public type index found", err=True)
            return False

        acl_content = set_acl(uri, user.webid)
        acl_res = await authenticated_put(role, acl_content, f"{uri}.acl")
        if acl_res.status_code not in [200, 201, 204, 205]:
            logger.error(f"✗ Failed to set public ACL: {acl_res.status_code}", err=True)

        index_res = await authenticated_get(role, public_index)
        updated_index = await append_index(public_index, index_res, uri)
        update_res = await authenticated_put(role, updated_index, public_index)
        logger.debug(update_res.status_code)

        return update_res.status_code in [200, 201, 204, 205]

    else:
        if not private_index:
            logger.error("✗ No private type index found", err=True)
            return False
        index_res = await authenticated_get(role, private_index)
        updated_index = await append_index(private_index, index_res, uri)
        update_res = await authenticated_put(role, updated_index, private_index)
        logger.debug(update_res.status_code)

        return update_res.status_code in [200, 201, 204, 205]

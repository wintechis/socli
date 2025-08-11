import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import click
from loguru import logger
from rdflib import Graph, URIRef, Namespace
from rdflib.namespace import RDF, FOAF, DCAT
from rich.console import Console
from rich.table import Table

from socli.operations import (
    authenticated_get,
    authenticated_put,
    display_inbox_items,
    display_type_index,
    get_inbox_items,
    get_type_index,
    get_user_selection,
    handle_access_url,
    process_inbox_item,
    upload_with_index,
)
from socli.user import Config, User, UserDB, get_role_with_default
from socli.utils import (
    logit,
    run_async,
)

DPROD = Namespace("https://ekgf.github.io/dprod/")
LDP = Namespace("http://www.w3.org/ns/ldp#")
SOLID = Namespace("http://www.w3.org/ns/solid/terms#")


@click.group()
def cli():
    """Solid client CLI for interacting with the Community Solid Server."""


@cli.group()
def config():
    """Manage socli configuration."""


@config.command("set-default")
@click.option("-r", "--role", required=True, help="Role to set as default")
@click.option(
    "-c", "--config-path", default="./.socli.config.toml", help="Config file path"
)
@run_async
@logit
async def set_default(role: str, config_path: str) -> None:
    """Set the default user role for all commands."""
    config = await Config.read_from_file(config_path)
    db_path = config.database

    try:
        db = await UserDB.read_from_file(db_path)
        user_found = any(user.role == role for user in db.users)

        if not user_found:
            click.echo(
                f"Error: User with role '{role}' not found in database.", err=True
            )
            click.echo(
                f"Available roles: {', '.join([u.role for u in db.users])}", err=True
            )
            raise click.Abort()

        config.default_role = role
        await config.write_to_file(config_path)
        click.echo(f"✓ Default role set to '{role}'")

    except FileNotFoundError:
        click.echo(f"Error: Database file '{db_path}' not found.", err=True)
        raise click.Abort()
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()


@config.command("get-default")
@click.option(
    "-c", "--config-path", default="./.socli.config.toml", help="Config file path"
)
@run_async
@logit
async def get_default(config_path: str) -> None:
    """Show the current default user role."""
    config = await Config.read_from_file(config_path)

    if config.default_role:
        click.echo(f"Default role: {config.default_role}")
    else:
        click.echo("No default role configured")


@config.command("clear-default")
@click.option(
    "-c", "--config-path", default="./.socli.config.toml", help="Config file path"
)
@run_async
@logit
async def clear_default(config_path: str) -> None:
    """Clear the default user role."""
    config = await Config.read_from_file(config_path)
    config.default_role = None
    await config.write_to_file(config_path)
    click.echo("✓ Default role cleared")


@cli.command()
@click.option("-r", "--role", required=True, help="User role (unique identifier)")
@click.option("-e", "--email", required=True, help="User email address")
@click.option("-p", "--password", required=True, help="User password", hide_input=True)
@click.option("-w", "--webid", required=True, help="User WebID URL")
@click.option("-o", "--oidc", required=True, help="OIDC provider URL")
@click.option("-d", "--database", default="./.db.toml", help="Database file path")
@run_async
@logit
async def add(role, email, password, webid, oidc, database) -> None:
    """Add a new user to the database with authentication."""
    from socli.user import (
        authenticate,
    )

    user = User(
        role=role, email=email, webid=webid, password=password, oidc=oidc, token=None
    )
    try:
        db_path = Path(database)
        if not db_path.exists():
            empty_db = UserDB(users=[])
            await empty_db.write_to_file(database)

        try:
            token = await authenticate(user)
            user.token = token
            logger.info(f"Authentication successful. Token ID: {token.id}")
        except Exception as e:
            click.echo(f"Authentication failed: {e}", err=True)
            raise click.Abort()

        updated_db = await UserDB.add_user_to_file(user, database)
        await updated_db.write_to_file(database)

        verify_db = await UserDB.read_from_file(database)
        logger.info(f"Database written. Verified users count: {len(verify_db.users)}")

    except ValueError as e:
        logger.error(f"Error: {e}", err=True)
        raise click.Abort()
    except Exception as e:
        logger.error(f"Failed to add user: {e}", err=True)
        raise click.Abort()


@cli.command()
@click.option("-d", "--database", default="./.db.toml", help="Database file path")
@click.option("-j", "--json", "output_json", is_flag=True, help="Output as JSON")
@run_async
@logit
async def status(database: str, output_json: bool) -> None:
    """Display all users in the database."""
    try:
        db = await UserDB.read_from_file(database)
        if not db.users:
            click.echo("No users found in the database.")
            return

        if output_json:
            users_data = [
                {
                    "role": user.role,
                    "email": user.email,
                    "webid": user.webid,
                    "oidc": user.oidc,
                    "has_token": user.token is not None,
                    "token_id": user.token.id if user.token else None,
                }
                for user in db.users
            ]
            click.echo(json.dumps(users_data, indent=2))
        else:
            table = Table(title=f"Users in {database}")
            table.add_column("Role", style="cyan", no_wrap=True)
            table.add_column("Email", style="magenta")
            table.add_column("WebID", style="green", overflow="fold")
            table.add_column("OIDC Provider", style="yellow", overflow="fold")
            table.add_column("Token Status", style="red")

            for user in db.users:
                token_status = "✓ Valid" if user.token else "✗ None"
                table.add_row(
                    user.role,
                    user.email,
                    user.webid,
                    user.oidc,
                    token_status,
                )

            console = Console()
            console.print(table)
            console.print(f"\nTotal users: {len(db.users)}")

    except FileNotFoundError:
        click.echo(f"✗ Database file not found: {database}", err=True)
    except Exception as e:
        click.echo(f"✗ Error reading database: {e}", err=True)


@cli.command()
@click.option("-r", "--role", help="User to act as (uses default if not specified)")
@click.option("-u", "--uri", required=True, help="Target URI")
@click.option("-o", "--output", help="Output file (stdout if not specified)")
@click.option("-v", "--verbose", is_flag=True, help="Show response headers")
@logit
@run_async
async def get(role: str | None, uri: str, output: str | None, verbose: bool) -> None:
    """Fetch content from a URI using authenticated access."""
    if not validate_url(uri):
        click.echo(f"Error: '{uri}' is not a valid URL", err=True)
        return

    try:
        role = await get_role_with_default(role)
        response = await authenticated_get(role, uri)

        if verbose:
            click.echo(f"Status: {response.status_code}")
            click.echo(f"Headers: {dict(response.headers)}")
            click.echo("---")

        if response.status_code == 200:
            if output:
                with open(output, "w") as f:
                    f.write(response.text)
                click.echo(f"✓ Saved to {output}")
            else:
                click.echo(response.text)
        else:
            click.echo(f"✗ Request failed: {response.status_code}", err=True)
            if response.text:
                click.echo(response.text, err=True)

    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)


@cli.command()
@click.option("-r", "--role", help="User to act as (uses default if not specified)")
@click.option("-u", "--uri", required=True, help="Target URI")
@click.option("-d", "--data", required=True, help="File path or '-' for stdin")
@click.option(
    "-s",
    "--status",
    type=click.Choice(["public", "private"]),
    required=False,
    help="Visibility status",
)
@logit
@run_async
async def put(role: str | None, uri: str, data: str, status: str) -> None:
    """Upload content to a Solid pod with type index management."""
    role = await get_role_with_default(role)
    if data == "-":
        content = click.get_text_stream("stdin").read()
    else:
        try:
            with open(data, "r") as f:
                content = f.read()
        except FileNotFoundError:
            logger.error(f"File not found: {data}", err=True)
            return
        except Exception as e:
            logger.error(f"Error reading file: {e}", err=True)
            return

    user = await UserDB.get_user_by_role_from_file(role)
    if not user:
        click.echo(f"User '{role}' not found", err=True)
        return

    success = await upload_with_index(role, user, content, uri, status)

    if success:
        logger.info(f"Successfully uploaded to {uri} ({status})")
    else:
        logger.info("Failed to complete upload", err=True)


@cli.command()
@click.option("-r", "--role", help="User to act as (uses default if not specified)")
@click.option("-w", "--webid", required=True, help="WebID to check for content")
@click.option(
    "-f",
    "--format",
    type=click.Choice(["turtle", "n3", "json-ld"]),
    default="turtle",
    help="Output format",
)
@logit
@run_async
async def show(role: str | None, webid: str, format: str) -> None:
    """Show the type indexes and resources visible for a user."""
    role = await get_role_with_default(role)
    public_uri, private_uri = await get_type_index(role, webid)

    if not public_uri and not private_uri:
        raise ValueError("No type indexes found!")

    if public_uri and (
        public_graph := await display_type_index(role, public_uri, "public")
    ):
        click.echo(public_graph.serialize(format=format))

    if private_uri and (
        private_graph := await display_type_index(role, private_uri, "private")
    ):
        click.echo(private_graph.serialize(format=format))


@logit
def create_notification_graph(
    user: User, target_uri: str, notification_uri: str
) -> Graph:
    """Create an RDF graph for notification subscription.

    Args:
        user: User object with webid and oidc information
        target_uri: URI to subscribe to
        notification_uri: URI for the notification request

    Returns:
        RDF Graph with notification triples
    """
    notification_graph = Graph()
    notification_graph.bind("solid", SOLID)
    notification_graph.bind("dprod", DPROD)
    notification_graph.bind("foaf", FOAF)
    notification_graph.bind("dcat", DCAT)

    user_ref = URIRef(user.webid)
    oidc_ref = URIRef(user.oidc)
    notif_ref = URIRef(notification_uri)
    target_ref = URIRef(target_uri)

    notification_graph.add((user_ref, RDF.type, SOLID.Account))
    notification_graph.add((user_ref, RDF.type, FOAF.Agent))
    notification_graph.add((user_ref, SOLID.oidcIssuer, oidc_ref))
    notification_graph.add((user_ref, SOLID.notification, notif_ref))
    notification_graph.add((notif_ref, DCAT.accessURL, target_ref))

    return notification_graph


@cli.command()
@click.option("-r", "--role", help="User to act as (uses default if not specified)")
@click.option("-u", "--uri", required=True, help="URI to subscribe to")
# TODO: derive inbox from webid
@click.option(
    "-i",
    "--inbox-base",
    default="http://localhost:3000/dprod/inbox/",
    help="Base inbox URI",
)
@logit
@run_async
async def subscribe(role: str | None, uri: str, inbox_base: str) -> None:
    """Subscribe to notifications for content from a specific URI."""
    role = await get_role_with_default(role)
    user = await UserDB.get_user_by_role_from_file(role)
    if not user:
        click.echo(f"Error: User with role '{role}' not found.", err=True)
        return

    timestamp = datetime.now().timestamp()
    notification_uri = f"{inbox_base.rstrip('/')}/{timestamp}_req.ttl"

    g = create_notification_graph(user, uri, notification_uri)
    content = g.serialize(format="turtle")

    ctx = click.get_current_context()
    if ctx.obj and ctx.obj.get("verbose", False):
        click.echo(f"Notification content:\n{content}")

    try:
        res = await authenticated_put(role, content, notification_uri)
        if res.status_code in [200, 201, 204, 205]:
            click.echo(f"Successfully created notification at {notification_uri}")
        else:
            click.echo(f"Failed with status {res.status_code}: {res.text}", err=True)
    except Exception as e:
        click.echo(f"Error during subscription: {e}", err=True)


@cli.command()
@click.option("-r", "--role", help="User to act as (uses default if not specified)")
@click.option(
    "-i", "--inbox-uri", default="http://localhost:3000/dprod/inbox/", help="Inbox URI"
)
@logit
@run_async
async def inbox(role: str | None, inbox_uri: str) -> None:
    """View and manage inbox contents interactively."""
    role = await get_role_with_default(role)
    items = await get_inbox_items(role, inbox_uri)

    if not items:
        click.echo("No items found in inbox.")
        return

    display_inbox_items(items)

    selection = None
    while selection != 0:
        try:
            selection, should_quit = get_user_selection()

            if should_quit:
                break

            if selection is None:
                continue

            if selection == 0:
                break

            if not 1 <= selection <= len(items):
                click.echo("Invalid selection.", err=True)
                continue

            selected_uri = items[selection - 1]
            item_data = await process_inbox_item(role, selected_uri)

            if not item_data:
                click.echo(f"Failed to process item: {selected_uri}", err=True)
                continue

            click.echo(f"\n{'=' * 60}")
            click.echo(f"Item: {selected_uri}")
            click.echo(f"Access URLs: {len(item_data['access_urls'])}")

            for access_url in item_data["access_urls"]:
                should_continue = await handle_access_url(role, access_url)
                if not should_continue:
                    break

        except (KeyboardInterrupt, EOFError):
            click.echo("\nExiting...")
            break


def validate_url(url: str) -> bool:
    """Validate that a string is a well-formed URL."""
    try:
        parsed = urlparse(url)
        return all([parsed.scheme, parsed.netloc])
    except Exception:
        return False


@cli.command()
@click.option("-r", "--role", help="User to act as (uses default if not specified)")
@click.option("-u", "--uri", required=True, help="URI to fetch and edit")
@run_async
async def edit(role, uri):
    """
    Fetches content from a URL via HTTP GET, opens it in the user's preferred editor,
    and sends the edited content back via HTTP PUT.
    """
    role = await get_role_with_default(role)
    editor = os.environ.get("EDITOR", "nano")

    if not validate_url(uri):
        click.echo(f"Error: '{uri}' is not a valid URL", err=True)
        return

    try:
        logger.info(f"Fetching content from {uri}...")
        res = await authenticated_get(role, uri)
        original_content = res.text

        extension = None

        parsed_url = urlparse(uri)
        path = parsed_url.path
        if path and "/" in path:
            filename = path.rstrip("/").split("/")[-1]
            if "." in filename:
                extension = filename.split(".")[-1].lower()
                if extension not in [
                    "json",
                    "jsonld",
                    "ttl",
                    "n3",
                    "rdf",
                    "html",
                    "xml",
                    "txt",
                ]:
                    extension = None

        if not extension:
            content_type = (
                res.headers.get("Content-Type", "").split(";")[0].strip().lower()
            )
            content_type_map = {
                "application/json": "json",
                "application/ld+json": "jsonld",
                "text/turtle": "ttl",
                "text/n3": "n3",
                "application/rdf+xml": "rdf",
                "text/html": "html",
                "application/xhtml+xml": "html",
                "text/plain": "txt",
            }
            extension = content_type_map.get(content_type, "txt")

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=f".{extension}", delete=False
        ) as tmp_file:
            tmp_file.write(original_content)
            tmp_filename = tmp_file.name

        try:
            subprocess.run([editor, tmp_filename], check=True)

            with open(tmp_filename, "r") as f:
                edited_content = f.read()

            if edited_content != original_content:
                click.echo(f"Uploading edited content to {uri}...")
                try:
                    await authenticated_put(
                        role=role,
                        content=edited_content,
                        endpoint_url=uri,
                    )
                    click.echo(f"Successfully uploaded edited content to {uri}")
                except Exception as e:
                    click.echo(f"Error uploading content: {e}", err=True)
                    return
            else:
                click.echo("No changes detected, skipping upload.")

        finally:
            os.unlink(tmp_filename)

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

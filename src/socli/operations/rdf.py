from loguru import logger
from rdflib import Graph, URIRef, Namespace
from typing import Optional

from rdflib.namespace import RDF, FOAF, DCAT
from socli.user import User

from enum import Enum

ACL = Namespace("http://www.w3.org/ns/auth/acl#")
SOLID = Namespace("http://www.w3.org/ns/solid/terms#")
DPROD = Namespace("https://ekgf.github.io/dprod/")
LDP = Namespace("http://www.w3.org/ns/ldp#")


class ACLMode(Enum):
    """ACL permission modes"""

    READ = "Read"
    WRITE = "Write"
    CONTROL = "Control"
    APPEND = "Append"


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
    g = Graph()
    g.bind("solid", SOLID)
    g.bind("dprod", DPROD)
    g.bind("foaf", FOAF)
    g.bind("dcat", DCAT)

    user_ref = URIRef(user.webid)
    oidc_ref = URIRef(user.oidc)
    notif_ref = URIRef(notification_uri)
    target_ref = URIRef(target_uri)

    g.add((user_ref, RDF.type, SOLID.Account))
    g.add((user_ref, RDF.type, FOAF.Agent))
    g.add((user_ref, SOLID.oidcIssuer, oidc_ref))
    g.add((user_ref, SOLID.notification, notif_ref))
    g.add((notif_ref, DCAT.accessURL, target_ref))

    return g


# TODO: Dead code - check correlation with set acl
def add_agent_to_authorization(
    graph: Graph, agent_uri: str, modes: list[ACLMode], access_to: str = "./"
) -> None:
    """Add an agent with specific modes. If an authorization with exactly those modes exists, add the agent to it. Otherwise, create a new authorization."""

    query = """
        PREFIX acl: <http://www.w3.org/ns/auth/acl#>
        SELECT ?auth
        WHERE {
            ?auth a acl:Authorization ;
                  acl:accessTo ?resource .
        }
    """
    resource_uri = URIRef(access_to)
    candidate_auths = []
    for row in graph.query(query, initBindings={"resource": resource_uri}):
        if isinstance(row, tuple) and len(row) > 0:
            candidate_auths.append(row[0])
        elif not isinstance(row, tuple):
            candidate_auths.append(row)

    desired_modes = {ACL[mode.value] for mode in modes}
    found_auth = None

    for auth_uri in candidate_auths:
        current_modes = set(graph.objects(subject=auth_uri, predicate=ACL.mode))
        if current_modes == desired_modes:
            found_auth = auth_uri
            break

    if found_auth:
        logger.info(
            f"Found existing authorization {found_auth} with modes {[m.value for m in modes]}"
        )
        graph.add((found_auth, ACL.agent, URIRef(agent_uri)))
        logger.info(f"Added agent {agent_uri} to existing authorization {found_auth}")
    else:
        import hashlib

        modes_str = "_".join(sorted([m.value for m in modes]))
        hash_input = f"{access_to}_{modes_str}".encode()
        auth_id = f"auth_{hashlib.md5(hash_input).hexdigest()[:10]}"

        logger.info(
            f"Creating new authorization {auth_id} for {agent_uri} with modes {[m.value for m in modes]}"
        )
        create_authorization(
            graph, auth_id, agent_uri, access_to, modes, default_for=None
        )


# TODO: Dead code - check correlation with set acl
def remove_agent_from_authorization(
    graph: Graph, agent_uri: str, modes: Optional[list[ACLMode]] = None
) -> None:
    """Remove an agent from authorizations. If modes specified, only remove from
    authorizations that have ALL those modes."""
    if modes:
        mode_patterns = " .\n            ".join(
            [f"?auth acl:mode acl:{mode.value}" for mode in modes]
        )
        where_clause = f"""
            ?auth a acl:Authorization .
            ?auth acl:agent <{agent_uri}> .
            {mode_patterns} .
        """
    else:
        where_clause = f"""
            ?auth a acl:Authorization .
            ?auth acl:agent <{agent_uri}> .
        """

    query = f"""
        PREFIX acl: <http://www.w3.org/ns/auth/acl#>
        DELETE {{
            ?auth acl:agent <{agent_uri}> .
        }}
        WHERE {{
            {where_clause}
        }}
    """
    logger.info(f"Removing agent {agent_uri} from authorizations")
    graph.update(query)


# TODO: Dead code - check correlation with set acl
def create_authorization(
    graph: Graph,
    auth_id: str,
    agent_uri: str,
    access_to: str,
    modes: list[ACLMode],
    default_for: str | None,
) -> Graph:
    """Create a new authorization in the ACL graph."""
    auth_uri = URIRef(f"#{auth_id}")
    graph.add((auth_uri, RDF.type, ACL.Authorization))
    graph.add((auth_uri, ACL.agent, URIRef(agent_uri)))
    graph.add((auth_uri, ACL.accessTo, URIRef(access_to)))

    for mode in modes:
        graph.add((auth_uri, ACL.mode, ACL[mode.value]))

    if default_for:
        graph.add((auth_uri, ACL.default, URIRef(default_for)))

    logger.info(f"Created authorization {auth_id} for agent {agent_uri}")
    return graph


# TODO: Dead code - check correlation with set acl
def get_agents_with_mode(graph: Graph, mode: ACLMode) -> set[str]:
    """Get all agents that have a specific permission mode."""
    query = f"""
        PREFIX acl: <http://www.w3.org/ns/auth/acl#>
        SELECT DISTINCT ?agent
        WHERE {{
            ?auth a acl:Authorization .
            ?auth acl:mode acl:{mode.value} .
            ?auth acl:agent ?agent .
        }}
    """
    results = graph.query(query)
    agents = set()
    for row in results:
        agent = row[0] if isinstance(row, tuple) else row
        agents.add(str(agent))
    return agents


def get_agent_permissions(graph: Graph, agent_uri: str) -> dict[str, set[str]]:
    """Get all permissions for a specific agent."""
    query = f"""
        PREFIX acl: <http://www.w3.org/ns/auth/acl#>
        SELECT ?resource ?mode
        WHERE {{
            ?auth a acl:Authorization .
            ?auth acl:agent <{agent_uri}> .
            ?auth acl:accessTo ?resource .
            ?auth acl:mode ?mode .
        }}
    """

    results = graph.query(query)
    permissions: dict[str, set[str]] = {}

    for row in results:
        if isinstance(row, tuple) and len(row) >= 2:
            resource, mode = row[0], row[1]
        else:
            continue

        resource_str = str(resource)
        if resource_str not in permissions:
            permissions[resource_str] = set()

        mode_name = str(mode).split("#")[-1]
        permissions[resource_str].add(mode_name)

    return permissions


async def append_index(index, res, uri):
    g = Graph()
    g.parse(data=res.text, format="turtle", publicID=index)
    SOLID = Namespace("http://www.w3.org/ns/solid/terms#")
    DPROD = Namespace("https://ekgf.github.io/dprod/")
    g.bind("dprod", DPROD)
    g.bind("solid", SOLID)

    index_uri = URIRef(index)
    uri_ref = URIRef(uri)
    classification_class = DPROD.InformationSensitivityClassification

    triples_to_add = [
        (index_uri, SOLID.forClass, classification_class),
        (index_uri, SOLID.instance, uri_ref),
    ]

    for triple in triples_to_add:
        if triple not in g:
            g.add(triple)

    return g.serialize(format="turtle")


def set_acl(uri, owner_webid, acl_config=None) -> str:
    """Generate an ACL document with dynamic rights for the given URI."""
    if acl_config is None:
        acl_config = {
            "public": [],
            "authenticated": ["Read"],
            "owner": ["Read", "Write", "Control"],
        }

    graph = Graph()
    graph.bind("acl", ACL)
    graph.bind("foaf", FOAF)

    if acl_config.get("public"):
        public_auth = URIRef("#public")
        graph.add((public_auth, RDF.type, ACL.Authorization))
        graph.add((public_auth, ACL.agentClass, FOAF.Agent))
        graph.add((public_auth, ACL.accessTo, URIRef(uri)))
        for mode in acl_config["public"]:
            graph.add((public_auth, ACL.mode, ACL[mode]))

    if acl_config.get("authenticated"):
        auth_auth = URIRef("#authenticated")
        graph.add((auth_auth, RDF.type, ACL.Authorization))
        graph.add((auth_auth, ACL.agentClass, ACL.AuthenticatedAgent))
        graph.add((auth_auth, ACL.accessTo, URIRef(uri)))
        for mode in acl_config["authenticated"]:
            graph.add((auth_auth, ACL.mode, ACL[mode]))

    owner_auth = URIRef("#owner")
    graph.add((owner_auth, RDF.type, ACL.Authorization))
    graph.add((owner_auth, ACL.agent, URIRef(owner_webid)))
    graph.add((owner_auth, ACL.accessTo, URIRef(uri)))
    for mode in acl_config.get("owner", ["Read", "Write", "Control"]):
        graph.add((owner_auth, ACL.mode, ACL[mode]))

    return graph.serialize(format="turtle")

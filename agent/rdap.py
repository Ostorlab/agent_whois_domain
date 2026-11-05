"""RDAP lookups.

RDAP replaced WHOIS as the authoritative source of gTLD registration data, and
answers with JSON instead of the free text WHOIS returns. It does not cover
every TLD, and registries redact the registrant entity, so the caller still
needs WHOIS for the registrant's organisation and country.
"""

import functools
import json
import logging
import typing
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
TIMEOUT = 20
# The words whois reports for the same state, so both sources read alike.
SIGNED = "signedDelegation"
UNSIGNED = "unsigned"
# The event each date field is recorded under, as named by RFC 9083.
EVENT_FIELDS = {
    "registration": "creation_date",
    "expiration": "expiration_date",
    "last changed": "updated_date",
}


@functools.cache
def _bootstrap() -> dict[str, str]:
    """Map every TLD to its RDAP server, from IANA's bootstrap registry.

    The registry is read once, as it is around a megabyte and changes rarely.

    Returns:
        The server of each TLD that has one, empty when the registry is unreachable.
    """
    try:
        with urllib.request.urlopen(BOOTSTRAP_URL, timeout=TIMEOUT) as response:
            registry = json.load(response)
    except (
        OSError,
        ValueError,
    ) as e:
        logger.warning("Could not read the RDAP bootstrap registry: %s", e)
        return {}

    return {
        tld.lower(): service[1][0].rstrip("/")
        for service in registry.get("services", [])
        for tld in service[0]
    }


def fetch(domain: str) -> dict[str, typing.Any] | None:
    """Look a domain up over RDAP.

    Args:
        domain: The registrable domain to look up.

    Returns:
        The RDAP response, None when the TLD has no RDAP server or the lookup
        did not answer.
    """
    tld = domain.rsplit(".", 1)[-1].lower()
    server = _bootstrap().get(tld)
    if server is None:
        logger.info("No RDAP server for .%s, relying on whois for %s", tld, domain)
        return None

    request = urllib.request.Request(
        f"{server}/domain/{domain}", headers={"Accept": "application/rdap+json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return typing.cast(dict[str, typing.Any], json.load(response))
    except (
        OSError,
        ValueError,
    ) as e:
        logger.warning("RDAP lookup failed for %s: %s", domain, e)
        return None


def _vcard(entity: dict[str, typing.Any], name: str) -> typing.Any:
    """Read one property out of an entity's jCard.

    A registry that redacts a property keeps it with an empty value, which
    reads the same as the property being absent.
    """
    for entry in entity.get("vcardArray", [[], []])[1]:
        if entry[0] == name and entry[3] != "":
            return entry[3]
    return None


def parse(response: dict[str, typing.Any]) -> dict[str, typing.Any]:
    """Pull the registration records out of an RDAP response.

    The registrant's organisation and country are deliberately absent: registries
    redact that entity, so WHOIS remains the only source for them.

    Args:
        response: An RDAP domain response.

    Returns:
        The fields that carry a value, named as the whois parser names them.
    """
    parsed: dict[str, typing.Any] = {}

    entities = response.get("entities", [])
    registrar = next(
        (entity for entity in entities if "registrar" in entity.get("roles", [])), None
    )
    if registrar is not None:
        name = _vcard(registrar, "fn")
        if name is not None:
            parsed["registrar"] = name

    for event in response.get("events", []):
        field = EVENT_FIELDS.get(event.get("eventAction", ""))
        date = event.get("eventDate")
        if field is not None and date is not None:
            parsed[field] = [date]

    name_servers = [
        server["ldhName"].lower()
        for server in response.get("nameservers", [])
        if server.get("ldhName") is not None
    ]
    if len(name_servers) > 0:
        parsed["name_servers"] = sorted(set(name_servers))

    status = response.get("status", [])
    if len(status) > 0:
        parsed["status"] = status

    # RFC 9083 reports the chain as a flag rather than the word whois returns.
    delegation_signed = response.get("secureDNS", {}).get("delegationSigned")
    if delegation_signed is not None:
        parsed["dnssec"] = [SIGNED if delegation_signed is True else UNSIGNED]

    return parsed

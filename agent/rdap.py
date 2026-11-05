"""RDAP lookups.

RDAP replaced WHOIS as the authoritative source of gTLD registration data, and
answers with JSON instead of the free text WHOIS returns. It does not cover
every TLD, and registries redact the registrant entity, so the caller still
needs WHOIS for the registrant's organisation and country.
"""

import http.client
import json
import logging
import time
import typing
import urllib.request

logger = logging.getLogger(__name__)

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
TIMEOUT = 20
# How long an unreadable bootstrap registry is left alone before trying again.
RETRY_AFTER = 60
# The words whois reports for the same state, so both sources read alike.
SIGNED = "signedDelegation"
UNSIGNED = "unsigned"
# The event each date field is recorded under, as named by RFC 9083.
EVENT_FIELDS = {
    "registration": "creation_date",
    "expiration": "expiration_date",
    "last changed": "updated_date",
}


_SERVERS: dict[str, str] = {}
_FAILED_AT = 0.0


def _bootstrap() -> dict[str, str]:
    """Map every TLD to its RDAP server, from IANA's bootstrap registry.

    A reading is kept, as the registry is around a megabyte and changes rarely.
    A failed reading is not, so an outage does not disable RDAP for the rest of
    the agent's life, but it is not retried for every domain either: a reading
    is attempted again only once the retry window has passed.

    Returns:
        The server of each TLD that has one, empty when the registry could not
        be read.
    """
    global _FAILED_AT

    if len(_SERVERS) > 0:
        return _SERVERS
    if time.monotonic() - _FAILED_AT < RETRY_AFTER:
        return {}

    try:
        with urllib.request.urlopen(BOOTSTRAP_URL, timeout=TIMEOUT) as response:
            registry = json.load(response)
    except (
        OSError,
        ValueError,
        http.client.HTTPException,
    ) as e:
        _FAILED_AT = time.monotonic()
        logger.warning("Could not read the RDAP bootstrap registry: %s", e)
        return {}

    if not isinstance(registry, dict):
        logger.warning("The RDAP bootstrap registry is not an object")
        return {}

    for service in registry.get("services", []):
        if len(service) < 2 or len(service[1]) == 0:
            continue
        for tld in service[0]:
            _SERVERS[tld.lower()] = service[1][0].rstrip("/")
    return _SERVERS


def fetch(domain: str) -> dict[str, typing.Any] | None:
    """Look a domain up over RDAP.

    Args:
        domain: The registrable domain to look up.

    Returns:
        The RDAP response, None when the TLD has no RDAP server or the lookup
        did not answer.
    """
    try:
        # The registry keys TLDs by their A-label and a URL carries the ASCII
        # form, so an internationalised domain is encoded before either.
        hostname = domain.encode("idna").decode("ascii")
    except UnicodeError as e:
        logger.warning("Could not encode %s for an RDAP lookup: %s", domain, e)
        return None

    tld = hostname.rsplit(".", 1)[-1].lower()
    server = _bootstrap().get(tld)
    if server is None:
        logger.info("No RDAP server for .%s, relying on whois for %s", tld, domain)
        return None

    request = urllib.request.Request(
        f"{server}/domain/{hostname}", headers={"Accept": "application/rdap+json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return typing.cast(dict[str, typing.Any], json.load(response))
    except (
        OSError,
        ValueError,
        http.client.HTTPException,
    ) as e:
        logger.warning("RDAP lookup failed for %s: %s", domain, e)
        return None


def _dicts(value: typing.Any) -> list[dict[str, typing.Any]]:
    """Read a response member as a list of objects.

    A registry may send any of these members as null, as a single object or as
    a list holding something other than objects, so anything else reads as an
    empty list.
    """
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _vcard(entity: dict[str, typing.Any], name: str) -> typing.Any:
    """Read one property out of an entity's jCard.

    A registry that redacts a property keeps it with an empty value, which
    reads the same as the property being absent.
    """
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None

    for entry in vcard[1]:
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

    registrar = next(
        (
            entity
            for entity in _dicts(response.get("entities"))
            if "registrar" in (entity.get("roles") or [])
        ),
        None,
    )
    if registrar is not None:
        name = _vcard(registrar, "fn")
        if name is not None:
            parsed["registrar"] = name

    for event in _dicts(response.get("events")):
        field = EVENT_FIELDS.get(event.get("eventAction", ""))
        date = event.get("eventDate")
        if field is not None and date is not None:
            parsed[field] = [date]

    name_servers = [
        server["ldhName"].lower()
        for server in _dicts(response.get("nameservers"))
        if isinstance(server.get("ldhName"), str)
    ]
    if len(name_servers) > 0:
        parsed["name_servers"] = sorted(set(name_servers))

    status = response.get("status")
    if isinstance(status, str):
        status = [status]
    if isinstance(status, list) and len(status) > 0:
        parsed["status"] = status

    # RFC 9083 reports the chain as a flag rather than the word whois returns.
    secure_dns = response.get("secureDNS")
    if isinstance(secure_dns, dict):
        delegation_signed = secure_dns.get("delegationSigned")
        if delegation_signed is not None:
            parsed["dnssec"] = [SIGNED if delegation_signed is True else UNSIGNED]

    return parsed

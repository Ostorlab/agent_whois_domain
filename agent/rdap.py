"""RDAP lookups.

RDAP replaced WHOIS as the authoritative source of gTLD registration data, and
answers with JSON instead of the free text WHOIS returns. It does not cover
every TLD, and many registries redact the registrant entity, so the registrant's
organisation and country are read from the registrar's record the registry links to,
else from the registry's own.
"""

import http.client
import json
import logging
import time
import typing
import urllib.error
import urllib.request

import tenacity

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
# The media type a registry's link to the registrar's RDAP record carries.
RDAP_MEDIA_TYPE = "application/rdap+json"
# A server that answers HTTP 429 is asked again this many times in all, waiting longer each time.
RATE_LIMITED_ATTEMPTS = 3
RATE_LIMITED_STATUS = 429


_SERVERS: dict[str, str] = {}
_FAILED_AT: float | None = None


def _bootstrap(user_agent: str) -> dict[str, str]:
    """Map every TLD to its RDAP server, from IANA's bootstrap registry.

    A reading is kept, as the registry is around a megabyte and changes rarely.
    A failed reading is not, so an outage does not disable RDAP for the rest of
    the agent's life, but it is not retried for every domain either: a reading
    is attempted again only once the retry window has passed.

    Args:
        user_agent: The User-Agent the request identifies the agent with.

    Returns:
        The server of each TLD that has one, empty when the registry could not
        be read.
    """
    global _FAILED_AT

    if len(_SERVERS) > 0:
        return _SERVERS
    if _FAILED_AT is not None and time.monotonic() - _FAILED_AT < RETRY_AFTER:
        return {}

    request = urllib.request.Request(BOOTSTRAP_URL, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
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


def fetch(domain: str, user_agent: str) -> dict[str, typing.Any] | None:
    """Look a domain up over RDAP.

    Args:
        domain: The registrable domain to look up.
        user_agent: The User-Agent the requests identify the agent with.

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
    server = _bootstrap(user_agent).get(tld)
    if server is None:
        logger.info("No RDAP server for .%s, relying on whois for %s", tld, domain)
        return None

    return _lookup(f"{server}/domain/{hostname}", domain, user_agent)


def fetch_registrar(
    response: dict[str, typing.Any], domain: str, user_agent: str
) -> dict[str, typing.Any] | None:
    """Follow a registry's RDAP answer to the registrar's record of the domain.

    Args:
        response: The registry's RDAP answer.
        domain: The domain the answer is about.
        user_agent: The User-Agent the request identifies the agent with.

    Returns:
        The registrar's RDAP answer, None when the registry links none or the
        lookup did not answer.
    """
    url = _registrar_link(response)
    if url is None:
        return None
    return _lookup(url, domain, user_agent)


def _registrar_link(response: dict[str, typing.Any]) -> str | None:
    """Return the https URL of the registrar's RDAP record the registry links to."""
    for link in _dicts(response.get("links")):
        href = link.get("href")
        if link.get("rel") != "related" or link.get("type") != RDAP_MEDIA_TYPE:
            continue
        if isinstance(href, str) and href.startswith("https://"):
            return href
    return None


def _lookup(url: str, domain: str, user_agent: str) -> dict[str, typing.Any] | None:
    """Return the RDAP answer at a URL, None when it did not answer with an object."""
    request = urllib.request.Request(
        url, headers={"Accept": RDAP_MEDIA_TYPE, "User-Agent": user_agent}
    )
    try:
        answer = _read(request)
    except (
        OSError,
        ValueError,
        http.client.HTTPException,
    ) as e:
        logger.warning("RDAP lookup failed for %s: %s", domain, e)
        return None

    if not isinstance(answer, dict):
        logger.warning("The RDAP answer for %s is not an object", domain)
        return None
    return answer


def _is_rate_limited(error: BaseException) -> bool:
    """Tell whether a request failed because the server asks to slow down."""
    return (
        isinstance(error, urllib.error.HTTPError) and error.code == RATE_LIMITED_STATUS
    )


@tenacity.retry(
    retry=tenacity.retry_if_exception(_is_rate_limited),
    stop=tenacity.stop_after_attempt(RATE_LIMITED_ATTEMPTS),
    wait=tenacity.wait_exponential(multiplier=1, min=1, max=4),
    reraise=True,
)
def _read(request: urllib.request.Request) -> typing.Any:
    """Return the JSON a request answers with, asking again after an HTTP 429."""
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.load(response)


def _dicts(value: typing.Any) -> list[dict[str, typing.Any]]:
    """Read a response member as a list of objects.

    A registry may send any of these members as null, as a single object or as
    a list holding something other than objects, so anything else reads as an
    empty list.
    """
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _entity(response: dict[str, typing.Any], role: str) -> dict[str, typing.Any] | None:
    """Return the first entity of a response that holds a role."""
    for entity in _dicts(response.get("entities")):
        roles = entity.get("roles")
        if isinstance(roles, list) and role in roles:
            return entity
    return None


def _vcard_property(
    entity: dict[str, typing.Any], name: str
) -> list[typing.Any] | None:
    """Read one property out of an entity's jCard, with its parameters.

    A registry that redacts a property keeps it with an empty value, which
    reads the same as the property being absent.
    """
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    if not isinstance(vcard[1], list):
        return None

    for entry in vcard[1]:
        # A jCard property is a list of four, the value last.
        if not isinstance(entry, list) or len(entry) < 4:
            continue
        if entry[0] == name and entry[3] != "":
            return entry
    return None


def _vcard(entity: dict[str, typing.Any], name: str) -> typing.Any:
    """Read the value of one property out of an entity's jCard."""
    entry = _vcard_property(entity, name)
    if entry is None:
        return None
    return entry[3]


def parse(response: dict[str, typing.Any]) -> dict[str, typing.Any]:
    """Pull the registration records out of an RDAP response.

    The registrant is left to parse_registrant.

    Args:
        response: An RDAP domain response.

    Returns:
        The fields that carry a value, named as the whois parser names them.
    """
    parsed: dict[str, typing.Any] = {}

    registrar = _entity(response, "registrar")
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


def parse_registrant(response: dict[str, typing.Any]) -> dict[str, str]:
    """Pull the registrant's organisation and country out of an RDAP answer.

    Args:
        response: A registrar's or registry's RDAP domain response.

    Returns:
        The organisation and country the answer publishes, redaction notices
        included, named as the whois parser names them.
    """
    registrant = _entity(response, "registrant")
    if registrant is None:
        return {}

    parsed: dict[str, str] = {}
    org = _non_blank(_organisation(registrant))
    if org is not None:
        parsed["org"] = org
    country = _non_blank(_country(registrant))
    if country is not None:
        parsed["country"] = country
    return parsed


def _organisation(entity: dict[str, typing.Any]) -> str | None:
    """Return the organisation name of an entity, the first part of a structured one."""
    org = _vcard(entity, "org")
    if isinstance(org, list) and len(org) > 0:
        org = org[0]
    if not isinstance(org, str):
        return None
    return org


def _country(entity: dict[str, typing.Any]) -> str | None:
    """Return the country code of an entity's address, else the country it names."""
    address = _vcard_property(entity, "adr")
    if address is None:
        return None

    parameters = address[1]
    code = parameters.get("cc") if isinstance(parameters, dict) else None
    if isinstance(code, str) and code.strip() != "":
        return code
    # The country name is the last of an address's seven parts.
    parts = address[3]
    if isinstance(parts, list) and len(parts) >= 7 and isinstance(parts[6], str):
        return parts[6]
    return None


def _non_blank(value: str | None) -> str | None:
    """Return a value without surrounding blanks, None when nothing is left."""
    if value is None:
        return None
    value = value.strip()
    if value == "":
        return None
    return value

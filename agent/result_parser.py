"""Module to parse whois_domain scan results."""

import datetime
import re
from collections.abc import Iterator
from typing import Any

import email_validator
import whois

OPTIONAL_FIELDS = [
    "registrar",
    "whois_server",
    "referral_url",
    "address",
    "city",
    "state",
    "zipcode",
]
# The keys TLD parsers store the registrant's organisation and country under, preferred first.
ORG_FIELDS = ["org", "registrant_org", "registrant_organization"]
COUNTRY_FIELDS = ["country", "registrant_country"]

UNDISCLOSED_VALUE = "<data not disclosed>"

# Ends the registry's record; python-whois appends the registrar's referral answer after it.
REGISTRY_RECORD_END = re.compile(r">>> Last update of WHOIS database", re.IGNORECASE)
ORG_LINE = re.compile(r"^Registrant Organization:(.*)$", re.IGNORECASE | re.MULTILINE)
COUNTRY_LINE = re.compile(r"^Registrant Country:(.*)$", re.IGNORECASE | re.MULTILINE)
NAME_SERVER_LINE = re.compile(r"^Name Server:(.*)$", re.IGNORECASE | re.MULTILINE)
DNSSEC_LINE = re.compile(r"^DNSSEC:(.*)$", re.IGNORECASE | re.MULTILINE)
# The ICANN link written after an EPP status code.
STATUS_LINK = re.compile(r"\s+\(?https?://\S*$")


def parse_results(results: whois.parser.WhoisCom) -> Iterator[dict[str, Any]]:
    """Parses whois_domain scan results.

    Args:
       results: Scan results returned by whois_domain.

    Returns:
       The parsed output of the whois_domain scan results.
    """
    scan_output_dict = dict(results)
    registry_record = _registry_record(results)
    names = set()
    for name in get_list_from_string(scan_output_dict.pop("domain_name", "")):
        if name is not None:
            names.add(name.lower())

    for name in names:
        if name != "":
            found_emails = get_list_from_string(
                scan_output_dict.get("email") or scan_output_dict.get("emails", "")
            )
            output: dict[str, str | list[str] | None] = {
                "updated_date": get_isoformat(scan_output_dict.get("updated_date", [])),
                "creation_date": get_isoformat(
                    scan_output_dict.get("creation_date", [])
                ),
                "expiration_date": get_isoformat(
                    scan_output_dict.get("expiration_date", [])
                ),
                "name": name,
                "emails": [email for email in found_emails if _is_valid_email(email)],
                "status": _status_codes(
                    get_list_from_string(scan_output_dict.get("status", ""))
                ),
                "name_servers": _normalize_name_servers(
                    _name_servers(scan_output_dict, registry_record)
                ),
                "contact_names": get_list_from_string(scan_output_dict.get("name", "")),
                "dnssec": _dnssec(scan_output_dict, registry_record),
                "org": _registrant_value(
                    scan_output_dict, ORG_FIELDS, registry_record, ORG_LINE
                ),
                "country": _registrant_value(
                    scan_output_dict, COUNTRY_FIELDS, registry_record, COUNTRY_LINE
                ),
            }

            for field in OPTIONAL_FIELDS:
                if field in scan_output_dict:
                    value = scan_output_dict[field]
                    output[field] = _format_str(value) if value is not None else value
            yield output


def get_isoformat(
    date_name: datetime.datetime | list[datetime.datetime],
) -> list[str]:
    """Converts dates to ISO format

    Args:
       date_name (Union[datetime.datetime, List[datetime.datetime]]): _description_

    Returns:
       A list of ISO date formats.
    """
    if date_name is None:
        return []
    elif isinstance(date_name, list):
        return [
            date_obj.isoformat()
            for date_obj in date_name
            if isinstance(date_obj, datetime.datetime)
        ]
    elif isinstance(date_name, datetime.datetime):
        return [date_name.isoformat()]
    else:
        return []


def get_list_from_string(scan_output_value: str | list[str]) -> list[str]:
    """Checks if the value of an attribute is a string and puts it in a list.

    Args:
       scan_output_value: The value to convert

    Returns:
       A list from the scan_output_value, empty for an empty or undisclosed string.
    """
    if isinstance(scan_output_value, str):
        if scan_output_value in ("", UNDISCLOSED_VALUE):
            return []
        return [scan_output_value]
    else:
        return scan_output_value or []


def _registry_record(results: whois.parser.WhoisCom) -> str:
    """Returns the registry's record from the raw answer, without the registrar's referral."""
    if not isinstance(results, whois.parser.WhoisEntry):
        return ""
    raw_text: str = results.text
    return REGISTRY_RECORD_END.split(raw_text, maxsplit=1)[0]


def _registry_values(registry_record: str, line: re.Pattern[str]) -> list[str]:
    """Returns the non-empty values of a line in the registry's record."""
    values = [value.strip() for value in line.findall(registry_record)]
    return [value for value in values if value != ""]


def _registrant_value(
    scan_output: dict[str, Any],
    fields: list[str],
    registry_record: str,
    line: re.Pattern[str],
) -> str | None:
    """Returns the first parsed field holding a value, else the registry record's line."""
    for field in fields:
        value = scan_output.get(field)
        if value is not None and len(value) > 0:
            return _format_str(value)
    registry_values = _registry_values(registry_record, line)
    if len(registry_values) == 0:
        return None
    return registry_values[0]


def _name_servers(scan_output: dict[str, Any], registry_record: str) -> list[str]:
    """Returns the parsed name servers, else the registry record's without a trailing dot."""
    name_servers = get_list_from_string(scan_output.get("name_servers", ""))
    if len(name_servers) > 0:
        return name_servers
    return [
        server.rstrip(".")
        for server in _registry_values(registry_record, NAME_SERVER_LINE)
    ]


def _dnssec(scan_output: dict[str, Any], registry_record: str) -> list[str]:
    """Returns the parsed DNSSEC state, else the registry record's."""
    dnssec = get_list_from_string(scan_output.get("dnssec", ""))
    if len(dnssec) > 0:
        return dnssec
    return _registry_values(registry_record, DNSSEC_LINE)


def _status_codes(statuses: list[str]) -> list[str]:
    """Returns each status code once, in first-seen order, without its ICANN link."""
    codes = [STATUS_LINK.sub("", status) for status in statuses]
    return list(dict.fromkeys(codes))


def _normalize_name_servers(name_servers: list[str]) -> list[str]:
    """Normalizes name servers to lowercase and removes duplicates."""
    return list({ns.lower() for ns in name_servers})


def _format_str(value: str | list[str]) -> str:
    """Handles string or list of strings and returns a single string."""
    return value if isinstance(value, str) else " ".join(value)


def _is_valid_email(value: str) -> bool:
    """Checks if a given value is a valid email.

    Args:
        value: The value to check.

    Returns:
        True if it is a valid email. False Otherwise
    """
    try:
        email_validator.validate_email(value)
        return True
    except email_validator.EmailNotValidError:
        return False

"""Module to parse whois_domain scan results."""
import datetime
import re
from typing import Any, Union, List, Dict, Iterator
import whois

OPTIONAL_FIELDS = [
    "registrar",
    "whois_server",
    "referral_url",
    "org",
    "address",
    "city",
    "state",
    "zipcode",
    "country",
]

UNDISCLOSED_VALUE = "<data not disclosed>"
EMAIL_REGEX = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"


def parse_results(results: whois.parser.WhoisCom) -> Iterator[Dict[str, Any]]:
    """Parses whois_domain scan results.

    Args:
       results: Scan results returned by whois_domain.

    Returns:
       The parsed output of the whois_domain scan results.
    """
    scan_output_dict = dict(results)
    names = set()
    for name in get_list_from_string(scan_output_dict.pop("domain_name", "")):
        if name is not None:
            names.add(name.lower())

    for name in names:
        if name != "":
            found_emails = get_list_from_string(
                scan_output_dict.get("email") or scan_output_dict.get("emails", "")
            )
            valid_emails = [
                email for email in found_emails if re.match(EMAIL_REGEX, email)
            ]

            output: dict[str, str | list[str] | None] = {
                "updated_date": get_isoformat(scan_output_dict.get("updated_date", [])),
                "creation_date": get_isoformat(
                    scan_output_dict.get("creation_date", [])
                ),
                "expiration_date": get_isoformat(
                    scan_output_dict.get("expiration_date", [])
                ),
                "name": name,
                "emails": valid_emails,
                "status": get_list_from_string(scan_output_dict.get("status", "")),
                "name_servers": get_list_from_string(
                    scan_output_dict.get("name_servers", "")
                ),
                "contact_names": get_list_from_string(scan_output_dict.get("name", "")),
                "dnssec": get_list_from_string(scan_output_dict.get("dnssec", "")),
            }

            for field in OPTIONAL_FIELDS:
                if field in scan_output_dict:
                    value = scan_output_dict[field]
                    output[field] = _format_str(value) if value is not None else value
            yield output


def get_isoformat(
    date_name: Union[datetime.datetime, List[datetime.datetime]],
) -> List[str]:
    """Converts dates to ISO fomat

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


def get_list_from_string(scan_output_value: Union[str, List[str]]) -> List[str]:
    """Checks if the value of an attribute is a string and puts it in a list.

    Args:
       scan_output_value: The value to convert

    Returns:
       A list from the scan_output_value.
    """
    if isinstance(scan_output_value, str):
        if scan_output_value == UNDISCLOSED_VALUE:
            return []
        return [scan_output_value]
    else:
        return scan_output_value or []


def _format_str(value: str | List[str]) -> str:
    """Handles string or list of strings and returns a single string."""
    return value if isinstance(value, str) else " ".join(value)

"""Module to parse whois_domain scan results."""
import datetime
import copy
from typing import Any, Union, List, Dict, Iterator

import whois


def parse_results(results: whois.parser.WhoisCom) -> Iterator[Dict[str, Any]]:
    """Parses whois_domain scan results.

    Args:
       results: Scan results returned by whois_domain.

    Returns:
       The parsed output of the whois_domain scan results.
    """

    scan_output_dict = dict(results)
    names = set()
    for name in get_list_from_string(scan_output_dict.pop('domain_name', '')):
        if name is not None:
            names.add(name.lower())

    contact_name = scan_output_dict.pop('name', '')
    for name in names:
        output = copy.deepcopy(scan_output_dict)
        output['updated_date'] = get_isoformat(scan_output_dict['updated_date'])
        output['creation_date'] = get_isoformat(scan_output_dict['creation_date'])
        output['expiration_date'] = get_isoformat(scan_output_dict['expiration_date'])
        output['name'] = name
        output['emails'] = get_list_from_string(scan_output_dict['emails'])
        output['status'] = get_list_from_string(scan_output_dict['status'])
        output['name_servers'] = get_list_from_string(scan_output_dict['name_servers'])
        output['contact_name'] = contact_name
        yield output


def get_isoformat(date_name: Union[datetime.datetime, List[datetime.datetime]]) -> List[str]:
    """Converts dates to ISO fomat

    Args:
       date_name (Union[datetime.datetime, List[datetime.datetime]]): _description_

    Returns:
       A list of ISO date formats.
    """
    if date_name is None:
        return []
    elif isinstance(date_name, list):
        return [date_obj.isoformat() for date_obj in date_name]
    else:
        return [date_name.isoformat()]


def get_list_from_string(scan_output_value: Union[str, List[str]]) -> List[str]:
    """Checks if the value of an attribute is a string and puts it in a list.

    Args:
       scan_output_value: The value to convert

    Returns:
       A list from the scan_output_value.
    """
    if isinstance(scan_output_value, str):
        return [scan_output_value]
    else:
        return scan_output_value or []

"""Unit tests for the whois result parser."""

import whois

from agent import result_parser


def testParseResults_whenMeParserUsesRegistrantOrg_shouldReturnTheOrg(
    proton_me_whois: whois.parser.WhoisEntry,
) -> None:
    """Ensure that the .me registrant_org is returned as org."""
    output = next(result_parser.parse_results(proton_me_whois))

    assert output["org"] == "Proton AG"


def testParseResults_whenAiParserUsesRegistrantOrg_shouldReturnTheOrg(
    scale_ai_whois: whois.parser.WhoisEntry,
) -> None:
    """Ensure that the .ai registrant_org is returned as org."""
    output = next(result_parser.parse_results(scale_ai_whois))

    assert output["org"] == "Scale AI"


def testParseResults_whenItParserUsesRegistrantOrganization_shouldReturnTheOrg(
    ferrari_it_whois: whois.parser.WhoisEntry,
) -> None:
    """Ensure that registrant_organization is returned as org."""
    output = next(result_parser.parse_results(ferrari_it_whois))

    assert output["org"] == "Ferrari S.p.A."


def testParseResults_whenComAnswer_shouldKeepTheParsedOrg(
    microsoft_com_whois: whois.parser.WhoisEntry,
) -> None:
    """Ensure that a .com answer keeps the org python-whois parses."""
    output = next(result_parser.parse_results(microsoft_com_whois))

    assert output["org"] == "Microsoft Corporation"


def testParseResults_whenOrgIsRedacted_shouldReturnTheRedactionNotice(
    cloudflare_com_whois: whois.parser.WhoisEntry,
) -> None:
    """Ensure that a redaction notice is returned as the organisation."""
    output = next(result_parser.parse_results(cloudflare_com_whois))

    assert output["org"] == "DATA REDACTED"


def testParseResults_whenOrgAndRegistrantOrgAreSet_shouldPreferOrg() -> None:
    """Ensure that org wins over registrant_org."""
    scan_output = {
        "domain_name": "example.com",
        "org": "Example Org",
        "registrant_org": "Other Org",
    }

    output = next(result_parser.parse_results(scan_output))

    assert output["org"] == "Example Org"


def testParseResults_whenNoOrgField_shouldReturnNoOrg() -> None:
    """Ensure that a missing organisation is returned as None."""
    output = next(result_parser.parse_results({"domain_name": "example.com"}))

    assert output["org"] is None

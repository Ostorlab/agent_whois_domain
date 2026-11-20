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


def testParseResults_whenMeParserMissesTheCountry_shouldReadItFromTheRegistryRecord(
    proton_me_whois: whois.parser.WhoisEntry,
) -> None:
    """Ensure that the .me country is read from the registry record."""
    output = next(result_parser.parse_results(proton_me_whois))

    assert output["country"] == "CH"


def testParseResults_whenAiParserUsesRegistrantCountry_shouldReturnTheCountry(
    scale_ai_whois: whois.parser.WhoisEntry,
) -> None:
    """Ensure that registrant_country is returned as country."""
    output = next(result_parser.parse_results(scale_ai_whois))

    assert output["country"] == "US"


def testParseResults_whenIoAnswer_shouldReturnTheCountry(
    docker_io_whois: whois.parser.WhoisEntry,
) -> None:
    """Ensure that the .io registrant country is returned."""
    output = next(result_parser.parse_results(docker_io_whois))

    assert output["country"] == "US"


def testParseResults_whenCaParserHasNoCountryKey_shouldReadItFromTheRegistryRecord(
    shopify_ca_whois: whois.parser.WhoisEntry,
) -> None:
    """Ensure that the .ca country is read from the registry record."""
    output = next(result_parser.parse_results(shopify_ca_whois))

    assert output["country"] == "CA"


def testParseResults_whenComAnswer_shouldKeepTheParsedCountry(
    microsoft_com_whois: whois.parser.WhoisEntry,
) -> None:
    """Ensure that a .com answer keeps the country python-whois parses."""
    output = next(result_parser.parse_results(microsoft_com_whois))

    assert output["country"] == "US"


def testParseResults_whenRegistryCountryIsEmpty_shouldNotReadTheReferral(
    proton_me_whois_with_empty_registry_values: whois.parser.WhoisEntry,
) -> None:
    """Ensure that an empty registry country is ignored and the referral is not read."""
    output = next(
        result_parser.parse_results(proton_me_whois_with_empty_registry_values)
    )

    assert output["country"] is None


def testParseResults_whenCountryAndRegistrantCountryAreSet_shouldPreferCountry() -> (
    None
):
    """Ensure that country wins over registrant_country."""
    scan_output = {
        "domain_name": "example.com",
        "country": "FR",
        "registrant_country": "DE",
    }

    output = next(result_parser.parse_results(scan_output))

    assert output["country"] == "FR"


def testParseResults_whenNoCountryField_shouldReturnNoCountry() -> None:
    """Ensure that a missing country is returned as None."""
    output = next(result_parser.parse_results({"domain_name": "example.com"}))

    assert output["country"] is None

"""Unit tests for the RDAP lookups."""

from typing import Any

from pytest_mock import plugin

from agent import rdap

RDAP_RESPONSE: dict[str, Any] = {
    "ldhName": "ebay.com",
    "status": ["client delete prohibited", "client transfer prohibited"],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-04T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2026-08-03T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2025-07-01T09:12:33Z"},
        {
            "eventAction": "last update of RDAP database",
            "eventDate": "2026-11-05T00:00:00Z",
        },
    ],
    "nameservers": [{"ldhName": "NS1.EBAY.COM"}, {"ldhName": "ns2.ebay.com"}],
    "secureDNS": {"delegationSigned": False},
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "MarkMonitor Inc."],
                ],
            ],
        }
    ],
}


def testRdapParse_whenFullResponse_returnsTheRegistrationRecords() -> None:
    """Ensure that the registration records are read out of the response."""
    parsed = rdap.parse(RDAP_RESPONSE)

    assert parsed["registrar"] == "MarkMonitor Inc."
    assert parsed["creation_date"] == ["1995-08-04T04:00:00Z"]
    assert parsed["expiration_date"] == ["2026-08-03T04:00:00Z"]
    assert parsed["updated_date"] == ["2025-07-01T09:12:33Z"]
    assert parsed["name_servers"] == ["ns1.ebay.com", "ns2.ebay.com"]
    assert parsed["status"] == [
        "client delete prohibited",
        "client transfer prohibited",
    ]


def testRdapParse_always_leavesTheRegistrantOut() -> None:
    """Ensure that the registrant fields are not sourced from RDAP."""
    parsed = rdap.parse(RDAP_RESPONSE)

    assert "org" not in parsed
    assert "country" not in parsed


def testRdapParse_whenFieldsAreAbsent_leavesThemOut() -> None:
    """Ensure that a sparse response yields only what it carries."""
    parsed = rdap.parse({"ldhName": "example.com"})

    assert parsed == {}


def testRdapFetch_whenTldHasNoServer_returnsNone(
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure that a TLD outside the bootstrap registry is not looked up."""
    mocker.patch.object(
        rdap, "_bootstrap", return_value={"com": "https://rdap.example"}
    )
    urlopen = mocker.patch("urllib.request.urlopen")

    assert rdap.fetch("ostorlab.co") is None
    urlopen.assert_not_called()


def testRdapFetch_whenLookupFails_returnsNone(
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure that an unanswered lookup falls back rather than raising."""
    mocker.patch.object(
        rdap, "_bootstrap", return_value={"com": "https://rdap.example"}
    )
    mocker.patch("urllib.request.urlopen", side_effect=OSError("boom"))

    assert rdap.fetch("ebay.com") is None


def testRdapParse_whenDelegationIsSigned_reportsItAsWhoisWould() -> None:
    """Ensure that the signed chain is reported with the word whois uses."""
    parsed = rdap.parse({"secureDNS": {"delegationSigned": True}})

    assert parsed["dnssec"] == ["signedDelegation"]


def testRdapParse_whenSecureDnsIsAbsent_leavesDnssecOut() -> None:
    """Ensure that a response without secureDNS reports no dnssec."""
    assert "dnssec" not in rdap.parse({"ldhName": "example.com"})


def testRdapParse_whenTheRegistrarNameIsRedacted_leavesItOut() -> None:
    """Ensure that a property emptied by a registry is treated as absent."""
    parsed = rdap.parse(
        {
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", ""]]],
                }
            ]
        }
    )

    assert "registrar" not in parsed

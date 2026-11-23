"""Unit tests for the RDAP lookups."""

import http.client
from typing import Any
from unittest import mock

import pytest
from pytest_mock import plugin

from agent import rdap


@pytest.fixture(autouse=True)
def clear_bootstrap_cache() -> None:
    """Keep a reading, or a failure, made by one test out of the next."""
    rdap._SERVERS.clear()
    rdap._FAILED_AT = None


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


def testRdapFetch_whenTldIsInternationalised_looksUpItsALabel(
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure that the registry is keyed by the A-label, not the unicode TLD."""
    mocker.patch.object(
        rdap, "_bootstrap", return_value={"xn--q9jyb4c": "https://rdap.example"}
    )
    urlopen = mocker.patch("urllib.request.urlopen", side_effect=OSError("stop here"))

    rdap.fetch("nic.\u307f\u3093\u306a")

    assert (
        urlopen.call_args.args[0].full_url
        == "https://rdap.example/domain/nic.xn--q9jyb4c"
    )


def testRdapBootstrap_whenTheRegistryIsUnreachable_readsItAgainNextTime(
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure that an outage does not disable RDAP for the rest of the run."""
    urlopen = mocker.patch("urllib.request.urlopen", side_effect=OSError("down"))

    assert rdap._bootstrap() == {}
    rdap._FAILED_AT = None  # as if the retry window had passed
    assert rdap._bootstrap() == {}

    assert urlopen.call_count == 2


def testRdapBootstrap_whenTheRegistryIsRead_keepsIt(
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure that a successful reading is not fetched twice."""
    registry = {"services": [[["com"], ["https://rdap.example/com/"]]]}
    response = mocker.MagicMock()
    response.__enter__.return_value = response
    mocker.patch("urllib.request.urlopen", return_value=response)
    urlopen = mocker.patch("json.load", return_value=registry)

    assert rdap._bootstrap() == {"com": "https://rdap.example/com"}
    assert rdap._bootstrap() == {"com": "https://rdap.example/com"}

    assert urlopen.call_count == 1


def testRdapBootstrap_whenAReadingJustFailed_doesNotDownloadItAgain(
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure that an outage does not stall every domain on the download."""
    urlopen = mocker.patch("urllib.request.urlopen", side_effect=OSError("down"))

    assert rdap._bootstrap() == {}
    assert rdap._bootstrap() == {}

    assert urlopen.call_count == 1


def testRdapParse_whenSecureDnsIsNull_leavesDnssecOut() -> None:
    """Ensure that a null secureDNS is treated as absent rather than raising."""
    assert "dnssec" not in rdap.parse({"secureDNS": None})


def testRdapParse_whenTheVcardIsMalformed_leavesTheRegistrarOut() -> None:
    """Ensure that a redacted vCard is skipped rather than raising."""
    for vcard in (
        [],
        None,
        ["vcard"],
        ["vcard", None],
        ["vcard", [None]],
        ["vcard", [["fn"]]],
        ["vcard", "fn"],
    ):
        parsed = rdap.parse(
            {"entities": [{"roles": ["registrar"], "vcardArray": vcard}]}
        )

        assert "registrar" not in parsed


MALFORMED: list[dict[str, Any]] = [
    {"entities": None},
    {"entities": "registrar"},
    {"entities": [None]},
    {"entities": [{"roles": None}]},
    {"entities": [{"roles": "registrar"}]},
    {"events": None},
    {"events": [None]},
    {"events": "registration"},
    {"nameservers": None},
    {"nameservers": [None]},
    {"nameservers": [{"ldhName": None}]},
    {"status": None},
    {"secureDNS": None},
    {"secureDNS": "signed"},
]


@pytest.mark.parametrize("response", MALFORMED)
def testRdapParse_whenTheResponseIsMalformed_readsItAsEmpty(
    response: dict[str, Any],
) -> None:
    """Ensure that no shape a registry can send escapes as an exception."""
    assert rdap.parse(response) == {}


def testRdapParse_whenStatusIsAString_emitsItAsAList() -> None:
    """Ensure that the field keeps one shape whichever source answered."""
    parsed = rdap.parse({"status": "client transfer prohibited"})

    assert parsed["status"] == ["client transfer prohibited"]


def testRdapBootstrap_whenTheRegistryIsMalformed_readsItAsEmpty(
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure that a payload that is not the registry does not raise."""
    response = mocker.MagicMock()
    response.__enter__.return_value = response
    mocker.patch("urllib.request.urlopen", return_value=response)
    mocker.patch("json.load", return_value=["not", "the", "registry"])

    assert rdap._bootstrap() == {}


def testRdapBootstrap_whenAServiceHasNoServer_skipsIt(
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure that a service entry carrying no URL is passed over."""
    response = mocker.MagicMock()
    response.__enter__.return_value = response
    mocker.patch("urllib.request.urlopen", return_value=response)
    mocker.patch(
        "json.load",
        return_value={
            "services": [[["dead"], []], [["com"], ["https://rdap.example/com/"]]]
        },
    )

    assert rdap._bootstrap() == {"com": "https://rdap.example/com"}


def testRdapBootstrap_whenTheMachineJustBooted_stillReadsTheRegistry(
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure the retry window does not hold on a clock that started near zero."""
    mocker.patch("time.monotonic", return_value=3.0)
    urlopen = mocker.patch("urllib.request.urlopen", side_effect=OSError("down"))

    rdap._bootstrap()

    assert urlopen.call_count == 1


@pytest.mark.parametrize("answer", [None, ["a"], "text", 3])
def testRdapFetch_whenTheAnswerIsNotAnObject_returnsNone(
    answer: Any, mocker: plugin.MockerFixture
) -> None:
    """Ensure that a 200 carrying something other than an object is not used."""
    mocker.patch.object(
        rdap, "_bootstrap", return_value={"com": "https://rdap.example"}
    )
    response = mocker.MagicMock()
    response.__enter__.return_value = response
    mocker.patch("urllib.request.urlopen", return_value=response)
    mocker.patch("json.load", return_value=answer)

    assert rdap.fetch("ebay.com") is None


def testRdapFetchRegistrar_whenTheRegistryLinksTheRegistrar_returnsItsAnswer(
    techcrunch_com_rdap: dict[str, Any],
    rdap_servers: mock.MagicMock,
) -> None:
    """Ensure that the registrar's RDAP record linked by the registry is looked up."""
    answer = rdap.fetch_registrar(techcrunch_com_rdap, "techcrunch.com")

    assert answer is not None
    assert answer["port43"] == "whois.markmonitor.com"
    assert (
        rdap_servers.call_args.args[0].full_url
        == "https://rdap.markmonitor.com/rdap/domain/TECHCRUNCH.COM"
    )


UNUSABLE_LINKS: list[Any] = [
    None,
    "https://rdap.markmonitor.com/rdap/domain/TECHCRUNCH.COM",
    [],
    [None],
    [
        {
            "rel": "self",
            "type": "application/rdap+json",
            "href": "https://rdap.verisign.com/com/v1/domain/techcrunch.com",
        }
    ],
    [{"rel": "related", "type": "text/html", "href": "https://www.markmonitor.com"}],
    [
        {
            "rel": "related",
            "type": "application/rdap+json",
            "href": "http://rdap.markmonitor.com/rdap/domain/TECHCRUNCH.COM",
        }
    ],
    [{"rel": "related", "type": "application/rdap+json"}],
    [{"rel": "related", "type": "application/rdap+json", "href": None}],
]


@pytest.mark.parametrize("links", UNUSABLE_LINKS)
def testRdapFetchRegistrar_whenTheRegistryLinksNoRegistrarRecord_returnsNone(
    links: Any, mocker: plugin.MockerFixture
) -> None:
    """Ensure that only an https link to an RDAP record is followed."""
    urlopen = mocker.patch("urllib.request.urlopen")

    assert rdap.fetch_registrar({"links": links}, "techcrunch.com") is None
    urlopen.assert_not_called()


@pytest.mark.parametrize(
    "error",
    [
        OSError("timed out"),
        ValueError("not JSON"),
        http.client.HTTPException("bad status line"),
    ],
)
def testRdapFetchRegistrar_whenTheRegistrarLookupFails_returnsNone(
    error: Exception,
    techcrunch_com_rdap: dict[str, Any],
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure that an unanswered registrar lookup is skipped rather than raising."""
    mocker.patch("urllib.request.urlopen", side_effect=error)

    assert rdap.fetch_registrar(techcrunch_com_rdap, "techcrunch.com") is None


def testRdapParseRegistrant_whenTheRegistrarPublishesOrgAndCountry_readsBoth(
    arstechnica_com_registrar_rdap: dict[str, Any],
) -> None:
    """Ensure that the registrant's org and country are read from the registrar."""
    parsed = rdap.parse_registrant(arstechnica_com_registrar_rdap)

    assert parsed == {"org": "Advance Magazine Publishers Inc.", "country": "US"}


def testRdapParseRegistrant_whenTheRegistrarHidesTheOrg_readsOnlyTheCountry(
    techcrunch_com_registrar_rdap: dict[str, Any],
) -> None:
    """Ensure that an org the registrar leaves out is not reported."""
    parsed = rdap.parse_registrant(techcrunch_com_registrar_rdap)

    assert parsed == {"country": "US"}


def testRdapParseRegistrant_whenTheAnswerHasNoRegistrant_returnsNothing(
    techcrunch_com_rdap: dict[str, Any],
) -> None:
    """Ensure that a registry answer, which carries no registrant, yields nothing."""
    assert rdap.parse_registrant(techcrunch_com_rdap) == {}


def _registrant(*properties: list[Any]) -> dict[str, Any]:
    """Builds an RDAP answer whose registrant's jCard holds the given properties."""
    return {
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"], *properties]],
            }
        ]
    }


@pytest.mark.parametrize(
    "notice",
    [
        "REDACTED FOR PRIVACY",
        "DATA REDACTED",
        "Data Protected",
        "<data not disclosed>",
        "Domains By Proxy, LLC",
    ],
)
def testRdapParseRegistrant_whenValuesAreNoticesOrProxies_keepsThemAsPublished(
    notice: str,
) -> None:
    """Ensure that what the registrar publishes is reported, redaction notices and proxies included."""
    parsed = rdap.parse_registrant(
        _registrant(
            ["org", {}, "text", notice],
            ["adr", {"cc": notice}, "text", ["", "", "", "", "", "", ""]],
        )
    )

    assert parsed == {"org": notice, "country": notice}


def testRdapParseRegistrant_whenValuesAreBlank_leavesThemOut() -> None:
    """Ensure that an org or country emptied by the registrar is treated as absent."""
    parsed = rdap.parse_registrant(
        _registrant(
            ["org", {}, "text", "   "],
            ["adr", {"cc": " "}, "text", ["", "", "", "", "", "", "  "]],
        )
    )

    assert parsed == {}


def testRdapParseRegistrant_whenTheRegistryPublishesTheRegistrant_readsIt(
    lemonde_fr_rdap: dict[str, Any],
) -> None:
    """Ensure that a registry's own answer yields the registrant it publishes."""
    parsed = rdap.parse_registrant(lemonde_fr_rdap)

    assert parsed == {"org": "SOCIETE EDITRICE DU MONDE", "country": "FR"}


def testRdapParseRegistrant_whenTheAddressHasNoCc_readsItsCountryPart() -> None:
    """Ensure that the country part of the address stands in for a missing cc."""
    parsed = rdap.parse_registrant(
        _registrant(["adr", {}, "text", ["", "", "", "", "", "", "Switzerland"]])
    )

    assert parsed == {"country": "Switzerland"}


def testRdapParseRegistrant_whenTheOrgIsStructured_readsItsName() -> None:
    """Ensure that an org with units reports the organisation's name."""
    parsed = rdap.parse_registrant(
        _registrant(["org", {}, "text", ["Proton AG", "Legal"]])
    )

    assert parsed == {"org": "Proton AG"}


@pytest.mark.parametrize(
    "properties",
    [
        [["org", {}, "text", None]],
        [["org", {}, "text", []]],
        [["org", {}, "text", [3]]],
        [["adr", None, "text", None]],
        [["adr", {"cc": 3}, "text", "Paris"]],
        [["adr", {}, "text", ["", ""]]],
        [["adr", {}, "text", ["", "", "", "", "", "", ["FR"]]]],
    ],
)
def testRdapParseRegistrant_whenTheJcardIsMalformed_readsItAsEmpty(
    properties: list[list[Any]],
) -> None:
    """Ensure that no registrant shape a registrar can send escapes as an exception."""
    assert rdap.parse_registrant(_registrant(*properties)) == {}

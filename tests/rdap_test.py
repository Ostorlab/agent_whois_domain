"""Unit tests for the RDAP lookups."""

from typing import Any

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

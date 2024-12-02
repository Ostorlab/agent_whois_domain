"""Unittests for whois_domain agent."""

import datetime
from typing import Any, List

import pytest
from ostorlab.agent.message import message
from pytest_mock import plugin

from agent import whois_domain_agent

SCAN_OUTPUT = {
    "domain_name": "test.ostorlab.co",
    "registrar": "Tucows Domains Inc.",
    "whois_server": "whois.opensrs.net",
    "referral_url": None,
    "updated_date": datetime.datetime.fromisoformat("2018-12-08 10:36:41"),
    "creation_date": datetime.datetime.fromisoformat("2015-01-27 22:03:32"),
    "expiration_date": datetime.datetime.fromisoformat("2023-01-26 23:59:59"),
    "name_servers": [
        "nirvana.easydns.net",
        "motorhead.easydns.org",
        "rush.easydns.com",
    ],
    "status": [
        "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
        "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
    ],
    "email": ["abuse@godaddy.com"],
    "dnssec": "unsigned",
    "name": ["Catherine Shapiro", "Ivan SLY"],
    "org": "Contact Privacy Inc. Customer 0139267634",
    "address": "REDACTED FOR PRIVACY",
    "city": "REDACTED FOR PRIVACY",
    "state": "ON",
    "zipcode": "REDACTED FOR PRIVACY",
    "country": "CA",
}

SCAN_OUTPUT_WITH_ENPTY_DOMAIN = {
    "domain_name": "",
    "registrar": "Tucows Domains Inc.",
    "whois_server": "whois.opensrs.net",
    "referral_url": None,
    "updated_date": datetime.datetime.fromisoformat("2018-12-08 10:36:41"),
    "creation_date": datetime.datetime.fromisoformat("2015-01-27 22:03:32"),
    "expiration_date": datetime.datetime.fromisoformat("2023-01-26 23:59:59"),
    "name_servers": [
        "nirvana.easydns.net",
        "motorhead.easydns.org",
        "rush.easydns.com",
    ],
    "status": [
        "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
        "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
    ],
    "email": ["abuse@godaddy.com"],
    "dnssec": "unsigned",
    "name": ["Catherine Shapiro", "Ivan SLY"],
    "org": "Contact Privacy Inc. Customer 0139267634",
    "address": "REDACTED FOR PRIVACY",
    "city": "REDACTED FOR PRIVACY",
    "state": "ON",
    "zipcode": "REDACTED FOR PRIVACY",
    "country": "CA",
}

SCAN_OUTPUT_LIST = {
    "domain_name": ["test.ostorlab.co", "TEST.OSTORLAB.CO"],
    "registrar": "Tucows Domains Inc.",
    "whois_server": "whois.opensrs.net",
    "referral_url": None,
    "updated_date": datetime.datetime.fromisoformat("2018-12-08 10:36:41"),
    "creation_date": datetime.datetime.fromisoformat("2015-01-27 22:03:32"),
    "expiration_date": datetime.datetime.fromisoformat("2023-01-26 23:59:59"),
    "name_servers": [
        "nirvana.easydns.net",
        "motorhead.easydns.org",
        "rush.easydns.com",
    ],
    "status": [
        "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
        "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
    ],
    "email": ["compliance@tucows.com", "easydns@myprivacy.ca"],
    "dnssec": "unsigned",
    "name": ["Catherine Shapiro", "Ivan SLY"],
    "org": "Contact Privacy Inc. Customer 0139267634",
    "address": "REDACTED FOR PRIVACY",
    "city": "REDACTED FOR PRIVACY",
    "state": "ON",
    "zipcode": "REDACTED FOR PRIVACY",
    "country": "CA",
}

SCAN_OUTPUT_MULTIPLE_CONTACT_NAMES = {
    "domain_name": "marksandspencer.at",
    "registrar": "Key-Systems GmbH ( https://nic.at/registrar/404 )",
    "name": ["Catherine Shapiro", "Ivan SLY"],
    "org": ["Marks And Spencer P.l.c.", "IP TWINS S.A.S."],
    "address": ["Waterside House", "35 North Wharf Road", "78 rue de Turbigo"],
    "registrant_postal_code": ["W2 1NW", "75003"],
    "city": ["London", "PARIS"],
    "country": ["United Kingdom of Great Britain and Northern Ireland (the)", "France"],
    "phone": ["+442087186494", "+33142789312"],
    "fax": "+440207487267",
    "updated_date": [
        datetime.datetime(2021, 6, 23, 10, 10, 57),
        datetime.datetime(2021, 6, 23, 10, 7, 2),
        datetime.datetime(2023, 1, 4, 19, 30, 24),
    ],
    "email": ["externaldnssupport@marks-and-spencer.com", "ivan.sly@iptwins.com"],
}

SCAN_OUTPUT_NO_CONTACT_NAMES = {
    "domain_name": "marksandspencer.at",
    "registrar": "Key-Systems GmbH ( https://nic.at/registrar/404 )",
    "name": [],
    "org": ["Marks And Spencer P.l.c.", "IP TWINS S.A.S."],
    "address": ["Waterside House", "35 North Wharf Road", "78 rue de Turbigo"],
    "registrant_postal_code": ["W2 1NW", "75003"],
    "city": ["London", "PARIS"],
    "country": ["United Kingdom of Great Britain and Northern Ireland (the)", "France"],
    "phone": ["+442087186494", "+33142789312"],
    "fax": "+440207487267",
    "updated_date": [
        datetime.datetime(2021, 6, 23, 10, 10, 57),
        datetime.datetime(2021, 6, 23, 10, 7, 2),
        datetime.datetime(2023, 1, 4, 19, 30, 24),
    ],
    "email": ["externaldnssupport@marks-and-spencer.com", "ivan.sly@iptwins.com"],
}


def testAgentWhois_whenDomainNameAsset_emitsMessages(
    scan_message: message.Message,
    test_agent: whois_domain_agent.AgentWhoisDomain,
    agent_persist_mock: Any,
    mocker: plugin.MockerFixture,
    agent_mock: List[message.Message],
) -> None:
    """Tests running the agent and emitting vulnerabilities."""
    del agent_persist_mock

    mock_whois = mocker.patch("whois.whois", return_value=SCAN_OUTPUT)
    test_agent.start()
    test_agent.process(scan_message)
    mock_whois.assert_called_once()
    assert len(agent_mock) > 0
    assert agent_mock[0].selector == "v3.asset.domain_name.whois"
    assert agent_mock[0].data["name"] == "test.ostorlab.co"
    assert agent_mock[0].data["updated_date"] == ["2018-12-08T10:36:41"]
    assert agent_mock[0].data["creation_date"] == ["2015-01-27T22:03:32"]
    assert agent_mock[0].data["expiration_date"] == ["2023-01-26T23:59:59"]
    assert agent_mock[0].data["emails"] == ["abuse@godaddy.com"]


def testAgentWhois_whenMultipleContactNames_emitsMessages(
    scan_message: message.Message,
    test_agent: whois_domain_agent.AgentWhoisDomain,
    agent_persist_mock: Any,
    mocker: plugin.MockerFixture,
    agent_mock: List[message.Message],
) -> None:
    """Tests running the agent and emitting vulnerabilities."""
    del agent_persist_mock

    mock_whois = mocker.patch(
        "whois.whois", return_value=SCAN_OUTPUT_MULTIPLE_CONTACT_NAMES
    )
    test_agent.start()
    test_agent.process(scan_message)
    mock_whois.assert_called_once()

    assert len(agent_mock) > 0
    assert agent_mock[0].selector == "v3.asset.domain_name.whois"
    assert agent_mock[0].data["name"] == "marksandspencer.at"
    assert agent_mock[0].data["updated_date"] == [
        "2021-06-23T10:10:57",
        "2021-06-23T10:07:02",
        "2023-01-04T19:30:24",
    ]
    assert agent_mock[0].data["emails"] == [
        "externaldnssupport@marks-and-spencer.com",
        "ivan.sly@iptwins.com",
    ]
    assert agent_mock[0].data["contact_names"] == ["Catherine Shapiro", "Ivan SLY"]


def testAgentWhois_whenNoContactNames_emitsMessages(
    scan_message: message.Message,
    test_agent: whois_domain_agent.AgentWhoisDomain,
    agent_persist_mock: Any,
    mocker: plugin.MockerFixture,
    agent_mock: List[message.Message],
) -> None:
    """Tests running the agent and emitting vulnerabilities."""
    del agent_persist_mock

    mock_whois = mocker.patch("whois.whois", return_value=SCAN_OUTPUT_NO_CONTACT_NAMES)
    test_agent.start()
    test_agent.process(scan_message)
    mock_whois.assert_called_once()

    assert len(agent_mock) > 0
    assert agent_mock[0].selector == "v3.asset.domain_name.whois"
    assert agent_mock[0].data["name"] == "marksandspencer.at"
    assert agent_mock[0].data["updated_date"] == [
        "2021-06-23T10:10:57",
        "2021-06-23T10:07:02",
        "2023-01-04T19:30:24",
    ]
    assert agent_mock[0].data["emails"] == [
        "externaldnssupport@marks-and-spencer.com",
        "ivan.sly@iptwins.com",
    ]
    assert "contact_names" not in agent_mock[0].data


def testAgentWhois_whenDomainNameInputIsEmpty_NotEmitsMessages(
    scan_message_not_valid: message.Message,
    test_agent: whois_domain_agent.AgentWhoisDomain,
    agent_persist_mock: Any,
    mocker: plugin.MockerFixture,
    agent_mock: List[message.Message],
) -> None:
    """Tests running the agent and emitting vulnerabilities."""
    del agent_persist_mock

    mock_whois = mocker.patch("whois.whois")
    test_agent.start()
    test_agent.process(scan_message_not_valid)
    mock_whois.assert_not_called()
    assert len(agent_mock) == 0


def testAgentWhois_whenDomainNameIsEmpty_notEmitsMessages(
    scan_message: message.Message,
    test_agent: whois_domain_agent.AgentWhoisDomain,
    agent_persist_mock: Any,
    mocker: plugin.MockerFixture,
    agent_mock: List[message.Message],
) -> None:
    """Tests running the agent and emitting vulnerabilities."""
    del agent_persist_mock

    mock_whois = mocker.patch("whois.whois", return_value=SCAN_OUTPUT_WITH_ENPTY_DOMAIN)
    test_agent.start()
    test_agent.process(scan_message)
    mock_whois.assert_called_once()
    assert len(agent_mock) == 0


def testAgentWhois_whenDomainNameListAsset_emitsMessages(
    scan_message: message.Message,
    test_agent: whois_domain_agent.AgentWhoisDomain,
    agent_persist_mock: Any,
    mocker: plugin.MockerFixture,
    agent_mock: List[message.Message],
) -> None:
    """Tests running the agent and emitting vulnerabilities."""
    del agent_persist_mock

    mock_whois = mocker.patch("whois.whois", return_value=SCAN_OUTPUT_LIST)
    test_agent.start()
    test_agent.process(scan_message)
    mock_whois.assert_called_once()
    assert len(agent_mock) > 0
    assert agent_mock[0].selector == "v3.asset.domain_name.whois"
    assert agent_mock[0].data["name"] == "test.ostorlab.co"


def testAgentWhois_withBug1750_RunScan(
    bug_1750_message: message.Message,
    test_agent: whois_domain_agent.AgentWhoisDomain,
    agent_persist_mock: Any,
    agent_mock: List[message.Message],
) -> None:
    """Tests running the agent and emitting vulnerabilities."""
    del agent_persist_mock

    test_agent.start()
    test_agent.process(bug_1750_message)

    assert len(agent_mock) > 0
    assert agent_mock[0].selector == "v3.asset.domain_name.whois"
    assert agent_mock[0].data["name"] == "ostorlab.co"
    assert agent_mock[0].data["updated_date"] == ["2023-01-30T06:57:45"]
    assert agent_mock[0].data["creation_date"] == ["2015-01-27T22:03:32"]
    assert agent_mock[0].data["expiration_date"] == ["2027-01-26T23:59:59"]
    assert agent_mock[0].data["emails"] == [
        "compliance@tucows.com",
        "easydns@myprivacy.ca",
    ]
    assert agent_mock[0].data["address"] == "REDACTED FOR PRIVACY"


def testAgentWhois_withBug3001_RunScan(
    bug_3001_message: message.Message,
    test_agent: whois_domain_agent.AgentWhoisDomain,
    agent_persist_mock: Any,
    agent_mock: List[message.Message],
) -> None:
    """Tests running the agent and emitting vulnerabilities."""
    del agent_persist_mock

    test_agent.start()
    test_agent.process(bug_3001_message)

    assert len(agent_mock) > 0
    assert agent_mock[0].selector == "v3.asset.domain_name.whois"
    assert agent_mock[0].data["name"] == "rexel.it"


def testAgentWhois_withDomainScopeArgAndDomainMessageInScope_emitsMessages(
    test_agent_with_scope_arg: whois_domain_agent.AgentWhoisDomain,
    agent_persist_mock: Any,
    mocker: plugin.MockerFixture,
    agent_mock: List[message.Message],
) -> None:
    """Ensure the domain scope argument is enforced, and domains in the scope should be scanned."""
    del agent_persist_mock
    selector = "v3.asset.domain_name"
    msg_data = {
        "name": "a.b.c.d.medallia.com",
    }
    scan_message = message.Message.from_data(selector, data=msg_data)
    mock_whois = mocker.patch("whois.whois", return_value=SCAN_OUTPUT)

    test_agent_with_scope_arg.start()
    test_agent_with_scope_arg.process(scan_message)

    mock_whois.assert_called_once()
    assert len(agent_mock) > 0
    assert agent_mock[0].selector == "v3.asset.domain_name.whois"
    assert agent_mock[0].data["name"] == "test.ostorlab.co"
    assert agent_mock[0].data["emails"] == ["abuse@godaddy.com"]


def testAgentWhois_withDomainScopeArgAndDomainMessageNotInScope_targetShouldNotBeScanned(
    test_agent_with_scope_arg: whois_domain_agent.AgentWhoisDomain,
    agent_persist_mock: Any,
    mocker: plugin.MockerFixture,
    agent_mock: List[message.Message],
) -> None:
    """Ensure the domain scope argument is enforced, and domains not in the scope should not be scanned."""
    del agent_persist_mock
    selector = "v3.asset.domain_name"
    msg_data = {
        "name": "ostorlab.com",
    }
    scan_message = message.Message.from_data(selector, data=msg_data)
    mock_whois = mocker.patch("whois.whois", return_value=SCAN_OUTPUT)

    test_agent_with_scope_arg.start()
    test_agent_with_scope_arg.process(scan_message)

    assert mock_whois.called == 0
    assert len(agent_mock) == 0


def testAgentWhois_whenDifferentSubdomainsRecevied_onlyFldIsProcessed(
    test_agent: whois_domain_agent.AgentWhoisDomain,
    agent_persist_mock: Any,
    mocker: plugin.MockerFixture,
    agent_mock: List[message.Message],
) -> None:
    """Tests running the agent and emitting vulnerabilities."""
    del agent_persist_mock

    mock_whois = mocker.patch("whois.whois", return_value=SCAN_OUTPUT_LIST)
    test_agent.start()
    test_agent.process(
        message.Message.from_data(
            "v3.asset.domain_name",
            data={
                "name": "foobar.ostorlab.co",
            },
        )
    )
    test_agent.process(
        message.Message.from_data(
            "v3.asset.domain_name",
            data={
                "name": "toto.ostorlab.co",
            },
        )
    )
    mock_whois.assert_called_once()
    assert len(agent_mock) > 0
    assert agent_mock[0].selector == "v3.asset.domain_name.whois"
    assert agent_mock[0].data["name"] == "test.ostorlab.co"


def testAgentWhois_whenEmailIsNotDisclosed_shouldNotEmitEmails(
    test_agent: whois_domain_agent.AgentWhoisDomain,
    mocker: plugin.MockerFixture,
    agent_persist_mock: Any,
    agent_mock: list[message.Message],
) -> None:
    del agent_persist_mock
    mocker.patch(
        "whois.whois", return_value={**SCAN_OUTPUT, "email": "<data not disclosed>"}
    )

    test_agent.process(
        message.Message.from_data(
            "v3.asset.domain_name",
            data={
                "name": "test.co",
            },
        )
    )

    assert agent_mock[0].data.get("emails") is None


def testAgentWhois_whenDomainNameAssetInvalidTLD_emitsMessages(
    electro_scan_message: message.Message,
    test_agent: whois_domain_agent.AgentWhoisDomain,
    agent_persist_mock: Any,
    mocker: plugin.MockerFixture,
    agent_mock: List[message.Message],
) -> None:
    """Tests running the agent and emitting vulnerabilities."""
    del agent_persist_mock

    test_agent.start()
    test_agent.process(electro_scan_message)

    assert len(agent_mock) > 0
    assert agent_mock[0].selector == "v3.asset.domain_name.whois"
    assert "electrohold.bg" in agent_mock[0].data["name"]


def testAgentWhois_whenConnectionError_shouldRetry(
    scan_message: message.Message,
    test_agent: whois_domain_agent.AgentWhoisDomain,
    agent_persist_mock: Any,
    mocker: plugin.MockerFixture,
    agent_mock: List[message.Message],
) -> None:
    """Tests running the agent shouldn't crash when connection error occur."""
    del agent_persist_mock
    mocker.patch("time.sleep")
    mock_whois = mocker.patch("whois.whois", side_effect=ConnectionResetError)

    test_agent.start()
    test_agent.process(scan_message)

    assert mock_whois.call_count == 3


def testAgentWhois_whenWhoisUnicodeError_doesNotCrash(
    scan_message: message.Message,
    test_agent: whois_domain_agent.AgentWhoisDomain,
    agent_persist_mock: Any,
    mocker: plugin.MockerFixture,
    agent_mock: List[message.Message],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The agent should not crash when UnicodeError occurs."""
    del agent_persist_mock
    mocker.patch("time.sleep")
    mock_whois = mocker.patch(
        "whois.whois", side_effect=UnicodeError("Invalid character '�'")
    )

    test_agent.start()
    test_agent.process(scan_message)

    assert (
        "Unicode error when fetching whois for medallia.com : Invalid character"
        in caplog.text
    )
    assert mock_whois.called == 1
    assert len(agent_mock) == 0

"""Unittests for whois_domain agent."""
import datetime
from typing import List, Any

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
    "emails": ["abuse@godaddy.com"],
    "dnssec": "unsigned",
    "name": "REDACTED FOR PRIVACY",
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
    "emails": ["compliance@tucows.com", "easydns@myprivacy.ca"],
    "dnssec": "unsigned",
    "name": "REDACTED FOR PRIVACY",
    "org": "Contact Privacy Inc. Customer 0139267634",
    "address": "REDACTED FOR PRIVACY",
    "city": "REDACTED FOR PRIVACY",
    "state": "ON",
    "zipcode": "REDACTED FOR PRIVACY",
    "country": "CA",
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


def testAgentWhois_withBug_RunScan(
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
    assert agent_mock[0].data["updated_date"] == ["2018-12-08T10:36:41"]
    assert agent_mock[0].data["creation_date"] == ["2015-01-27T22:03:32"]
    assert agent_mock[0].data["expiration_date"] == ["2023-01-26T23:59:59"]
    assert agent_mock[0].data["emails"] == [
        "compliance@tucows.com",
        "easydns@myprivacy.ca",
    ]
    assert agent_mock[0].data["address"] == "REDACTED FOR PRIVACY"

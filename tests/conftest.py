"""Pytest fixture for the whois domain agent."""

import json
import pathlib

import pytest
import whois
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import definitions

from agent import whois_domain_agent

WHOIS_ANSWERS = pathlib.Path(__file__).parent / "files"


def _read_whois_answer(domain: str) -> str:
    """Reads a saved WHOIS answer, keeping its line endings."""
    return (WHOIS_ANSWERS / f"{domain}.txt").read_text(encoding="utf-8", newline="")


def _load_whois_answer(domain: str) -> whois.parser.WhoisEntry:
    """Parses a saved WHOIS answer the way python-whois parses a live one."""
    return whois.parser.WhoisEntry.load(domain, _read_whois_answer(domain))


@pytest.fixture
def proton_me_whois() -> whois.parser.WhoisEntry:
    """The .me registry's answer for proton.me followed by the registrar's referral."""
    return _load_whois_answer("proton.me")


@pytest.fixture
def scale_ai_whois() -> whois.parser.WhoisEntry:
    """The .ai answer for scale.ai, parsed into registrant_org and registrant_country."""
    return _load_whois_answer("scale.ai")


@pytest.fixture
def ferrari_it_whois() -> whois.parser.WhoisEntry:
    """The .it answer for ferrari.it, parsed into registrant_organization."""
    return _load_whois_answer("ferrari.it")


@pytest.fixture
def microsoft_com_whois() -> whois.parser.WhoisEntry:
    """The .com answer for microsoft.com, parsed into org and country."""
    return _load_whois_answer("microsoft.com")


@pytest.fixture
def cloudflare_com_whois() -> whois.parser.WhoisEntry:
    """The .com answer for cloudflare.com, whose registrar redacts the organisation."""
    return _load_whois_answer("cloudflare.com")


@pytest.fixture
def proton_me_message() -> message.Message:
    """Creates a v3.asset.domain_name message for proton.me."""
    return message.Message.from_data("v3.asset.domain_name", data={"name": "proton.me"})


@pytest.fixture
def scan_message_not_valid() -> message.Message:
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes."""
    selector = "v3.asset.domain_name"
    msg_data = {
        "name": "test",
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_bad_character() -> message.Message:
    """Creates a dummy message with invalid domain name to test error handling."""
    selector = "v3.asset.domain_name"
    msg_data = {
        "name": "meda�llia.com",
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message() -> message.Message:
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes."""
    selector = "v3.asset.domain_name"
    msg_data = {
        "name": "medallia.com",
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def electro_scan_message() -> message.Message:
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes."""
    selector = "v3.asset.domain_name"
    msg_data = {
        "name": "electrohold.bg",
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def test_agent() -> whois_domain_agent.AgentWhoisDomain:
    """Creates a dummy agent for the Whois Domain Agent."""

    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/whois_domain",
            bus_url="NA",
            bus_exchange_topic="NA",
            redis_url="redis://redis",
            args=[],
            healthcheck_port=0,
        )
        return whois_domain_agent.AgentWhoisDomain(definition, settings)


@pytest.fixture
def test_agent_with_scope_arg() -> whois_domain_agent.AgentWhoisDomain:
    """Creates a dummy agent for the Whois Domain Agent with the scope_domain_regex set."""

    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/whois_domain",
            bus_url="NA",
            bus_exchange_topic="NA",
            redis_url="redis://redis",
            args=[
                definitions.Arg(
                    name="scope_domain_regex",
                    type="string",
                    value=json.dumps(".*medallia.com").encode(),
                ),
            ],
            healthcheck_port=0,
        )
        return whois_domain_agent.AgentWhoisDomain(definition, settings)


@pytest.fixture
def bug_1750_message() -> message.Message:
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes."""
    selector = "v3.asset.domain_name"
    msg_data = {
        "name": "ostorlab.co",
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def bug_3001_message() -> message.Message:
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes."""
    selector = "v3.asset.domain_name"
    msg_data = {
        "name": "rexel.it",
    }
    return message.Message.from_data(selector, data=msg_data)

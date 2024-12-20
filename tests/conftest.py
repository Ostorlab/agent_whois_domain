"""Pytest fixture for the whois domain agent."""

import pathlib
import random
import json

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.agent.message import message
from ostorlab.utils import definitions

from agent import whois_domain_agent


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
            healthcheck_port=random.randint(4000, 5000),
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
            healthcheck_port=random.randint(4000, 5000),
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

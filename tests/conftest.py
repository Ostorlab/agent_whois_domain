"""Pytest fixture for the whois domain agent."""
import pytest

from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from agent import whois_domain_agent


@pytest.fixture
def whois_test_agent():
    """Creates a dummy agent for the Whois Domain Agent.
    """
    agent_definition = agent_definitions.AgentDefinition(name='whois')
    agent_settings = runtime_definitions.AgentSettings(key='whois', redis_url='redis://redis')
    return whois_domain_agent.AgentWhoisDomain(agent_definition, agent_settings)

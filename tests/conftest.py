"""Pytest fixture for the whois domain agent."""

import io
import json
import pathlib
import re
import urllib.error
import urllib.request
from typing import Any
from unittest import mock

import pytest
import whois
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import definitions
from pytest_mock import plugin

from agent import (
    rdap,
    whois_domain_agent,
)

WHOIS_ANSWERS = pathlib.Path(__file__).parent / "files"
# The proton.me registry record's lines that the empty-values fixture blanks.
REGISTRY_LINES_TO_EMPTY = re.compile(
    r"^(Registrant Organization|Registrant Country|Name Server|DNSSEC):.*$",
    re.MULTILINE,
)
COM_RDAP_SERVER = "https://rdap.verisign.com/com/v1"
# The saved RDAP answer served at each registry and registrar URL.
RDAP_ANSWERS = {
    f"{COM_RDAP_SERVER}/domain/arstechnica.com": "arstechnica.com.rdap.json",
    "https://rdap.cscglobal.com/dbs/rdap-api/v1/domain/ARSTECHNICA.COM": "arstechnica.com.registrar.rdap.json",
    f"{COM_RDAP_SERVER}/domain/techcrunch.com": "techcrunch.com.rdap.json",
    "https://rdap.markmonitor.com/rdap/domain/TECHCRUNCH.COM": "techcrunch.com.registrar.rdap.json",
}


def _read_whois_answer(domain: str) -> str:
    """Reads a saved WHOIS answer, keeping its line endings."""
    return (WHOIS_ANSWERS / f"{domain}.txt").read_text(encoding="utf-8", newline="")


def _load_whois_answer(domain: str) -> whois.parser.WhoisEntry:
    """Parses a saved WHOIS answer the way python-whois parses a live one."""
    return whois.parser.WhoisEntry.load(domain, _read_whois_answer(domain))


def _load_rdap_answer(name: str) -> dict[str, Any]:
    """Reads a saved RDAP answer."""
    answer: dict[str, Any] = json.loads((WHOIS_ANSWERS / name).read_text())
    return answer


def _serve_rdap_answer(request: urllib.request.Request, timeout: int) -> io.BytesIO:
    """Answers an RDAP lookup with the saved answer of its URL."""
    del timeout
    name = RDAP_ANSWERS.get(request.full_url)
    if name is None:
        raise urllib.error.URLError(f"no saved answer for {request.full_url}")
    return io.BytesIO((WHOIS_ANSWERS / name).read_bytes())


@pytest.fixture
def proton_me_whois() -> whois.parser.WhoisEntry:
    """The .me registry's answer for proton.me followed by the registrar's referral."""
    return _load_whois_answer("proton.me")


@pytest.fixture
def proton_me_whois_with_empty_registry_values() -> whois.parser.WhoisEntry:
    """The proton.me answer whose registry record leaves org, country, name server and DNSSEC empty."""
    raw_text = _read_whois_answer("proton.me")
    registry_record, record_end, referral = raw_text.partition(">>> Last update")
    registry_record = REGISTRY_LINES_TO_EMPTY.sub(r"\1: ", registry_record)
    return whois.parser.WhoisEntry.load(
        "proton.me", registry_record + record_end + referral
    )


@pytest.fixture
def scale_ai_whois() -> whois.parser.WhoisEntry:
    """The .ai answer for scale.ai, parsed into registrant_org and registrant_country."""
    return _load_whois_answer("scale.ai")


@pytest.fixture
def docker_io_whois() -> whois.parser.WhoisEntry:
    """The .io answer for docker.io, whose parser keeps the organisation under registrant_name."""
    return _load_whois_answer("docker.io")


@pytest.fixture
def ferrari_it_whois() -> whois.parser.WhoisEntry:
    """The .it answer for ferrari.it, parsed into registrant_organization."""
    return _load_whois_answer("ferrari.it")


@pytest.fixture
def shopify_ca_whois() -> whois.parser.WhoisEntry:
    """The .ca answer for shopify.ca, whose parser has no organisation or country key."""
    return _load_whois_answer("shopify.ca")


@pytest.fixture
def microsoft_com_whois() -> whois.parser.WhoisEntry:
    """The .com answer for microsoft.com, parsed into org and country."""
    return _load_whois_answer("microsoft.com")


@pytest.fixture
def cloudflare_com_whois() -> whois.parser.WhoisEntry:
    """The .com answer for cloudflare.com, whose registrar redacts the organisation."""
    return _load_whois_answer("cloudflare.com")


@pytest.fixture
def arstechnica_com_whois() -> whois.parser.WhoisEntry:
    """The .com registry's answer for arstechnica.com, whose registrar's WHOIS server timed out."""
    return _load_whois_answer("arstechnica.com")


@pytest.fixture
def arstechnica_com_rdap() -> dict[str, Any]:
    """The .com registry's RDAP answer for arstechnica.com, linking to CSC's."""
    return _load_rdap_answer("arstechnica.com.rdap.json")


@pytest.fixture
def arstechnica_com_registrar_rdap() -> dict[str, Any]:
    """CSC's RDAP answer for arstechnica.com, publishing the registrant's org and country."""
    return _load_rdap_answer("arstechnica.com.registrar.rdap.json")


@pytest.fixture
def techcrunch_com_rdap() -> dict[str, Any]:
    """The .com registry's RDAP answer for techcrunch.com, linking to MarkMonitor's."""
    return _load_rdap_answer("techcrunch.com.rdap.json")


@pytest.fixture
def techcrunch_com_registrar_rdap() -> dict[str, Any]:
    """MarkMonitor's RDAP answer for techcrunch.com, publishing only the registrant's country."""
    return _load_rdap_answer("techcrunch.com.registrar.rdap.json")


@pytest.fixture
def rdap_servers(mocker: plugin.MockerFixture) -> mock.MagicMock:
    """Serves the saved .com registry and registrar RDAP answers in place of the network."""
    mocker.patch.object(rdap, "_bootstrap", return_value={"com": COM_RDAP_SERVER})
    urlopen: mock.MagicMock = mocker.patch(
        "urllib.request.urlopen", side_effect=_serve_rdap_answer
    )
    return urlopen


@pytest.fixture
def arstechnica_message() -> message.Message:
    """Creates a v3.asset.domain_name message for arstechnica.com."""
    return message.Message.from_data(
        "v3.asset.domain_name", data={"name": "arstechnica.com"}
    )


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

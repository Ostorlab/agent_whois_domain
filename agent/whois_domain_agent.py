"""Whois Domain Agent: Agent responsible for retrieving WHOIS information of a domain."""

import logging
import re
import socket
from typing import cast

import tenacity
import tld
import whois
from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent.message import message as msg
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging
from whois import parser

from agent import result_parser

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        rich_logging.RichHandler(rich_tracebacks=True),
    ],
    level="INFO",
    force=True,
)
logger = logging.getLogger(__name__)

LIB_SELECTOR = "v3.asset.domain_name.whois"
WAIT_TIME = 10
RETRY_NUMBER = 3


class AgentWhoisDomain(agent.Agent, persist_mixin.AgentPersistMixin):
    """Whois domain scanner implementation for ostorlab. using ostorlab python sdk."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)
        self._scope_domain_regex: str | None = self.args.get("scope_domain_regex")

    def process(self, message: msg.Message) -> None:
        """Starts a whois scan, wait for the scan to finish,
        and emit the results.

        Args:
            message:  The message to process from ostorlab runtime.
        """
        domain = message.data.get("name")
        if domain is None or domain == "":
            return

        domain_object = cast(
            tld.Result,
            tld.get_tld(domain, as_object=True, fix_protocol=True, fail_silently=True),
        )

        if domain_object is not None:
            logger.info("Processing message of selector : %s.", message.selector)
            if self.set_add("agent_whois_domain_asset", domain_object.fld) is False:
                logger.info(
                    "target %s was processed before, exiting", domain_object.fld
                )
                return
            if self._is_domain_in_scope(domain_object.fld) is False:
                return

            try:
                scan_output = self._fetch_whois(domain_object.fld)
                if scan_output is None:
                    return
                self._emit_result(scan_output)
            except parser.PywhoisError as e:
                logger.error(e)
        else:
            logger.error("domain is not a valid URL: %s", domain)

    def _is_domain_in_scope(self, domain: str) -> bool:
        """Check if a domain is in the scan scope with a regular expression."""
        if self._scope_domain_regex is None:
            return True
        domain_in_scope = re.match(self._scope_domain_regex, domain)
        if domain_in_scope is None:
            logger.warning(
                "Domain %s is not in scanning scope %s",
                domain,
                self._scope_domain_regex,
            )
            return False
        else:
            return True

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(RETRY_NUMBER),
        wait=tenacity.wait_fixed(WAIT_TIME),
        retry=tenacity.retry_if_exception_type(
            (socket.gaierror, ConnectionResetError, TimeoutError)
        ),
        retry_error_callback=lambda retry_state: None,
    )
    def _fetch_whois(self, domain_name: str) -> whois.parser.WhoisCom | None:
        """Collect whois data.

        Args:
            domain_name: Target domain to lookup.
        """
        logger.info("Starting a new scan for %s .", domain_name)
        try:
            whois_output = whois.whois(domain_name)
        except UnicodeError as e:
            logger.error(
                "Unicode error when fetching whois for %s : %s", domain_name, e
            )
            return None
        logger.info("done scanning %s .", domain_name)
        return whois_output

    def _emit_result(self, scan_output: whois.parser.WhoisCom) -> None:
        """After the scan is done, emit the scan findings."""

        logger.info("emitting results for %s", scan_output.get("domain_name"))
        for m in result_parser.parse_results(scan_output):
            self.emit(selector=LIB_SELECTOR, data=m)


if __name__ == "__main__":
    logger.info("Whois Domain agent starting ...")
    AgentWhoisDomain.main()

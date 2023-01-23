"""Whois Domain Agent: Agent responsible for retrieving WHOIS information of a domain."""
import logging
import re
from typing import Optional

from rich import logging as rich_logging
import whois
from whois import parser
from ostorlab.agent.message import message as msg
from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.runtimes import definitions as runtime_definitions

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


class AgentWhoisDomain(agent.Agent, persist_mixin.AgentPersistMixin):
    """Whois domain scanner implementation for ostorlab. using ostorlab python sdk."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)
        self._scope_domain_regex: Optional[str] = self.args.get("scope_domain_regex")

    def process(self, message: msg.Message) -> None:
        """Starts a whois scan, wait for the scan to finish,
        and emit the results.

        Args:
            message:  The message to process from ostorlab runtime.
        """
        domain = message.data.get("name")
        if domain is None:
            return

        logger.info("Processing message of selector : %s", message.selector)
        if self.set_add("agent_whois_domain_asset", domain) is False:
            logger.info("target %s was processed before, exiting", domain)
            return
        if self._is_domain_in_scope(self._scope_domain_regex, domain) is False:
            logger.warning(
                "Domain %s is not in scanning scope %s",
                domain,
                self._scope_domain_regex,
            )
            return

        try:
            scan_output = self._fetch_whois(domain)
            self._emit_result(scan_output)
        except parser.PywhoisError as e:
            logger.error(e)

    def _is_domain_in_scope(
        self, scope_domain_regex: Optional[str], domain: str
    ) -> bool:
        if scope_domain_regex is None:
            return True
        domain_in_scope = re.match(scope_domain_regex, domain) is not None
        if not domain_in_scope:
            return False
        else:
            return False

    def _fetch_whois(self, domain_name: str) -> whois.parser.WhoisCom:
        """Collect whois data.

        Args:
            domain_name: Target domain to lookup.
        """
        logger.info("staring a new scan for %s .", domain_name)
        whois_output = whois.whois(domain_name)
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

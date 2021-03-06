"""Whois Domain Agent: Agent responsible for retrieving WHOIS information of a domain."""
import logging

from rich import logging as rich_logging
import whois
from whois import parser
from ostorlab.agent import message as msg
from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.runtimes import definitions as runtime_definitions

from agent import result_parser


logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True), ],
    level='INFO',
    force=True
)
logger = logging.getLogger(__name__)

LIB_SELECTOR = 'v3.asset.domain_name.whois'


class AgentWhoisDomain(agent.Agent, persist_mixin.AgentPersistMixin):
    """Whois domain scanner implementation for ostorlab. using ostorlab python sdk."""

    def __init__(self, agent_definition: agent_definitions.AgentDefinition,
                 agent_settings: runtime_definitions.AgentSettings) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)

    def process(self, message: msg.Message) -> None:
        """Starts a whois scan, wait for the scan to finish,
        and emit the results.

        Args:
            message:  The message to process from ostorlab runtime.
        """
        domain = message.data.get('name')
        if domain is None:
            return

        logger.info('Processing message of selector : %s', message.selector)
        if not self.set_add('agent_whois_domain_asset', domain):
            logger.info('target %s was processed before, exiting', domain)
            return
        try:
            scan_output = self._fetch_whois(domain)
            self._emit_result(scan_output)
        except parser.PywhoisError as e:
            logger.error(e)

    def _fetch_whois(self, domain_name: str) -> whois.parser.WhoisCom:
        """Collect whois data.

        Args:
            domain_name: Target domain to lookup.
        """
        logger.info('staring a new scan for %s .', domain_name)
        whois_output = whois.whois(domain_name)
        logger.info('done scanning %s .', domain_name)
        return whois_output

    def _emit_result(self, scan_output: whois.parser.WhoisCom) -> None:
        """After the scan is done, emit the scan findings."""

        logger.info('emitting results for %s', scan_output.get('domain_name'))
        for m in result_parser.parse_results(scan_output):
            self.emit(selector=LIB_SELECTOR, data=m)


if __name__ == '__main__':
    logger.info('Whois Domain agent starting ...')
    AgentWhoisDomain.main()

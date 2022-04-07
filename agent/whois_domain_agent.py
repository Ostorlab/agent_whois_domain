"""Whois Domain Agent: Agent responsible for retrieving WHOIS information of a domain."""
import json
import logging

from ostorlab.agent import agent
from ostorlab.agent import message as msg
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from agent import result_parser

from rich import logging as rich_logging
import whois

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True), ],
    level='INFO',
    force=True
)
logger = logging.getLogger(__name__)

VULNZ_TITLE = 'WHOIS domain information'
VULNZ_ENTRY_RISK_RATING = 'INFO'
VULNZ_SHORT_DESCRIPTION = 'WHOIS information found.'
VULNZ_DESCRIPTION = """Lists WHOIS domain information including the domain name, registrar, creation date,
updated date, expiration date, emails, and organization. Other information includes the city, zipcode,
country, state, DNSSEC, address, name, status, and name servers."""

LIB_SELECTOR = 'v3.asset.domain_name.whois'

class AgentWhoisDomain(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin,
        persist_mixin.AgentPersistMixin):
    """Whois domain scanner implementation for ostorlab. using ostorlab python sdk.
    For more information visit https://github.com/Ostorlab/ostorlab."""

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
        domain = message.data['name']

        if (isinstance(domain, list)):
            domain = domain[0]

        logger.info('Processing message of selector : %s', message.selector)
        if not self.set_add('agent_whois_domain_asset', domain):
            logger.info('target %s/ was processed before, exiting', domain)
            return
        output = self._start_scan(domain)
        self._emit_report_result(whois_scan_output=output)

    def _start_scan(self, domain_name: str) -> whois.parser.WhoisCom:
        """Run a whois scan using python subprocess.

        Args:
            domain_name: Target domain to lookup.
        """
        logger.info('Staring a new scan for %s .', domain_name)
        whois_output = whois.whois(domain_name)
        logger.info('Done scanning %s .', domain_name)
        return whois_output

    def _emit_report_result(self, whois_scan_output: whois.parser.WhoisCom) -> None:
        """After the scan is done, emit the scan findings."""

        logger.info('Reporting results for %s',
                    whois_scan_output.get('domain_name'))
        parsed_results = result_parser.parse_results(whois_scan_output)

        self.emit(selector=LIB_SELECTOR, data=parsed_results)
        self.report_vulnerability(
            entry=kb.Entry(
                title=VULNZ_TITLE,
                risk_rating=VULNZ_ENTRY_RISK_RATING,
                short_description=VULNZ_SHORT_DESCRIPTION,
                description=VULNZ_DESCRIPTION,
                references={},
                security_issue=True,
                privacy_issue=False,
                has_public_exploit=False,
                targeted_by_malware=False,
                targeted_by_ransomware=False,
                targeted_by_nation_state=False
            ),
            technical_detail=f'```json\n{json.dumps(parsed_results, indent = 4)}\n```',
            risk_rating=agent_report_vulnerability_mixin.RiskRating.INFO)

if __name__ == '__main__':
    logger.info('Whois Domain agent starting ...')
    AgentWhoisDomain.main()

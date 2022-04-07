"""Unittests for whois_domain agent."""
import datetime

from ostorlab.agent import message as msg

WHOIS_SCAN_OUTPUT = {
    "domain_name": "ostorlab.co",
    "registrar": "Tucows Domains Inc.",
    "whois_server": "whois.opensrs.net",
    "referral_url": None,
    "updated_date": datetime.datetime.fromisoformat("2018-12-08 10:36:41"),
    "creation_date": datetime.datetime.fromisoformat("2015-01-27 22:03:32"),
    "expiration_date": datetime.datetime.fromisoformat("2023-01-26 23:59:59"),
    "name_servers": [
        "nirvana.easydns.net",
        "motorhead.easydns.org",
        "rush.easydns.com"
    ],
    "status": [
        "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
        "clientTransferProhibited https://icann.org/epp#clientTransferProhibited"
    ],
    "emails": [
        "compliance@tucows.com",
        "easydns@myprivacy.ca"
    ],
    "dnssec": "unsigned",
    "name": "REDACTED FOR PRIVACY",
    "org": "Contact Privacy Inc. Customer 0139267634",
    "address": "REDACTED FOR PRIVACY",
    "city": "REDACTED FOR PRIVACY",
    "state": "ON",
    "zipcode": "REDACTED FOR PRIVACY",
    "country": "CA"
}

WHOIS_PARSED_SCAN_OUTPUT = {
    'name': ['ostorlab.co'],
    'registrar': "Tucows Domains Inc.",
    'whois_server': 'whois.opensrs.net',
    'referral_url': None,
    'updated_date': ['2018-12-08T10:36:41'],
    'creation_date': ['2015-01-27T22:03:32'],
    'expiration_date': ['2023-01-26T23:59:59'],
    'name_servers': [
        'nirvana.easydns.net',
        'motorhead.easydns.org',
        'rush.easydns.com'
    ],
    'status': [
        'clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited',
        'clientTransferProhibited https://icann.org/epp#clientTransferProhibited'
    ],
    'emails': [
        'compliance@tucows.com',
        'easydns@myprivacy.ca'
    ],
    'dnssec': 'unsigned',
    'contact_name': 'REDACTED FOR PRIVACY',
    'org': 'Contact Privacy Inc. Customer 0139267634',
    'address': 'REDACTED FOR PRIVACY',
    'city': 'REDACTED FOR PRIVACY',
    'state': 'ON',
    'zipcode': 'REDACTED FOR PRIVACY',
    'country': 'CA'
}

def testWhoisDomainAgent_withAllChecksEnabled_emitsDomainInfo(whois_test_agent, mocker):
    """Test the whois_domain agent with a given target address. The test mocks the call to
    python_whois library and validates emitting the findings.
    """

    input_selector = 'v3.asset.domain_name'
    input_data = {'name': 'ostorlab.co'}

    output_selector = 'v3.asset.domain_name.whois'

    message = msg.Message.from_data(selector=input_selector, data=input_data)
    mocker.patch('ostorlab.agent.mixins.agent_persist_mixin.AgentPersistMixin.set_add', return_value=True)
    mocker.patch('whois.whois', return_value=WHOIS_SCAN_OUTPUT)
    mock_emit = mocker.patch(
        'agent.whois_domain_agent.AgentWhoisDomain.emit', return_value=None)
    whois_test_agent.process(message)
    mock_emit.assert_any_call(
        selector=output_selector, data=WHOIS_PARSED_SCAN_OUTPUT)

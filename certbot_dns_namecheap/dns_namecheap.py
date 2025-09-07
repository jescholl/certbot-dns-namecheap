"""DNS Authenticator for Namecheap DNS."""
import logging
from typing import Any
from typing import Callable

from requests import HTTPError

from certbot import errors
from certbot.plugins import dns_common_lexicon
from lexicon.config import ConfigResolver
import dns.resolver

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://ap.www.namecheap.com/settings/tools'


class Authenticator(dns_common_lexicon.LexiconDNSAuthenticator):
    """DNS Authenticator for Namecheap

    This Authenticator uses the Namecheap API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using Namecheap for DNS).'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._add_provider_option('api-key',
                                  f'User access token for Namecheap API. (See {ACCOUNT_URL}.)',
                                  'auth_token')
        self._add_provider_option('api-user',
                                  f'Username for Namecheap API. (See {ACCOUNT_URL}.)',
                                  'auth_username')

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 30) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='Namecheap credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Namecheap API.'

    def _get_my_ip(self) -> str:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [rdata.address for rdata in dns.resolver.resolve('resolver1.opendns.com', 'A')]
        return resolver.resolve('myip.opendns.com', 'A')[0].address


    def _build_lexicon_config(self, domain: str) -> ConfigResolver:
        if not hasattr(self, '_credentials'):  # pragma: no cover
            self._setup_credentials()

        dict_config = {
            'domain': domain,
            # We bypass Lexicon subdomain resolution by setting the 'delegated' field in the config
            # to the value of the 'domain' field itself. Here we consider that the domain passed to
            # _build_lexicon_config() is already the exact subdomain of the actual DNS zone to use.
            'delegated': domain,
            'provider_name': self._provider_name,
            'ttl': self._ttl,
            self._provider_name: {item[2]: self._credentials.conf(item[0])
                                  for item in self._provider_options}
        }

        # Add IP to config
        dict_config[self._provider_name]['auth_client_ip'] = self._get_my_ip()

        return ConfigResolver().with_dict(dict_config).with_env()


    @property
    def _provider_name(self) -> str:
        return 'namecheap'

    def _handle_http_error(self, e, domain_name):
        hint = None
        if str(e).startswith('400 Client Error:'):
            hint = 'Is your Application Secret value correct?'
        if str(e).startswith('403 Client Error:'):
            hint = 'Are your Application Key and Consumer Key values correct?'
        return errors.PluginError('Error determining zone identifier for {0}: {1}.{2}'
                                  .format(domain_name, e, ' ({0})'.format(hint) if hint else ''))

    def _handle_general_error(self, e, domain_name):
        if domain_name in str(e) and str(e).endswith('not found'):
            return

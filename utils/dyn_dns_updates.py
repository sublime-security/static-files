import logging
import os.path
from abc import abstractmethod
import json
import requests
from bs4 import BeautifulSoup

# some logging
log_format = logging.Formatter("%(asctime)s | %(filename)s:%(lineno)s - %(funcName)s | %(levelname)s | %(message)s")
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setFormatter(log_format)
logger.addHandler(ch)


class DynDnsDomain:
    def __init__(self, domain: str, provider_name: str):
        self.domain = domain.strip()
        self.provider_name = provider_name

    # only use the domain when comparing values to determine if the domain is "in" the list
    def __eq__(self, other):
        if not isinstance(other, DynDnsDomain):
            # don't attempt to compare against unrelated types
            return NotImplemented

        return self.domain == other.domain

    def __str__(self):
        return f'{self.domain},{self.provider_name}'


# we need to make sure that each provider gets the same instance of "TheList"  I think we do that by making it a
# singleton, which isn't a very Python thing to do, but whatever, it works.
class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class TheList(metaclass=Singleton):
    # this will manage reading and writing the domains to the file
    # the file will only get the domain and the provider name
    # if there are duplicates due to "catchall" providers such as VT and MISP, then the one with the lowest priority
    # will be written first, assuming it wasn't already written by one of the catchall providers
    # only the domain will be considered with performing "exists" operations on the list
    def __init__(self):
        self.output_file = '../dyn_dns_domains.csv'
        self.domains = []

        self._read_existing()

    def _read_existing(self):
        # we can read the output file, and find where the source matches to pre_populate the entries
        # make sure it's there
        if not os.path.exists(self.output_file):
            # if it's not there just return
            return
        with open(self.output_file, 'r') as f:
            for line in f.read().splitlines():
                # split the line on the comma
                domain_elements = line.split(',')
                self.domains.append(DynDnsDomain(domain=domain_elements[0], provider_name=domain_elements[1]))

    def add(self, domain: DynDnsDomain):
        if domain not in self.domains:
            self.domains.append(domain)
        else:
            pass

    def save(self):
        # we can use csv,writer if we want
        with open(self.output_file, 'w') as f:
            f.write("\n".join(map(str, self.domains)))


class Provider:
    # common functions that can be used across all providers
    def __init__(self, source_url: str, enabled: bool, provider_name: str, headers: dict = None, priority: int = 1,
                 manual_provider: bool = False, post_data: dict = None):
        self.source_url = source_url
        self.provider_name = provider_name
        self.enabled = enabled
        self.manual_provider = manual_provider
        # every provider will just get "TheList"
        self.domains = TheList()
        # we'll use headers for anything special like API keys for VT
        self.headers = headers
        # some providers require a POST to be sent to get the list of domains, dynaccess is one like this
        self.post_data = post_data
        # a place to put the source_url contents
        self.data = None
        # a priority allows multiple "catch all" type of providers to be sorted so one takes a higher priority
        # the high priority (the lowest int) will be the one that "wins" should a domain appear in more than one
        # provider list.  This allows for a method to associate the domain with a provider that contains more context
        # or linkage to a domain that the other.
        self.priority = priority

    def run(self):
        logger.warning(f"Starting {self.provider_name}")
        if not self.enabled:
            logger.warning(f"Skipping {self.provider_name} because provider is disabled")
            return []

        # if the provider is manual, we just need to call the extract function
        if self.manual_provider:
            self._extract(content=None)
        else:
            if self.post_data:
                response = requests.post(self.source_url, headers=self.headers, data=self.post_data)
            else:
                response = requests.get(self.source_url, headers=self.headers)

            if response.ok:
                # now we parse the page
                self._extract(response.content)

            del response

    @abstractmethod
    def _extract(self, content):
        raise NotImplementedError("The Specific Provider needs to override _extract")

    # create a custom method for sorting a list of providers, this gets used in the main function
    def __lt__(self, other):
        return self.priority < other.priority


class Afraid(Provider):
    def __init__(self):
        super().__init__(
            source_url='https://freedns.afraid.org/domain/registry/',
            enabled=True,
            provider_name="afraid.org",
            headers={
                'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
                'Referer': 'https://freedns.afraid.org/domain/registry/',
                'Cache-Control': 'max-age=0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'sec-ch-ua': '"Chrome";v="110", "Chromium";v="110", "Not=A?Brand";v="24"',
            }
        )

    # afraid.org is a bit special, so we'll override run here
    def run(self):
        logger.warning("Starting afraid.org")
        if not self.enabled:
            logger.warning("Skipping afraid.org because provider is disabled")
            return []

        # we'll grab the first 12 pages from their registry
        for i in range(0, 12):
            if i == 0:
                _uri = self.source_url
            else:
                _uri = f"{self.source_url}page-{i}.html"

            logger.debug(f"Attempting to fetch page {i}")
            response = requests.get(_uri, headers=self.headers)

            if response.ok:
                # now we parse the page
                self._extract(response.content)

            del response

    def _extract(self, content):
        logger.debug("Parsing Contents")
        soup = BeautifulSoup(content, "html.parser")
        # find the table.
        rows = soup.find('center').find('table').find_all('tr', class_=["trl", "trd"])
        for row in rows:
            domain = row.select_one("a[href*=subdomain]").text
            # create the domain object
            dyn_domain = DynDnsDomain(domain=domain, provider_name=self.provider_name)

            # add it to TheList and let TheList deal with duplicates
            self.domains.add(dyn_domain)
        del soup


class Dynu(Provider):
    def __init__(self):
        super().__init__(
            source_url='https://www.dynu.com/ControlPanel/AddDDNS',
            enabled=True,
            provider_name="dynu.com"
        )

    def _extract(self, content):
        logger.debug("Parsing Contents")
        soup = BeautifulSoup(content, "html.parser")
        # find the table.
        rows = soup.find('select', id="Container").find_all('option')
        for row in rows:
            dyn_domain = DynDnsDomain(domain=row.get('value'), provider_name=self.provider_name)

            self.domains.add(dyn_domain)

        del soup


class Dyn(Provider):
    def __init__(self):
        super().__init__(
            source_url='https://help.dyn.com/list-of-dyn-dns-pro-remote-access-domain-names/',
            enabled=True,
            provider_name="dyn.com"
        )

    def _extract(self, content):
        logger.debug("Parsing Contents")
        soup = BeautifulSoup(content, "html.parser")
        # find the table.
        rows = soup.find('section', class_="post_content").find('table').find_all('tr')
        for row in rows:
            table_data = row.find_all('td')
            # for each row
            for column in table_data:
                # each domain is space separated
                for entry in column.text.split():
                    dyn_domain = DynDnsDomain(domain=entry, provider_name=self.provider_name)
                    self.domains.add(dyn_domain)
        del soup


class NoIp(Provider):
    def __init__(self):
        super().__init__(
            source_url='https://www.noip.com/support/faq/frequently-asked-questions/',
            enabled=True,
            provider_name="noip.com"
        )

    def _extract(self, content):
        logger.debug("Parsing Contents")
        soup = BeautifulSoup(content, "html.parser")
        # find the first "article", then find all the h2s where the class is none (removes the first one)
        h2s = soup.find('article', class_='post-450').find_all('h2', class_=None)
        # within each h2 (one fore "Free Domains" and one for "Enhanced Domains"
        for h2 in h2s:
            # jump the next paragraph, which contains a new line seperated list
            domains = h2.find_next('p').text.split()
            for domain in domains:
                dyn_domain = DynDnsDomain(domain=domain, provider_name=self.provider_name)
                self.domains.add(dyn_domain)

        del soup


class ChangeIP(Provider):
    def __init__(self):
        super().__init__(
            source_url='https://www.changeip.com/accounts/cart.php?a=add&bid=1',
            enabled=True,
            provider_name="changeip.com"
        )

    def _extract(self, content):
        logger.debug("Parsing Contents")
        soup = BeautifulSoup(content, "html.parser")
        rows = soup.find('select', id="free-domain").find_all('option')
        for row in rows:
            dyn_domain = DynDnsDomain(domain=row.text, provider_name=self.provider_name)
            self.domains.add(dyn_domain)

        del soup


class DuiaDNS(Provider):
    def __init__(self):
        super().__init__(
            source_url='https://www.duiadns.net/register-personal-plus',
            enabled=True,
            provider_name="duiadns.net"
        )

    def _extract(self, content):
        logger.debug("Parsing Contents")
        soup = BeautifulSoup(content, "html.parser")
        options = soup.find('select', {"name": "d_default"}).find_all('option')
        for option in options:
            if 'disabled' in list(option.attrs.keys()):
                continue
            dyn_domain = DynDnsDomain(domain=option.text, provider_name=self.provider_name)
            self.domains.add(dyn_domain)

        del soup


class DnsExit(Provider):
    def __init__(self):
        super().__init__(
            source_url='https://dnsexit.com/domains/free-second-level-domains/',
            enabled=True,
            provider_name="dnsexit.com"
        )

    def _extract(self, content):
        logger.debug("Parsing Contents")
        soup = BeautifulSoup(content, "html.parser")
        options = soup.find('select', {"name": "domains", "id": "iddomain"}).find_all('option')
        for option in options:
            dyn_domain = DynDnsDomain(domain=option.get('value'), provider_name=self.provider_name)
            self.domains.add(dyn_domain)

        del soup


class DynAccess(Provider):
    """
    DynAccess seems not list _all_ of their domains on their website
    This one will pull from their website, but I'll setup a manual one and use them both
    """

    def __init__(self):
        super().__init__(
            source_url='https://www.dynaccess.com/e/Registration',
            post_data={'Tarif': 'HC', 'W': 'next step', 'LastPage': 1},
            enabled=True,
            provider_name="dynaccess.com"
        )

    def _extract(self, content):
        logger.debug("Parsing Contents")
        soup = BeautifulSoup(content, "html.parser")
        options = soup.find('select', {"name": "Domain"}).find_all('option')
        for option in options:
            dyn_domain = DynDnsDomain(domain=option.text, provider_name=self.provider_name)
            self.domains.add(dyn_domain)

        del soup


class DynAccessManual(Provider):
    """
    DynAccess seems not list _all_ of their domains on their website
    This one is based on a pivot for NS records and Reverse A records of dynaccess.de

        https://www.virustotal.com/gui/ip-address/217.114.73.102/relations

    Last Checked 2023/02/16
    """

    def __init__(self):
        super().__init__(
            source_url='https://www.dynaccess.com/',
            enabled=True,
            manual_provider=True,
            provider_name="dynaccess.com",
            priority=2
        )

    def _extract(self, content):
        manual_domains = [
            'dynxs.org', 'dyn-access.com', 'anydns.biz', 'xn--dnaccess-65a.net', 'dynaxess.biz', 'dynxs.com',
            'dynaccess.biz', 'wan-ip.com', 'wan-ip.de', 'dynaccess.be', 'dynaccess.eu', 'dynv4.com', 'hm-gruppe.net',
            'dyn-access.org', 'setip.net', 'dynaccess.ws', 'dynaccess.com', 'dynaxess.eu', 'anydns.org', 'dynv6.info',
            'dynv4.info', 'dynxs.net', 'dynaccess.co.at', 'getmyip.de', 'dynaxess.org', 'dynaxess.info', 'dynaccess.de',
            'dynaccess.net', 'dyn-access.net', 'dynv4.net', 'dynv4.biz', 'd-y-n.com', 'dynaces.eu', 'dynaccess.org',
            'dynaxess.net', 'xn--dnaccess-65a.eu', 'dns2go.de', 'dynaccess.asia', 'xn--dnaccess-65a.com', 'dynv4.org',
            'dyn-access.ws', 'dynaccess-nameserver.info', 'dynaccess-nameserver.com', 'dynaccess-nameserver.net',
            'fetchmail.de'

        ]

        for domain in manual_domains:
            dyn_domain = DynDnsDomain(domain=domain, provider_name=self.provider_name)
            self.domains.add(dyn_domain)


class DDNSDE(Provider):
    def __init__(self):
        super().__init__(
            source_url='https://ddnss.de/',
            enabled=True,
            provider_name="ddnss.de"
        )

    def _extract(self, content):
        logger.debug("Parsing Contents")
        soup = BeautifulSoup(content, "html.parser")
        headings = soup.find(class_='content').find(class_='container').find_all('h3')
        for heading in headings:
            # see if we found the one we want.
            if heading.text == "Diese Domains stehen Ihnen kostenlos zur Verfügung :":
                # find the next paragraph
                domains = heading.find_next('p').text.split(',')
                for domain in domains:
                    dyn_domain = DynDnsDomain(domain=domain, provider_name=self.provider_name)
                    self.domains.add(dyn_domain)

        del soup


class DynV6(Provider):
    def __init__(self):
        super().__init__(
            source_url='https://dynv6.com/',
            enabled=True,
            provider_name="dynv6.com"
        )

    def _extract(self, content):
        logger.debug("Parsing Contents")
        soup = BeautifulSoup(content, "html.parser")
        domains = json.loads(soup.find('quick-registration').attrs['v-bind:domains'])
        for domain in domains:
            dyn_domain = DynDnsDomain(domain=domain, provider_name=self.provider_name)
            self.domains.add(dyn_domain)

        del soup


class GSLB(Provider):
    """
    GSLB requires a login to access the account, therefor, I'll document the domains and treat them like any
    other provider

    Last Checked 2023/02/14
    """

    def __init__(self):
        super().__init__(
            source_url='https://www.gslb.me/',
            enabled=True,
            manual_provider=True,
            provider_name="gslb.me",
            priority=0
        )

    def _extract(self, content):
        manual_domains = ['gslb.biz', 'gslb.eu', 'gslb.info', 'gslb.mobi', 'gslb.us', 'gslb.ws']

        for domain in manual_domains:
            dyn_domain = DynDnsDomain(domain=domain, provider_name=self.provider_name)
            self.domains.add(dyn_domain)


class CloudNS(Provider):
    """
    CloudNS requires a login to access the account, therefor, I'll document the domains and treat them like any
    other provider

    Last Checked 2023/02/14
    """

    def __init__(self):
        super().__init__(
            source_url='https://www.cloudns.net/main/',
            enabled=True,
            manual_provider=True,
            provider_name="cloudns",
            priority=1
        )

    def _extract(self, content):
        manual_domains = ['dns-cloud.net', 'dnsabr.com']

        for domain in manual_domains:
            dyn_domain = DynDnsDomain(domain=domain, provider_name=self.provider_name)
            self.domains.add(dyn_domain)


class NSUpdate(Provider):
    """
    nsupdate.info requires a login to access the account. However, I was not able to create an account.

    To make up for this I used a VT Pivot to find a list of domains that use the same NS as nsupdate.info
    I believe this requires a paid VT account, I focused on the domains which had a large number of subdomains
        https://www.virustotal.com/gui/search/entity%253Adomain%2520whois%253Ans1.thinkmo.de/domains

    Last Checked 2023/02/14
    """

    def __init__(self):
        super().__init__(
            source_url='https://www.nsupdate.info/',
            enabled=True,
            manual_provider=True,
            provider_name="nsupdate",
            priority=1
        )

    def _extract(self, content):
        manual_domains = ['nsupdate.info']

        for domain in manual_domains:
            dyn_domain = DynDnsDomain(domain=domain, provider_name=self.provider_name)
            self.domains.add(dyn_domain)


class ThreeThreeTwoTwo(Provider):
    """
    3223 requires a login to access the account. However, I was not able to create an account due to phone number
    validation requirements.

    To make up for this I used a VT Pivot to find a list of domains that use the same NS as 3322.org
    I believe this requires a paid VT account, I focused on the domains which had a large number of subdomains
        3322.org
               https://www.virustotal.com/gui/search/entity%253Adomain%2520whois%253ANS1.3322.NET/domains
        webok.net
            https://www.virustotal.com/gui/search/entity%253Adomain%2520whois%253AV1N1.3322.NET/domains

    Last Checked 2023/02/14
    """

    def __init__(self):
        super().__init__(
            source_url='https://www.pubyun.com/products/dyndns/product/#001',
            enabled=True,
            manual_provider=True,
            provider_name="3223",
            priority=1
        )

    def _extract(self, content):
        manual_domains = ['3322.org', 'f3322.net', 'f3322.net', '8800.org', '8866.org', '2288.org', '7766.org',
                          '6600.org', '6600.org', '6600.org', 'webok.net', 'eatuo.com']

        for domain in manual_domains:
            dyn_domain = DynDnsDomain(domain=domain, provider_name=self.provider_name)
            self.domains.add(dyn_domain)


class DynIP(Provider):
    """
    So far as I can tell DynIP only uses dynip.com for subdomains.  They require you to run software in order to get
    a registration key to establish service.

    I installed their software in a sandbox - https://tria.ge/230216-cqc28afc86/behavioral1, and a list of subdomains
    appears to be provided as part of the network traffic from the server.  Interesting setup here

    Last Checked 2023/02/15
    """

    def __init__(self):
        super().__init__(
            source_url='http://www.dynip.com/',
            enabled=True,
            manual_provider=True,
            provider_name="dynip.com",
            priority=1
        )

    def _extract(self, content):
        manual_domains = [
            'dynip.com', 'bbszone.com', 'bbszone.net', 'hamsite.com', 'hamesite.net', 'ipname.com', 'ipname.net',
            'ipname.org'
        ]

        for domain in manual_domains:
            dyn_domain = DynDnsDomain(domain=domain, provider_name=self.provider_name)
            self.domains.add(dyn_domain)


class DynDNSDK(Provider):
    """
    dyndns.dk requires no registration, and currently supports only a single free domain.

    VT currently shows 1.8k subdomains
    Last Checked 2023/02/15
    """

    def __init__(self):
        super().__init__(
            source_url='https://dyndns.dk/ny.php',
            enabled=True,
            manual_provider=True,
            provider_name="dyndns.dk",
            priority=1
        )

    def _extract(self, content):
        manual_domains = ['dyndns.dk']

        for domain in manual_domains:
            dyn_domain = DynDnsDomain(domain=domain, provider_name=self.provider_name)
            self.domains.add(dyn_domain)


class darsite(Provider):
    """
    darsite.com requires registration and operations a couple different domains

        https://www.virustotal.com/gui/search/entity%253Adomain%2520whois%253Ans1.darsite.com/domains
    Last Checked 2023/02/15
    """

    def __init__(self):
        super().__init__(
            source_url='https://darsite.com',
            enabled=True,
            manual_provider=True,
            provider_name="darsite.com",
            priority=1
        )

    def _extract(self, content):
        manual_domains = ['darsite.com', 'dyndns.fr', 'dynamicdomain.net']

        for domain in manual_domains:
            dyn_domain = DynDnsDomain(domain=domain, provider_name=self.provider_name)
            self.domains.add(dyn_domain)


class MISP(Provider):
    # this only works with a premium account :-(
    def __init__(self):
        super().__init__(
            source_url='https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/dynamic-dns/list.json',
            enabled=True,
            provider_name="misp",
            priority=51
        )

    def _extract(self, content):
        content = json.loads(content)

        for domain in content.get('list'):
            # strip out the leading period
            domain = domain.lstrip('.')

            dyn_domain = DynDnsDomain(domain=domain, provider_name=self.provider_name)
            self.domains.add(dyn_domain)

        del content


if __name__ == "__main__":

    # dynamically find the classes that inherit the Provider class and run them all
    # each provider can be enabled/disabled within its own class.
    # in order to sort the list, we have to instantiate each provider first
    # so this works!
    providers = list(map(lambda x: x(), Provider.__subclasses__()))

    # now that they are all instantiated, sort the list of providers by their priority
    providers.sort()

    for provider in providers:
        # Run the provider
        provider.run()

    # save TheList
    TheList().save()

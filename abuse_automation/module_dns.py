# -*- coding: utf-8 -*-
"""


- Contributors
Elliann Marks <elian.markes@gmail.com>

**- Version 01 - 04/02/2019**

**- Version 2.0 - 11/07/2019**
- Require edit library tld and remove lower() in URL

**- Version 3.0 - 18/12/2019**

- dnspython 2.0
https://github.com/rthalley/dnspython

- List of TLDs BR
https://registro.br/dominio/categoria.html

- List of TLDs
https://publicsuffix.org/list/effective_tld_names.dat

- List of suffix
https://publicsuffix.org/list/public_suffix_list.dat

- Documentation TLD library
https://pypi.org/project/tld/
https://tld.readthedocs.io/en/0.9.2/

- Documentation validate_email library
https://pypi.org/project/validate_email/
"""

# libraries
from tld import get_tld
from tld.utils import update_tld_names
from tld.exceptions import TldBadUrl, TldDomainNotFound
from validate_email import validate_email
from abuse_automation.module_database import ModuleDatabase
from abuse_automation.module_dates import ModuleDates
from abuse_automation.module_exceptions import DatabaseSelectFailed, DatabaseInsertFailed
import dns.resolver
import dns.exception
import dns.reversename
import ipaddress


class ModuleDNS:
    
    def __init__(self, module_log, module_configuration):
        """
        Create instance of the ModuleDatabase class.
        :param module_log: Instance of the log class
        :type module_log: object
        """
        self.module_configuration = module_configuration
        self._log = module_log
        self._module_dates = ModuleDates(self._log)
        # instance ModuleDatabase class
        self._module_database = ModuleDatabase(module_log, self.module_configuration)
        # instance Resolver class
        self._dns_resolver = dns.resolver.Resolver()
        # set timeout and lifetime for query
        self._dns_resolver.timeout = 5
        self._dns_resolver.lifetime = 5
        if self.module_configuration.application == "development":
            self._dns_resolver.nameservers = ['1.1.1.1']

    def update_date_tld(self):
        """
        Execute of the command update_tld_names and update last execution in database, only execute each five days.
        :return: True on success, False on failure
        :rtype: bool
        """
        try:
            # calculate the last execution
            dates_tld = self._module_dates.calculate_dates(self._module_database.last_update_tld)
            # execute the each five days
            if dates_tld is not False and dates_tld.days >= 5:
                if update_tld_names() is True:
                    # performs updating of the last execution and returns true
                    self._module_database.update_date_tld()
                    return True

        except DatabaseSelectFailed:
            return False

        except DatabaseInsertFailed:
            return False

        except Exception as er:
            # generate a error log
            self._log.error("update_date_tld - {} - {}".format(self.__class__.__name__, er))
            return False

    def check_ip(self, value_ip):
        """
        Check if a string is a valid IP.
        :param value_ip: value of a IP address
        :type value_ip: string
        :return: IPAdress object with value of the string received on success,
            None on string not is a IP valid, False on failure
        :rtype: object or bool
        """
        try:
            return ipaddress.ip_address(value_ip)

        except ValueError as er:
            # generate a error log
            self._log.debug("check_ip - {} - {}".format(self.__class__.__name__, er))
            return None

        except Exception as er:
            # generate a error log
            self._log.error("check_ip - {} - {}".format(self.__class__.__name__, er))
            return False

    def check_url(self, domain_value):
        """
        Check if a string is a URL or domain valid.
        :param domain_value: value of a URL
        :type domain_value: string
        :return: TLD object after process the URL, separate domain, subdomain, path, query and protocol on success,
            None on string not is a URL or domain valid, False on failure
        :rtype: object or bool
        """
        try:
            # return object of the domain
            return get_tld(domain_value, as_object=True, fix_protocol=True)

        except TldBadUrl as er:
            # generate a debug log
            self._log.debug("check_url - {} - {}".format(self.__class__.__name__, er))
            return None

        except TldDomainNotFound as er:
            # generate a debug log
            self._log.debug("check_url - {} - {}".format(self.__class__.__name__, er))
            return None

        except Exception as er:
            # generate a error log
            self._log.error("check_url - {} - {}".format(self.__class__.__name__, er))
            return False

    def verification_email(self, value_email):
        """
        Check if a string is a e-mail valid and verify if exist a MX to domain of the e-mail.
        :param value_email: value fo a e-mail
        :type value_email: string
        :return: The same e-mail received on success, False on failure
        :rtype: string or bool
        """
        try:
            value_email = str(value_email)
            # check if e-mail is valid
            if validate_email(value_email, verify=True, smtp_timeout=4) is True:
                return value_email
            else:
                return False

        except Exception as er:
            # generate a error log
            self._log.error("verification_email - {} - {}".format(self.__class__.__name__, er))
            return False

    def dns_resolver(self, domain_value, type_record = "A"):
        """
        Execute a resolution of a DNS, any record in query.
        :param domain_value: Value of the a domain valid
        :param domain_value: string
        :param type_record: Value of the record for query DNS, default value is A
        :type type_record: string
        :return: DNS object on success, False on failure
        :rtype: object or bool
        """
        try:
            # check if domain_value is IPv4Address object
            if not isinstance(domain_value, ipaddress.IPv4Address):
                domain_value = str(domain_value)
            # transform record to upper
            type_record = type_record.upper()
            # check record type
            if type_record == "PTR":
                # execute query
                ip_resolver = self.check_ip(domain_value)
                if ip_resolver is not False and ip_resolver is not None:
                    result = self._dns_resolver.query(ip_resolver._reverse_pointer(), type_record)
                    return str(result[0])
                else:
                    return False
            else:
                # execute query
                result = self._dns_resolver.query(domain_value, type_record)
            # check if type record is MX to call to_text()
            if type_record == "MX":
                # format result if type record is MX and return
                return result[0].exchange.to_text()
            else:
                return result[0].to_text()

        except dns.exception.DNSException as er:
            # generate a debug log
            self._log.debug("dns_resolver - {} - {}".format(self.__class__.__name__, er))
            return False

        except Exception as er:
            # generate a error log
            self._log.error("dns_resolver - {} - {}".format(self.__class__.__name__, er))
            return False

# -*- coding: utf-8 -*-
"""


- Contributors
Elliann Marks <elian.markes@gmail.com>

**- Version 01 - 07/02/2019**

** - Version 2.0 - 11/07/2019**

**- Version 3.0 - 18/12/2019**

- Contribution to regex
http://daringfireball.net/2010/07/improved_regex_for_matching_urls
https://mathiasbynens.be/demo/url-regex

- Versions of the regex
Without path of the URL - ((((h[t|x][t|x]ps?))(://)?)?(w{0,3}\.)?(([a-z0-9_~\-@]|\.)+)\.(([a-z0-9_~\-@]|\.)+))
With path of the URL - ((((h[t|x][t|x]ps?))(://)?)?(w{0,3}\.)?(([a-z0-9_~\-@]|\.)+)\.(([a-z0-9_~\-@]|\.)+)(\/(([a-z0-9_~\-@\.\=\&\?\!]|\/))+)?)

"""

# libraries
import re
import yaml
import ipaddress
from contextlib import closing
from abuse_automation.module_database import ModuleDatabase
from abuse_automation.module_exceptions import DatabaseSelectFailed, GeneralError


class ModuleRegex:

    def __init__(self, module_log, module_configuration):
        """
        Define regex for capture URL, domains, IPs and e-mails in description of the ticket.
        :param module_log: Instance of the log class
        :type module_log: object
        :return: False on failure
        :rtype: bool
        """
        self.module_configuration = module_configuration
        self._log = module_log
        self.module_database = ModuleDatabase(self._log, self.module_configuration)
        try:
            #load yaml with regex
            with closing(open(self.module_configuration.regex_file)) as file_regex:
                regex_yaml_content = yaml.load(file_regex, Loader=yaml.FullLoader)

            #load yaml with networks
            with closing(open(self.module_configuration.network_file)) as file_network_regex:
                network_yaml_content = yaml.load(file_network_regex, Loader=yaml.FullLoader)

            if regex_yaml_content is not None and network_yaml_content is not None and \
                    regex_yaml_content is not False and network_yaml_content is not False:
                # create list with the regex
                self._regex_list = regex_yaml_content['regex']['check']
                self._regex_malware_list = regex_yaml_content['regex']['malware']
                self._regex_phishing_list = regex_yaml_content['regex']['phishing']
                self._regex_replaces_list = regex_yaml_content['regex']['replaces']
                self._regex_excludes_list = regex_yaml_content['regex']['excludes']
                self._regex_match_list = regex_yaml_content['regex']['match']
                self._regex_match_spf_list = regex_yaml_content['regex']['matchspf']
                self._regex_ftp_upload_list = regex_yaml_content['regex']['ftpupload']
                self._regex_cpanel_fml_list = regex_yaml_content['regex']['cpanelfml']
                self._regex_cpanel_list = regex_yaml_content['regex']['cpanel']
                self._regex_apache_wp_list = regex_yaml_content['regex']['apachewp']
                self._regex_apache_excludes_list = regex_yaml_content['regex']['apacheexcludes']
                self._regex_excludes_ip_list = regex_yaml_content['regex']['ipexcludes']
                self._regex_wordlist_list = regex_yaml_content['regex']['wordlist']
                self._network_latam_list = network_yaml_content['network']['latam']
            else:
                self._log.error("Error in get regex in YAML file")
                exit(5)

        except Exception as er:
            # generate a error log
            self._log.error("{} - {}".format(self.__class__.__name__, er))
            exit(5)

        # regex variables
        self.regex_log_ip = "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        self.regex_ftp_ip = "@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\)"
        self.regex_shared = "(br|bz|mx|srv)[0-9]{1,4}\.example\.(com\.br|com\.mx|mx|com\.cl|cl|com\.co|co)"
        self.regex_turbo = "srv[0-9]{1,4}\.example\.(com\.br|com\.mx|mx|com\.cl|cl|com\.co|co)"
        self.regex_reseller = "(srv|server)[0-9]{1,4}\.example\.(com\.br|com\.mx|mx|com\.cl|cl|com\.co|co)"
        self.regex_wp = "wp[0-9]{1,4}\.example\.com\.br"
        self.regex_vps = "(vps-[0-9]+|vps)\..*"
        self.regex_dedi = "(server[0-9]{1,2}|dedi-[0-9]+)\..*"
        self.regex = "(example|example02)\.(com\.br|com\.mx|mx|com\.cl|cl|com\.co|co)"
        self.regex_home = "/home[0-9]?/[a-z0-9]+"

    def check_network_latam(self, value_network_latam):
        """
        Check if o value received match in some regex
        :param value_network_latam: list, string or IPv4Address object
        :return: True on success, False on failure
        :rtype: bool
        """
        try:
            # check if object is a list
            if isinstance(value_network_latam, list):
                # scrolls through the list with values
                for content_network_latam in value_network_latam:
                    # scrolls through the regex list
                    for network_latam in self._network_latam_list:
                        # check if the IP match
                        if ipaddress.ip_address(content_network_latam) in ipaddress.ip_network(network_latam) \
                                or self.module_database.check_ip(content_network_latam):
                            return True
            # check if object is a string
            elif isinstance(value_network_latam, str):
                content_network_latam = value_network_latam
                # scrolls through the regex list
                for network_latam in self._network_latam_list:
                    # check if the IP match
                    if ipaddress.ip_address(content_network_latam) in ipaddress.ip_network(network_latam) \
                                or self.module_database.check_ip(content_network_latam):
                        return True
            # check if object is a IPv4Address object
            elif isinstance(value_network_latam, ipaddress.IPv4Address):
                content_network_latam = str(value_network_latam)
                # scrolls through the regex list
                for network_latam in self._network_latam_list:
                    # check if the IP match
                    if ipaddress.ip_address(content_network_latam) in ipaddress.ip_network(network_latam) \
                                or self.module_database.check_ip(content_network_latam):
                        return True

            return False

        except DatabaseSelectFailed:
            raise GeneralError

        except Exception as er:
            # generate a error log
            self._log.error("check_network_latam - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def check_excludes_ip(self, value_excludes_ip):
        try:
            for regex_excludes_ip in self._regex_excludes_ip_list:
                match_excludes_ip = re.match(regex_excludes_ip, value_excludes_ip)
                if match_excludes_ip is not None:
                    return True
            return False

        except Exception as er:
            # generate a error log
            self._log.error("check_excludes_ip - {} - {}".format(self.__class__.__name__, er))
            return False

    def check_string(self, value_string, check_spf=None):
        """
        Check if exists company string in value received.
        :param value_string: value to verify if exists company string
        :type value_string: string
        :param check_spf: active check_spf
        :type check_spf: bool
        :return: number of matches on success, False on failure
        :rtype: bool or int
        """
        try:
            value_match = 0
            # check if was received a value in check_spf
            if check_spf is None:
                # scrolls through the regex list
                for regex_check_match in self._regex_match_list:
                    # check if match
                    if len(re.findall(regex_check_match, value_string, flags=re.IGNORECASE)) != 0:
                        value_match += 1
            else:
                # scrolls through the regex list
                for regex_check_match in self._regex_match_spf_list:
                    # check if match
                    if len(re.findall(regex_check_match, value_string, flags=re.IGNORECASE)) != 0:
                        value_match += 1
            return value_match

        except Exception as er:
            # generate a error log
            self._log.error("check_string - {} - {}".format(self.__class__.__name__, er))
            return False

    def check_wordlist(self, ticket_object):
        try:
            # scrolls through the regex list
            for regex_wordlist in self._regex_wordlist_list:
                # check if match
                match_result = re.search(regex_wordlist, ticket_object['description'], flags=re.IGNORECASE)
                if match_result is not None:
                    return True
            return False

        except Exception as er:
            # generate a error log
            self._log.error("check_wordlist - {} - {}".format(self.__class__.__name__, er))
            return False

    def check_cpanel(self, cpanel_log):
        """
        Check if exists specific request in log cPanel
        :param cpanel_log: value to verify if exists
        :type cpanel_log: string
        :return: string match on success, False on failure
        :rtype: bool or string
        """
        try:
            if cpanel_log is not None:
                # scrolls through the regex list
                for regex_cpanel in self._regex_cpanel_list:
                    # check if match
                    match_cpanel = re.findall(regex_cpanel, cpanel_log, flags=re.IGNORECASE)
                    if len(match_cpanel) > 0:
                        match_ip = re.match(self.regex_log_ip, cpanel_log)
                        if match_ip is not None:
                            return match_ip.group()

        except Exception as er:
            # generate a error log
            self._log.error("check_cpanel - {} - {}".format(self.__class__.__name__, er))
            return False

    def check_apache(self, apache_log):
        """
        Check if exists specific content in apache log
        :param apache_log: value to verify if exists
        :type apache_log: string
        :return: list with matchs on success, False on failure
        :rtype: bool or list
        """
        try:
            list_apache = list()
            check_apache_wp = False
            check_apache_excludes = False
            if apache_log is not None:
                # scrolls through the regex list
                for regex_apache_excludes in self._regex_apache_excludes_list:
                    # check if match
                    match_apache_excludes = re.search(regex_apache_excludes, apache_log, flags=re.IGNORECASE)
                    if match_apache_excludes is not None:
                        check_apache_excludes = True
                if check_apache_excludes is False:
                    match_apache_method = re.search("POST", apache_log)
                    if match_apache_method is not None:
                        for regex_apache_wp in self._regex_apache_wp_list:
                            match_apache_wp = re.search(regex_apache_wp, apache_log, flags=re.IGNORECASE)
                            if match_apache_wp is not None:
                                check_apache_wp = True
                        match_apache_ip = re.match(self.regex_log_ip, apache_log)
                        if match_apache_ip is not None:
                            list_apache.append(match_apache_ip.group())
                        if check_apache_wp:
                            list_apache.append(1)
                        else:
                            list_apache.append(0)
                        return list_apache

        except Exception as er:
            # generate a error log
            self._log.error("check_apache - {} - {}".format(self.__class__.__name__, er))
            return False

    def check_cpanel_fml(self, cpanel_fml_log):
        """
        Check if exists specific command in log cPanelFml
        :param cpanel_fml_log: value to verify if exists
        :type cpanel_fml_log: string
        :return: string match on success, False on failure
        :rtype: bool or string
        """
        try:
            if cpanel_fml_log is not None:
                # scrolls through the regex list
                for regex_cpanel_fml in self._regex_cpanel_fml_list:
                    # check if match
                    match_cpanel_fml = re.search(regex_cpanel_fml, cpanel_fml_log, flags=re.IGNORECASE)
                    if match_cpanel_fml is not None:
                        return str(re.sub(" \(|extract |savefile ", "", match_cpanel_fml.group()))

        except Exception as er:
            # generate a error log
            self._log.error("check_cpanel_fml - {} - {}".format(self.__class__.__name__, er))
            return False

    def remove_www(self, value_remove_www):
        try:
            return str(re.sub("^www\.|^ftp\.|^mail\.", "", value_remove_www, flags=re.IGNORECASE))

        except Exception as er:
            # generate a error log
            self._log.error("remove_www - {} - {}".format(self.__class__.__name__, er))
            return value_remove_www

    def check_ftp_upload(self, ftp_upload_log):
        """
        Check if exists specific command in log ftp
        :param ftp_upload_log: value to verify if exists
        :type ftp_upload_log: string
        :return: string match on success, False on failure
        :rtype: bool or string
        """
        try:
            list_ftp_upload = list()
            if ftp_upload_log is not None:
                # scrolls through the regex list
                for regex_ftp_upload in self._regex_ftp_upload_list:
                    # check if match
                    match_ftp_upload = re.search(regex_ftp_upload, ftp_upload_log, flags=re.IGNORECASE)
                    match_ftp_upload_ip = re.match(self.regex_ftp_ip, ftp_upload_log)
                    if match_ftp_upload is not None and match_ftp_upload_ip is not None:
                        list_ftp_upload.append(str(re.sub("@|\)", "", match_ftp_upload_ip.group())))
                        list_ftp_upload.append(str(re.sub("notice\]| uploaded", "", match_ftp_upload.group(), flags=re.IGNORECASE)))
                        return list_ftp_upload

        except Exception as er:
            # generate a error log
            self._log.error("check_ftp_upload - {} - {}".format(self.__class__.__name__, er))
            return False

    def check_malware(self, ticket_object):
        """
        Check in description and subject if exists malware or phishing word
        :param ticket_object: dict with data of the tickets
        :return: number of matches on success, False on failure
        :rtype: bool or int
        """
        try:
            value_malware = 0
            # scrolls through the regex list of the malware
            for regex_check_malware in self._regex_malware_list:
                # check if in description or subject there is a match in regex
                if ticket_object['description'] is not None and ticket_object['subject'] is not None:
                    if len(re.findall(regex_check_malware, ticket_object['description'], flags=re.IGNORECASE)) != 0 or len(
                            re.findall(regex_check_malware, ticket_object['subject'], flags=re.IGNORECASE)) != 0:
                        value_malware += 1
                elif ticket_object['description'] is not None and ticket_object['subject'] is None:
                    if len(re.findall(regex_check_malware, ticket_object['description'], flags=re.IGNORECASE)) != 0:
                        value_malware += 1
                elif ticket_object['description'] is None and ticket_object['subject'] is not None:
                    if len(re.findall(regex_check_malware, ticket_object['subject'], flags=re.IGNORECASE)) != 0:
                        value_malware += 1
            return value_malware

        except Exception as er:
            # generate a error log
            self._log.error("check_malware - {} - {}".format(self.__class__.__name__, er))
            return False

    def check_phishing(self, ticket_object):
        """
        Check in description and subject if exists phishing word
        :param ticket_object: dict with data of the tickets
        :return: number of matches on success, False on failure
        :rtype: bool or int
        """
        try:
            value_phishing = 0
            # scrolls through the regex list of the phishing
            for regex_check_phishing in self._regex_phishing_list:
                # check if in description or subject there is a match in regex
                if ticket_object['description'] is not None and ticket_object['subject'] is not None:
                    if len(re.findall(regex_check_phishing, ticket_object['description'], flags=re.IGNORECASE)) != 0 or len(
                            re.findall(regex_check_phishing, ticket_object['subject'], flags=re.IGNORECASE)) != 0:
                        value_phishing += 1
                elif ticket_object['description'] is not None and ticket_object['subject'] is None:
                    if len(re.findall(regex_check_phishing, ticket_object['description'], flags=re.IGNORECASE)) != 0:
                        value_phishing += 1
                elif ticket_object['description'] is None and ticket_object['subject'] is not None:
                    if len(re.findall(regex_check_phishing, ticket_object['subject'], flags=re.IGNORECASE)) != 0:
                        value_phishing += 1
            return value_phishing

        except Exception as er:
            # generate a error log
            self._log.error("check_phishing - {} - {}".format(self.__class__.__name__, er))
            return False

    def user_website_url(self, website_url):
        try:
            result_website = re.match("/~[a-z0-9]+", website_url)
            if result_website is None:
                return None
            else:
                return str(result_website.group()).split("~")[1]

        except Exception as er:
            # generate a error log
            self._log.error("user_website_url - {} - {}".format(self.__class__.__name__, er))
            return False

    def check_server(self, value_type):
        try:
            if re.search(self.regex_shared, value_type, flags=re.IGNORECASE) is not None:
                return "shared"
            if re.search(self.regex_reseller, value_type, flags=re.IGNORECASE) is not None:
                return "reseller"
            if re.search(self.regex_wp, value_type, flags=re.IGNORECASE) is not None:
                return "wp"
            if re.search(self.regex_dedi, value_type, flags=re.IGNORECASE) is not None:
                return "dedi"
            if re.search(self.regex_vps, value_type, flags=re.IGNORECASE) is not None:
                return "vps"
            if re.search(self.regex_turbo, value_type, flags=re.IGNORECASE) is not None:
                return "turbo"
            return False

        except Exception as er:
            # generate a error log
            self._log.error("check_server - {} - {}".format(self.__class__.__name__, er))
            return False

    def check_home(self, value_type):
        try:
            if re.match(self.regex_home, value_type, flags=re.IGNORECASE) is not None:
                return True
            else:
                return False

        except Exception as er:
            # generate a error log
            self._log.error("check_home - {} - {}".format(self.__class__.__name__, er))
            return False

    def regex_check(self, ticket_object):
        """
        Check description of the zendesk ticket
        :param ticket_object: dict with data of the tickets
        :return: number of matches on success, False on failure
        :rtype: bool or list with domains and urls that match
        """
        try:
            if ticket_object['subject'] is not None:
                result_description = ticket_object['description'] + "\n" + ticket_object['subject']
            else:
                result_description = ticket_object['description']
            # scrolls through the regex list for make replace in space
            for regex_replaces_temp in self._regex_replaces_list:
                regex_replaces = regex_replaces_temp.split(" ")
                if regex_replaces[1] == "None":
                    # make replace <space> code to literal space
                    result_description = re.sub(regex_replaces[0].replace("<space>", " "), "", result_description)
                else:
                    # make replace <space> code to literal space
                    result_description = re.sub(regex_replaces[0].replace("<space>", " "), regex_replaces[1], result_description)
            # scrolls through the regex list
            for self.regex in self._regex_list:
                # create list empty for return result
                result = list()
                result_email = list()
                # loop in result of the get values using the regex
                for result_value_a in re.findall(self.regex, result_description, flags=re.IGNORECASE):
                    # loop in match with regex
                    for result_value_b in result_value_a:
                        # check if exists a dot in match
                        if "." in result_value_b:
                            # check if match is greater than four character and last character not equal a dot and not exists a @ in string
                            if len(result_value_b) >= 4:
                                if "@" in result_value_b and "/" not in result_value_b:
                                    result_email.append(result_value_b)
                                # verify if exists a string equal in list result
                                else:
                                    if result_value_b not in result:
                                        # add the string in list
                                        result.append(result_value_b)
                return result, result_email

        except Exception as er:
            # generate a error log
            self._log.error("regex_check - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def check_exclude(self, value_exclude):
        """
        Check the regex for exclude items
        :param value_exclude: list with the data
        :return: True on success, False on failure
        :rtype: bool
        """
        try:
            # scrolls through the regex list of excludes
            for regex_exclude in self._regex_excludes_list:
                # check if match
                if bool(re.search(regex_exclude, value_exclude, flags=re.IGNORECASE)) is True:
                    return True
            return None

        except Exception as er:
            # generate a error log
            self._log.error("check_exclude - {} - {}".format(self.__class__.__name__, er))
            return False

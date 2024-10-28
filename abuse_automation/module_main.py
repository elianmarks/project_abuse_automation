# -*- coding: utf-8 -*-
"""


- Contributors
Elliann Marks <elian.markes@gmail.com>

**- Version 01 - 08/02/2019**

**- Version 2.0 - 11/07/2019**

**- Version 3.0 - 18/12/2019**

"""

# custom libraries
from abuse_automation.module_log import ModuleLog
from abuse_automation.module_zen import ModuleZen
from abuse_automation.module_regex import ModuleRegex
from abuse_automation.module_dns import ModuleDNS
from abuse_automation.module_configuration import ModuleConfiguration
from abuse_automation.module_publish import ModulePublish
from abuse_automation.module_database import ModuleDatabase
from abuse_automation.module_exceptions import ZenFailed, GeneralError, \
    PublishFailed, ZenRollback, DatabaseUpdateFailed, DatabaseInsertFailed, ContinueError, DatabaseSelectFailed
import os
import time
import imgkit
import uuid


class ModuleMain:

    def __init__(self):
        try:
            # load the confs
            self.module_configuration = None
            self.module_log = None
            self.config_init()
            self._log = self.module_log.log
            # instance of the modules
            self.module_regex = ModuleRegex(self.module_log.log, self.module_configuration)
            self.module_zen = ModuleZen(self.module_log.log, self.module_configuration)
            self.module_dns = ModuleDNS(self.module_log.log, self.module_configuration)
            self.module_database = ModuleDatabase(self._log, self.module_configuration)
            self.queue_vt = ModulePublish(self.module_log.log, "vt", self.module_configuration.user_queue, self.module_configuration.password_queue,
                                                self.module_configuration.host_queue, self.module_configuration.key("vt"))
            self.queue_analyze = ModulePublish(self.module_log.log, "analyze", self.module_configuration.user_queue, self.module_configuration.password_queue,
                                                self.module_configuration.host_queue, self.module_configuration.key("analyze"))
            # variables
            self.options_img_kit = {'quiet': ''}
            self.report_print = self.module_configuration.report_prints
            self.domain_netloc = None
            self.dict_ticket = None
            self.user_website_url = None
            self.brand = None
            self.valid_ip = None

        except Exception as er:
            # generate a error log
            self._log.error("{} - {}".format(self.__class__.__name__, er))
            # exit the application with code 4
            exit(3)

    def config_init(self):
        try:
            # instance module configuration
            self.module_configuration = ModuleConfiguration()
            # instance the ModuleLog class
            self.module_log = ModuleLog(self.module_configuration, 1)

        except GeneralError:
            exit(2)

        except Exception as er:
            # only print the error, since moduleLog there isn't instance
            print("config_init - {} - {}".format(self.__class__.__name__, er))
            exit(2)

    def message_analyze(self):
        try:
            message_analyze = dict(check_website_url=self.dict_ticket['check_website_url'],
                           main_domain=self.dict_ticket['main_domain'],
                           path_url=self.domain_netloc.parsed_url.path,
                           main_check=self.dict_ticket['main_check'],
                           check_type=self.dict_ticket['check_type'],
                           ticket_id=self.dict_ticket['id'],
                           thread_id=self.dict_ticket['thread_id'],
                           intentional_words=self.dict_ticket['intentional_words'],
                           brand=self.dict_ticket['brand'])
            self.queue_analyze.publish(message_analyze)
            self._log.info("Send message_analyze - {}".format(message_analyze))

        except PublishFailed:
            raise ZenRollback

        except Exception as er:
            # generate a error log
            self._log.error("message_analyze - {} - {}".format(self.__class__.__name__, er))
            raise ZenRollback

    def message_analyze_website(self):
        try:
            message_analyze_website = dict(check_website_url=self.dict_ticket['check_website_url'],
                                           main_domain=self.user_website_url,
                                           path_url=self.dict_ticket[self.user_website_url].parsed_url.path,
                                           main_check=self.dict_ticket[self.user_website_url].parsed_url.netloc,
                                           check_type=self.dict_ticket['check_type'],
                                           ticket_id=self.dict_ticket['id'],
                                           thread_id=self.dict_ticket[self.user_website_url + "_thread_id"],
                                           intentional_words=self.dict_ticket['intentional_words'],
                                           brand=self.dict_ticket['brand'])
            self.queue_analyze.publish(message_analyze_website)
            self._log.info("Send message_analyze_website - {}".format(message_analyze_website))

        except PublishFailed:
            raise ZenRollback

        except Exception as er:
            self._log.error("message_analyze_website - {} - {}".format(self.__class__.__name__, er))
            raise ZenRollback

    def message_url_vt(self):
        try:
            message_url_vt = dict(scan_type=1,
                                  scan_target=self.dict_ticket['main_domain'],
                                  scan_ticket=self.dict_ticket['id'],
                                  thread_id=self.dict_ticket['thread_id'])
            self.queue_vt.publish(message_url_vt)
            self._log.info("Send message_url_vt - {}".format(message_url_vt))

        except PublishFailed:
            raise ZenRollback

        except Exception as er:
            # generate a error log
            self._log.error("message_url_vt - {} - {}".format(self.__class__.__name__, er))
            raise ZenRollback

    def check_network_ip(self):
        try:
            if self.module_regex.check_network_latam(self.valid_ip):
                # set true for checkA and false in others
                reverse_name = self.module_dns.dns_resolver(self.valid_ip, "PTR")
                # create key with domain and mode of the checking in dict
                if reverse_name is not False and reverse_name is not None:
                    self.dict_ticket.update({'main_check': reverse_name})
                else:
                    self.dict_ticket.update({'main_check': "Not found"})
                # set IP in MainCheck item
                self.dict_ticket.update({'main_ip': self.valid_ip})
                self.dict_ticket.update({'check_general': True})

        except GeneralError:
            raise GeneralError

        except Exception as er:
            # generate a error log
            self._log.error("check_network_ip - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def check_ns_resolver(self):
        """
        Test NS entry and register domain in dict
        :return: False on failure
        :rtype: bool
        """
        try:
            if self.dict_ticket['check_general'] is False:
                # test NS entry
                ns_resolver = self.module_dns.dns_resolver(self.domain_netloc.parsed_url.netloc, "NS")
                # check result of the dns query NS
                if ns_resolver is not False:
                    # check string default in NS
                    if self.module_regex.check_string(ns_resolver):
                        self.dict_ticket.update({'main_check': ns_resolver})
                        self.dict_ticket.update({'check_general': True})

        except Exception as er:
            # generate a error log
            self._log.error("check_ns_resolver - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def check_a_resolver(self):
        """
        Test A entry and register domain in dict
        :return: False on failure
        :rtype: bool
        """
        try:
            if self.dict_ticket['check_general'] is False:
                # test A entry
                a_resolver = self.module_dns.dns_resolver(self.domain_netloc.parsed_url.netloc, "A")
                # check result of the dns query with A record
                if a_resolver is not False:
                    # check if IP is include in subnets
                    if self.module_regex.check_network_latam(a_resolver):
                        self.dict_ticket.update({'main_check': a_resolver})
                        self.dict_ticket.update({'check_general': True})

        except GeneralError:
            raise GeneralError

        except Exception as er:
            # generate a error log
            self._log.error("check_a_resolver - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def check_mx_resolver(self):
        """
        Test MX entry and register domain in dict
        :return: False on failure
        :rtype: bool
        """
        try:
            if self.dict_ticket['check_general'] is False:
                # test MX entry
                mx_resolver = self.module_dns.dns_resolver(self.domain_netloc.parsed_url.netloc, "MX")
                # check result of the dns query MX
                if mx_resolver is not False:
                    # check return is IP or CNAME
                    if self.module_dns.check_ip(mx_resolver) is None:
                        a_mx_resolver = self.module_dns.dns_resolver(mx_resolver, "A")
                    else:
                        a_mx_resolver = mx_resolver
                    # check result of the query A
                    if a_mx_resolver is not False and a_mx_resolver is not None:
                        # check if IP is include in subnets
                        if self.module_regex.check_network_latam(a_mx_resolver):
                            self.dict_ticket.update({'main_check': a_mx_resolver})
                            self.dict_ticket.update({'check_general': True})

        except GeneralError:
            raise GeneralError

        except Exception as er:
            # generate a error log
            self._log.error("check_mx_resolver - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def check_website_url(self):
        try:
            list_users_website = list()
            # test NS entry
            for domain_website in self.dict_ticket['check_url']:
                if "teste.website" in domain_website.parsed_url.netloc and domain_website.parsed_url.path != "":
                    self.user_website_url = self.module_regex.user_website_url(domain_website.parsed_url.path)
                    if self.user_website_url is not None and self.user_website_url is not False and self.user_website_url not in list_users_website:
                        list_users_website.append(self.user_website_url)
                        self.dict_ticket.update({self.user_website_url: domain_website})
                        self.dict_ticket.update({self.user_website_url + "_thread_id": str(uuid.uuid4())})
                        self.dict_ticket.update({'main_users': list_users_website})
                        self.dict_ticket.update({'check_website_url': True})
                        self.dict_ticket.update({'check_general': True})

        except Exception as er:
            self._log.error("check_website_url - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def apply_website_url(self):
        try:
            self.module_database.insert_analyzing(ticket_id=self.dict_ticket['id'], thread_id=self.dict_ticket[self.user_website_url + "_thread_id"],
                                                  main_check=self.module_regex.remove_www(self.dict_ticket[self.user_website_url].parsed_url.netloc),
                                                  main_user=self.user_website_url, status=1, handled=1)
            if self.dict_ticket.get("path_url") is not None and len(self.dict_ticket['path_url']) >= 3:
                self.module_database.update_analyzing("path_url", self.dict_ticket['path_url'], thread_id=self.dict_ticket[self.user_website_url + "_thread_id"])

        except DatabaseInsertFailed:
            return ZenRollback

        except DatabaseUpdateFailed:
            return ContinueError

        except Exception as er:
            # generate a error log
            self._log.error("apply_website_url - {} - {}".format(self.__class__.__name__, er))
            return GeneralError

    def apply_website_url_ticket(self):
        try:
            # comment in ticket
            self.module_zen.comment_ticket(self.dict_ticket['id'], self.module_zen.return_comment(brand=self.brand), brand=self.brand)
            # get ticket object
            zen_return = self.module_zen.search_id(self.dict_ticket['id'], brand=self.brand)
            # update tags in ticket
            zen_return.tags = self.module_zen.handle_tag(zen_return.tags, self.module_zen.tag_checking, self.module_zen.tag_search)
            # apply the change in ticket
            self.module_zen.update_ticket(zen_return, brand=self.brand)

        except ZenFailed:
            raise ZenRollback

        except Exception as er:
            # generate a error log
            self._log.error("apply_website_url_ticket - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def apply_url(self):
        try:
            # comment in ticket
            self.module_zen.comment_ticket(self.dict_ticket['id'], self.module_zen.return_comment(brand=self.brand), brand=self.brand)
            # get ticket object
            zen_return = self.module_zen.search_id(self.dict_ticket['id'], brand=self.brand)
            zen_return.tags = self.module_zen.handle_tag(zen_return.tags, self.module_zen.tag_checking, self.module_zen.tag_search)
            # apply the change in ticket
            self.module_zen.update_ticket(zen_return, brand=self.brand)
            # insert in database
            self.module_database.insert_analyzing(ticket_id=self.dict_ticket['id'], thread_id=self.dict_ticket['thread_id'],
                                                  main_check=self.dict_ticket['main_check'],
                                                  main_domain=self.module_regex.remove_www(self.dict_ticket['main_domain']), status=1, handled=1)
            if self.dict_ticket.get("path_url") is not None and len(self.dict_ticket['path_url']) >= 3:
                self.module_database.update_analyzing("path_url", self.dict_ticket['path_url'], thread_id=self.dict_ticket['thread_id'])

        except ZenFailed:
            raise ZenRollback

        except DatabaseInsertFailed:
            raise ZenRollback

        except DatabaseUpdateFailed:
            raise ContinueError

        except Exception as er:
            # generate a error log
            self._log.error("apply_url - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def apply_ip(self):
        """
        Apply result true in database for IP check, insert the data and update ticket
        :return: False on failure
        :rtype: bool
        """
        try:
            # comment in ticket
            self.module_zen.comment_ticket(self.dict_ticket['id'], self.module_zen.return_comment(brand=self.brand), brand=self.brand)
            # get ticket object
            zen_return = self.module_zen.search_id(self.dict_ticket['id'], brand=self.brand)
            # update ticket
            zen_return.tags = self.module_zen.handle_tag(zen_return.tags, self.module_zen.tag_true, self.module_zen.tag_search)
            zen_return.assignee = None
            zen_return.status = "open"
            # apply the change in ticket
            self.module_zen.update_ticket(zen_return, brand=self.brand)
            # insert in database
            self.module_database.insert_analyzing(ticket_id=self.dict_ticket['id'], thread_id=self.dict_ticket['thread_id'],
                                                  main_check=self.dict_ticket['main_check'], main_ip=self.dict_ticket['main_ip'],
                                                  status=3, handled=0)

        except ZenFailed:
            raise ZenRollback

        except DatabaseInsertFailed:
            raise ZenRollback

        except Exception as er:
            # generate a error log
            self._log.error("apply_ip - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def apply_false(self):
        """
        Apply result false in database, insert the data and update ticket
        :return: False on failure
        :rtype: bool
        """
        try:
            # get ticket object
            zen_return = self.module_zen.macro(self.dict_ticket['id'], self.module_zen.macro_false(brand=self.brand), brand=self.brand)
            zen_return.ticket.tags = self.module_zen.handle_tag(zen_return.ticket.tags, self.module_zen.tag_false, self.module_zen.tag_search)
            zen_return.ticket.tags = self.module_zen.handle_tag(zen_return.ticket.tags, self.module_zen.tag_closed)
            zen_return.ticket.assignee = None
            zen_return.ticket.status = "pending"
            # apply the change in ticket
            self.module_zen.update_ticket(zen_return, type_macro=True, brand=self.brand)
            # insert result in database
            self.module_database.insert_check_false(self.dict_ticket['id'])

        except ZenFailed:
            raise ZenRollback

        except DatabaseInsertFailed:
            raise ZenRollback

        except Exception as er:
            # generate a error log
            self._log.error("apply_false - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def apply_error(self):
        try:
            # comment in ticket
            self.module_zen.comment_ticket(self.dict_ticket['id'], self.module_zen.return_comment(brand=self.brand), brand=self.brand)
            # get ticket object
            zen_return = self.module_zen.search_id(self.dict_ticket['id'], brand=self.brand)
            zen_return.tags = self.module_zen.handle_tag(zen_return.tags, self.module_zen.tag_true_error, self.module_zen.tag_search)
            zen_return.assignee = None
            zen_return.status = "open"
            # update ticket
            self.module_zen.update_ticket(zen_return, brand=self.brand)
            # check database
            if self.module_database.check_thread_id(self.dict_ticket['thread_id']):
                # update status analyzing
                self.module_database.update_analyzing("status", 2, thread_id=self.dict_ticket['thread_id'])
                # update analyzing
                self.module_database.update_analyzing("handled", 0, thread_id=self.dict_ticket['thread_id'])
            else:
                self.module_database.insert_analyzing_error(ticket_id=self.dict_ticket['id'], thread_id=self.dict_ticket['thread_id'],
                                                            status=2, handled=0)

        except DatabaseSelectFailed:
            raise ContinueError

        except ZenFailed:
            raise ContinueError

        except DatabaseInsertFailed:
            raise ZenRollback

        except DatabaseUpdateFailed:
            return ContinueError

        except Exception as er:
            # generate a error log
            self._log.error("apply_error - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def apply_duplicated_domain(self):
        """
        Apply result false in database, insert the data and update ticket
        :return: False on failure
        :rtype: bool
        """
        try:
            # comment in ticket
            self.module_zen.comment_ticket(self.dict_ticket['id'], self.module_zen.duplicated_comment(brand=self.brand), brand=self.brand)
            # get ticket object
            zen_return = self.module_zen.search_id(self.dict_ticket['id'], brand=self.brand)
            zen_return.tags = self.module_zen.handle_tag(zen_return.tags, self.module_zen.tag_duplicated, self.module_zen.tag_search)
            zen_return.tags = self.module_zen.handle_tag(zen_return.tags, self.module_zen.tag_closed)
            zen_return.assignee = None
            zen_return.status = "pending"
            # apply the change in ticket
            self.module_zen.update_ticket(zen_return, brand=self.brand)
            # insert result in database
            self.module_database.insert_check_duplicated(ticket_id=self.dict_ticket['id'], main_domain=self.dict_ticket['main_domain'])

        except ZenFailed:
            raise ContinueError

        except DatabaseInsertFailed:
            raise ContinueError

        except Exception as er:
            # generate a error log
            self._log.error("apply_duplicated_domain - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def check_ticket_type(self):
        """
        Check if the ticket is Malware or Phishing denunciation
        """
        try:
            # check string malware or phising in description
            # 3 - there are phishing and malware regex
            if (self.module_regex.check_malware(self.dict_ticket) != 0 and
                self.module_regex.check_malware(self.dict_ticket) is not False) and (
                    self.module_regex.check_phishing(self.dict_ticket) != 0 and
                    self.module_regex.check_phishing(self.dict_ticket) is not False):
                self.dict_ticket.update({'check_type': 3})
                self._log.info("Ticket {} is phishing and malware".format(self.dict_ticket['id']))
            # 1 - there are malware regex
            elif self.module_regex.check_malware(self.dict_ticket) != 0 and self.module_regex.check_malware(
                    self.dict_ticket) is not False:
                self.dict_ticket.update({'check_type': 1})
                self._log.info("Ticket {} is malware".format(self.dict_ticket['id']))
            # 2 - there are phishing regex
            elif self.module_regex.check_phishing(self.dict_ticket) != 0 and self.module_regex.check_phishing(
                    self.dict_ticket) is not False:
                self.dict_ticket.update({'check_type': 2})
                self._log.info("Ticket {} is phishing".format(self.dict_ticket['id']))
            else:
                # ticket not is a report about phishing or malware
                self.dict_ticket.update({'check_type': 0})
                self._log.info("Ticket {} is not phishing or malware".format(self.dict_ticket['id']))

            # check strings of the intentional_words in description ticket
            if self.module_regex.check_wordlist(self.dict_ticket):
                # if true set value one
                self.dict_ticket.update({'intentional_words': 1})
            else:
                # if false set value zero
                self.dict_ticket.update({'intentional_words': 0})

            # get result of the regex in tickets, store email and domains/ips
            result_regex, result_email = self.module_regex.regex_check(self.dict_ticket)
            # create key in dict with each result
            self.dict_ticket.update({'regex_check': result_regex})
            self.dict_ticket.update({'regex_email': result_email})

        except GeneralError:
            raise GeneralError

        except Exception as er:
            self._log.error("check_ticket_type - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def check_ticket_ip(self):
        """
        Check IP in result of the regex
        """
        try:
            check_ip = list()
            # check IP in result of the regex
            for regex_check in self.dict_ticket['regex_check']:
                # confirm if IP is a true IP
                check_ip_temp = self.module_dns.check_ip(str(regex_check))
                if check_ip_temp is not None and check_ip_temp is not False:
                    # check if result is a public IP and version 4
                    if check_ip_temp.is_global is True and check_ip_temp.version == 4:
                        check_ip.append(str(check_ip_temp))
            # create checkIP in dict with IP captured
            if len(check_ip) > 0:
                self.dict_ticket.update({'check_ip': check_ip})
                self.dict_ticket.update({'found_ip': True})
                # generate a info log
                self._log.info(check_ip)

        except Exception as er:
            self._log.error("check_ticket_ip - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def check_ticket_url(self):
        """
        Check URL in result of the regex
        """
        try:
            check_url = list()
            log_check_url = list()
            # check URL in result of the regex
            for regex_check in self.dict_ticket['regex_check']:
                # check if URL is a valid domain format
                check_url_temp = self.module_dns.check_url(str(regex_check))
                if check_url_temp is not None and check_url_temp is not False:
                    # exclude domains reliable
                    if self.module_regex.check_exclude(check_url_temp.parsed_url.netloc) is None:
                        check_url_add = False
                        # store object in list
                        if len(check_url) == 0:
                            check_url.append(check_url_temp)
                            log_check_url.append(str(check_url_temp.parsed_url.netloc) + str(check_url_temp.parsed_url.path))
                        else:
                            for temp_check_url in check_url:
                                if temp_check_url.parsed_url.netloc == check_url_temp.parsed_url.netloc:
                                    if len(check_url_temp.parsed_url.path) > len(temp_check_url.parsed_url.path):
                                        del check_url[check_url.index(temp_check_url)]
                                        del log_check_url[log_check_url.index(str(temp_check_url.parsed_url.netloc) + str(temp_check_url.parsed_url.path))]
                                        check_url.append(check_url_temp)
                                        log_check_url.append(str(check_url_temp.parsed_url.netloc) + str(check_url_temp.parsed_url.path))
                                        check_url_add = True
                            if check_url_add is False:
                                check_url.append(check_url_temp)
                                log_check_url.append(str(check_url_temp.parsed_url.netloc) + str(check_url_temp.parsed_url.path))
            # create checkURL in dict with domains captured
            if len(check_url) > 0:
                self.dict_ticket.update({'check_url': check_url})
                self.dict_ticket.update({'found_url': True})
                # generate a info log
                self._log.info(check_url)
                self._log.info(log_check_url)

        except Exception as er:
            self._log.error("check_ticket_url - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def print_page(self):
        try:
            # set path report and create complete url
            print_path = os.path.join(self.report_print, self.dict_ticket['thread_id'] + ".jpg")
            if self.dict_ticket['main_query'] is not None and len(self.dict_ticket['main_query']) >= 2:
                print_url = self.dict_ticket['main_domain'] + self.dict_ticket['path_url'] + "?" + self.dict_ticket['main_query']
            else:
                print_url = self.dict_ticket['main_domain'] + self.dict_ticket['path_url']
            # check if path url exists
            if len(self.dict_ticket['path_url']) >= 3:
                try:
                    imgkit.from_url(print_url, print_path, options=self.options_img_kit)

                except Exception as er:
                    time.sleep(1)
                    self._log.debug("imgkit error - remove print {} - {} - {}".format(print_path, self.__class__.__name__, er))
                    os.remove(print_path)

        except Exception as er:
            # generate a error log
            self._log.error("print_page - {} - {}".format(self.__class__.__name__, er))
            return False

    def get_tickets(self, group_search):
        try:
            # Get gold tickets in abuse group with tag not_checked
            tickets_object = self.module_zen.search_abuse("hold", group_search, self.module_zen.tag_search,
                                                               brand=self.brand)
            if tickets_object is not False:
                tickets_json = tickets_object._response_json
                tickets_result = tickets_json.get('results')
                return tickets_result
            else:
                return False

        except ZenFailed:
            return False

        except Exception as er:
            # generate a error log
            self._log.error("get_tickets - {} - {}".format(self.__class__.__name__, er))
            return False

    def zen_rollback(self):
        try:
            # get ticket object
            zen_return = self.module_zen.search_id(self.dict_ticket['id'], brand=self.brand)
            # update tags in ticket
            zen_return.tags = self.module_zen.handle_tag(zen_return.tags, self.module_zen.tag_search,
                                                         self.module_zen.tag_checking)
            # apply the change in ticket
            self.module_zen.update_ticket(zen_return, brand=self.brand)

        except ZenFailed:
            return False

        except Exception as er:
            # generate a error log
            self._log.error("zen_rollback - {} - {}".format(self.__class__.__name__, er))
            return False

    def process_tickets(self, brand):
        """
        Principal function that execute and call others functions, make all process for checking and apply result
        :return: False on failure
        :rtype: bool
        """
        try:
            self.brand = brand
            # check update of the TLD data
            self.module_dns.update_date_tld()
            # define group search
            if self.brand == "es":
                tickets_result = self.get_tickets(self.module_zen.group_abuse_es)
            else:
                tickets_result = self.get_tickets(self.module_zen.group_abuse)
            if tickets_result is not None and tickets_result is not False and \
                    len(tickets_result) > 0:
                # walks the tickets
                for self.dict_ticket in tickets_result:
                    try:
                        # set false for item used in checking
                        self.dict_ticket.update({'check_website_url_ticket': False})
                        self.dict_ticket.update({'check_website_url': False})
                        self.dict_ticket.update({'check_general': False})
                        self.dict_ticket.update({'found_url': False})
                        self.dict_ticket.update({'found_ip': False})
                        self.dict_ticket.update({'brand': self.brand})
                        # call functions
                        self.check_ticket_type()
                        self.check_ticket_url()
                        self.check_ticket_ip()
                        # generate threadID
                        self.dict_ticket.update({'thread_id': str(uuid.uuid4())})
                        # check if found URL in ticket
                        if self.dict_ticket['found_url']:
                            # check if exists URL with teste.website
                            self.check_website_url()
                            # check result of checkWebsiteURL and walks MainUsers
                            if self.dict_ticket['check_website_url']:
                                for self.user_website_url in self.dict_ticket['main_users']:
                                    if not self.dict_ticket['check_website_url_ticket']:
                                        self.apply_website_url_ticket()
                                        self.dict_ticket.update({'check_website_url_ticket': True})
                                    # set value in dict for use in apply_website_url
                                    self.dict_ticket.update({'main_domain': self.module_regex.remove_www(
                                        self.dict_ticket[self.user_website_url].parsed_url.netloc)})
                                    self.dict_ticket.update(
                                        {'path_url': self.dict_ticket[self.user_website_url].parsed_url.path})
                                    # apply result for user in websiteURL
                                    self.apply_website_url()
                                    # send message in queue
                                    self.message_analyze_website()
                            else:
                                # walks the URLs
                                for self.domain_netloc in self.dict_ticket['check_url']:
                                    # get NS domain and check
                                    self.check_ns_resolver()
                                    # check A record and check
                                    self.check_a_resolver()
                                    # check MX record and check
                                    self.check_mx_resolver()
                                    # stop for if true in checking
                                    if self.dict_ticket['check_general']:
                                        self.dict_ticket.update({'main_domain': self.module_regex.remove_www(self.domain_netloc.parsed_url.netloc)})
                                        self.dict_ticket.update({'main_query': self.domain_netloc.parsed_url.query})
                                        self.dict_ticket.update({'path_url': self.domain_netloc.parsed_url.path})
                                        break
                                # check if this domain had another report within three days
                                if self.dict_ticket['check_general'] and \
                                        self.module_database.duplicated_domain(self.dict_ticket['main_domain']):
                                    # apply duplicated in ticket
                                    self.apply_duplicated_domain()
                                    continue
                                elif self.dict_ticket['check_general']:
                                    # check if ticket is a phishing
                                    if self.dict_ticket['check_type'] == 2 or self.dict_ticket['check_type'] == 3:
                                        # apply result for URL
                                        self.apply_url()
                                        # send message in queue VT
                                        self.message_url_vt()
                                        # send message in queue
                                        self.message_analyze()
                                        # print page
                                        self.print_page()
                                        # check result and log finish message
                                        self._log.info("Finish apply_url with analyzing - '{}' - '{}'".format(self.dict_ticket['main_domain'], self.dict_ticket['id']))
                                        continue
                                    else:
                                        self.apply_url()
                                        self._log.info("Finish apply_url without analyzing - '{}' - '{}'".format(self.dict_ticket['main_domain'], self.dict_ticket['id']))
                                        continue
                        # check ip and handle
                        if self.dict_ticket['found_ip']:
                            # walks the IPs
                            for self.valid_ip in self.dict_ticket['check_ip']:
                                # check if ip has already been checked
                                self.check_network_ip()
                                if self.dict_ticket['check_general']:
                                    break
                            if self.dict_ticket['check_general']:
                                self.apply_ip()
                                self._log.info("Finish in apply_ip - '{}' - '{}'".format(self.valid_ip, self.dict_ticket['id']))
                                continue
                        # verify check general and apply_false
                        if self.dict_ticket['check_general'] is False:
                            self.apply_false()
                            self._log.info("Finish apply_false in - '{}'".format(self.dict_ticket['id']))
                            continue

                    except ZenRollback:
                        self.zen_rollback()
                        continue

                    except DatabaseSelectFailed:
                        continue

                    except ContinueError:
                        continue

                    except GeneralError:
                        self._log.info("Finish apply_error in - '{}'".format(self.dict_ticket['id']))
                        self.apply_error()
                        continue

                    except Exception as er:
                        # generate a error log
                        self._log.error("process_tickets - '{}' - '{}' - '{}'".format(self.__class__.__name__, er, self.dict_ticket['id']))
                        continue

        except Exception as er:
            # generate a error log
            self._log.critical("process_tickets - {} - {}".format(self.__class__.__name__, er))
            return False

    def process_generate_model(self, ticket_id, thread_id, main_domain):
        try:
            if self.module_configuration.application == "model":
                intentional_words = self.module_database.get_value("intentional_words", thread_id)
                brand = self.module_database.get_value("brand", thread_id)
                if intentional_words is not False and intentional_words is not None and \
                        brand is not False and brand is not None:
                    message_generate_model = dict(main_domain=main_domain,
                                                  ticket_id=ticket_id,
                                                  thread_id=thread_id,
                                                  intentional_words=intentional_words,
                                                  brand=brand)
                    self.queue_analyze.publish(message_generate_model)
                    self._log.info("Generate model send analyze - {}".format(message_generate_model))
                    return True
                else:
                    self._log.error("Failed generate model - {} - {} - {}".format(ticket_id, thread_id, main_domain))
                    return False
            else:
                self._log.info("Invalid application environment.")

        except DatabaseSelectFailed:
            return False

        except Exception as er:
            # generate a error log
            self._log.critical("process_generate_model - {} - {}".format(self.__class__.__name__, er))
            return False

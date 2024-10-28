# -*- coding: utf-8 -*-
"""


- Contributors
Elliann Marks <elian.markes@gmail.com>

**- Version 02 - 17/07/2019**

**- Version 03 - 18/12/2019**

- Commands in playbooks
**whmapi1 domainuserdata domain=example.com.br**
**whmapi1 accountsummary user=example**
**whmapi1 list_mysql_databases_and_users user=example**
**uapi --user=example DomainInfo list_domains**
**uapi --user=example Bandwidth query grouping=domain%7Cyear_month_day%7Cprotocol protocols=http%7Cftp timezone=America%2FSao_Paulo**
**uapi --user=example DomainInfo domains_data format=hash return_https_redirect_status=1**
**uapi --user=example Email get_main_account_disk_usage**
**uapi --user=example Email list_mxs**
**uapi --user=example Email list_pops_with_disk**
**uapi --user=example Fileman list_files dir=public_html types=dir%7Cfile limit_to_list=0 show_hidden=1 check_for_leaf_directories=1 include_mime=1 include_hash=1**
**uapi --user=example Ftp list_ftp_with_disk include_acct_types=main%7Canonymous**
**uapi --user=example last_login get_last_or_current_logged_in_ip**

"""

# libraries
import os
import json
import re
import ast
from sgqlc.endpoint.http import HTTPEndpoint
from contextlib import closing
from abuse_automation.module_ansible import ModuleAnsible
from abuse_automation.module_dns import ModuleDNS
from abuse_automation.module_dates import ModuleDates
from abuse_automation.module_database import ModuleDatabase
from abuse_automation.module_regex import ModuleRegex
from abuse_automation.module_exceptions import GeneralError, AnalyzeFailed, \
    DatabaseUpdateFailed, ResultFailed, FileResultFailed, GraphQLFailed, AnsibleScanFailed

class ModuleAnalyze:

    def __init__(self, module_log, module_configuration, values_ticket):
        """
        Responsible for execute the checking playbooks and store result in dict.
        :param module_log: log instance
        :type module_log: Object
        """
        try:
            self._log = module_log
            self.module_configuration = module_configuration
            self.values_ticket = values_ticket
            # create the instances
            self.module_dates = ModuleDates(self._log)
            self.module_regex = ModuleRegex(self._log, self.module_configuration)
            self.module_dns = ModuleDNS(self._log, self.module_configuration)
            self.module_database = ModuleDatabase(self._log, self.module_configuration)
            # instance ansible module to all servers
            self.module_ansible = ModuleAnsible(module_log=self._log,
                                                module_configuration=self.module_configuration)
            # set variables of configuration
            self.report_dir = self.module_configuration.report_dir
            self.playbook_check = self.module_configuration.playbook_check
            self.playbook_scan = self.module_configuration.playbook_scan
            self.playbook_abuse = self.module_configuration.playbook_abuse
            self.url_graphql = self.module_configuration.api_example
            # set query graphql
            self.query_graphql = '''query (
                                $identify: String!,
                                $serverType: String!,
                                $domain: String!,
                                $brand: String!,
                                $token: String
                                )
                            {
                            userInfo (
                                identify: $identify
                                serverType: $serverType
                                domain: $domain
                                brand: $brand
                                token: $token
                            ) { 
                                result, httpStatusCode, message 
                                } 
                            }'''
            # set values
            self.check_type = self.values_ticket['check_type']
            self.check_website_url = self.values_ticket['check_website_url']
            self.path_url = self.values_ticket['path_url']
            self.main_check = self.values_ticket['main_check']
            self.intentional_words = self.values_ticket['intentional_words']
            self.main_domain = self.values_ticket['main_domain']
            self.ticket_id = self.values_ticket['ticket_id']
            self.thread_id = self.values_ticket['thread_id']
            self.brand = self.values_ticket['brand']
            # directory report
            self.report_case = str(self.main_domain) + "_" + str(self.ticket_id) + "_" + str(self.thread_id)
            self.report_case_path = os.path.join(self.report_dir, self.report_case)
            # files of the reports
            self.file_domain_user_data = os.path.join(self.report_case_path, "domain_user_data.json")
            self.file_account_summary = os.path.join(self.report_case_path, "account_summary.json")
            self.file_account_summary_owner = os.path.join(self.report_case_path, "account_summary_owner.json")
            self.file_email_account_disk = os.path.join(self.report_case_path, "email_account_disk.json")
            self.file_last_login = os.path.join(self.report_case_path, "last_login.json")
            self.file_pops_disk = os.path.join(self.report_case_path, "list_pops_disk.json")
            self.file_mysql_databases = os.path.join(self.report_case_path, "mysql_databases.json")
            self.file_ftp_disk = os.path.join(self.report_case_path, "list_ftp_disk.json")
            self.file_email_mxs = os.path.join(self.report_case_path, "email_list_mxs.json")
            self.file_domains_data = os.path.join(self.report_case_path, "domains_data.json")
            self.file_list_domains = os.path.join(self.report_case_path, "list_domains.json")
            self.file_report = os.path.join(self.report_case_path, "report")
            self.file_hostname = os.path.join(self.report_case_path, "hostname")
            # paths scan
            self.report_scan_phishing = os.path.join(self.report_case_path, "scan_phishing")
            self.report_scan_malware = os.path.join(self.report_case_path, "scan_malware")
            self.report_user_info = os.path.join(self.report_case_path, "user_info.json")
            self.report_user_info_owner = os.path.join(self.report_case_path, "user_info_owner.json")
            self.file_flag_check_error = os.path.join(self.report_case_path, "check_error.flag")
            # check if exist path in URL and set file_url
            self.file_url = None
            self.set_file_url()
            # set type scan
            self.type_scan = None
            self.set_type_scan()
            # check and process main_check
            self.server = None
            self.set_server()
            # initialize dict
            self.result_dict = dict(ansible_check=False,
                                    scan=False,
                                    path_url=self.path_url,
                                    main_check=self.main_check,
                                    intentional_words=self.intentional_words,
                                    thread_id=self.thread_id,
                                    ticket_id=self.ticket_id,
                                    main_domain=self.main_domain,
                                    brand=self.brand,
                                    server=self.server,
                                    general_error=False)
            # variables
            self.ansible_check = None
            self.summary_ansible = None
            self.scan = None

        except GeneralError:
            raise AnalyzeFailed

        except KeyError as er:
            self._log.error("Analyze key - {} - {}".format(self.__class__.__name__, er))
            raise AnalyzeFailed

        except Exception as er:
            # generate a error log
            self._log.error("Analyze init - {} - {}".format(self.__class__.__name__, er))
            raise AnalyzeFailed

    def set_server(self):
        try:
            temp_main_check = self.module_dns.check_ip(self.main_check)
            if temp_main_check is None or temp_main_check is False:
                self.server = self.module_dns.dns_resolver(self.main_check)
            else:
                self.server = self.main_check

        except Exception as er:
            # generate a error log
            self._log.error("set_server - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def set_file_url(self):
        try:
            if self.path_url is not None and self.path_url is not False and len(self.path_url) >= 3:
                if self.check_website_url:
                    temp_file_url = re.sub("/~[a-z0-9]+", "", self.path_url)
                    if len(temp_file_url) >= 3:
                        self.file_url = temp_file_url
                    else:
                        self.file_url = None
                else:
                    self.file_url = self.path_url
            else:
                self.file_url = None

        except Exception as er:
            # generate a error log
            self._log.error("set_file_url - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def set_type_scan(self):
        try:
            if self.check_type == 3:
                self.type_scan = "scan_all"
            elif self.check_type == 2:
                self.type_scan = "scan_phishing"
            elif self.check_type == 1:
                self.type_scan = "scan_malware"
            else:
                raise GeneralError

        except Exception as er:
            # generate a error log
            self._log.error("set_type_scan - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def get_ansible_vars(self):
        try:
            if self.file_url is None:
                if self.check_website_url:
                    vars_ansible = {
                        "user": self.main_domain,
                        "ticket_id": self.ticket_id,
                        "thread_id": self.thread_id,
                    }
                else:
                    vars_ansible = {
                        "domain": self.main_domain,
                        "ticket_id": self.ticket_id,
                        "thread_id": self.thread_id,
                    }
            else:
                if self.check_website_url:
                    vars_ansible = {
                        "user": self.main_domain,
                        "ticket_id": self.ticket_id,
                        "thread_id": self.thread_id,
                        "file_url": self.file_url,
                    }
                else:
                    vars_ansible = {
                        "domain": self.main_domain,
                        "ticket_id": self.ticket_id,
                        "thread_id": self.thread_id,
                        "file_url": self.file_url,
                    }
            return vars_ansible


        except Exception as er:
            # generate a error log
            self._log.error("get_ansible_vars - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def process(self):
        """
        Responsible for execute the playbooks domain_check, scan_check and abuse_upload
        :return: True in success and False in error
        :rtype: bool
        """
        try:
            if os.path.exists(self.file_flag_check_error):
                os.remove(self.file_flag_check_error)
            vars_ansible = self.get_ansible_vars()
            # mark start ansible check, 1 - start, 2 - failed, 3 - completed
            self.module_database.update_analyzing("ansible_check", 1, self.thread_id)
            # debug log
            self._log.debug(vars_ansible)
            # execute playbook and get summary result
            if self.module_configuration.application == "development" or \
                self.module_configuration.application == "production":
                self.summary_ansible = self.module_ansible.execute(self.playbook_check, vars_ansible, self.server)
                # check if execution completed with success
                if self.summary_ansible is False or self.summary_ansible is None or self.summary_ansible['skipped'] > 80 or \
                        self.summary_ansible['rescued'] > 0 or os.path.exists(self.file_flag_check_error) or \
                        not os.path.exists(self.report_case_path):
                    # update ansible_check with failed
                    self.module_database.update_analyzing("ansible_check", 2, self.thread_id)
                    self.ansible_check = False
                    # error log
                    self._log.error("Ansible check failed - {}".format(self.values_ticket))
                    self.result_dict.update({"general_error": True})
                else:
                    # debug log
                    self._log.debug("Ansible check completed - {}".format(self.values_ticket))
                    # execute check results
                    self.check_results()
                    # execute get user info
                    self.get_user_info()
                    # execute playbook scan
                    self.scan_ansible()
                    # execute playbook upload reports
                    if self.module_configuration.application == "production":
                        self.abuse_upload()
                    self.ansible_check = True
                    # set completed with success in ansible_check
                    self.module_database.update_analyzing("ansible_check", 3, self.thread_id)
            elif self.module_configuration.application == "model":
                # get info e set values without execute playbook
                self.ansible_check = True
                if os.path.exists(self.report_case_path) and self.check_results() and self.get_user_info():
                    if os.path.exists(self.report_scan_malware) and os.path.exists(self.report_scan_phishing):
                        self.scan = self.count_malwares(self.report_scan_phishing) + self.count_malwares(
                            self.report_scan_malware)
                    elif os.path.exists(self.report_scan_phishing):
                        self.scan = self.count_malwares(self.report_scan_phishing)
                    elif os.path.exists(self.report_scan_malware):
                        self.scan = self.count_malwares(self.report_scan_malware)
            # add in dict result scan and ansible_check
            self.result_dict.update({"scan": self.scan})
            self.result_dict.update({"ansible_check": self.ansible_check})

        except GeneralError:
            raise AnalyzeFailed

        except DatabaseUpdateFailed:
            raise AnalyzeFailed

        except ResultFailed:
            raise AnalyzeFailed

        except FileResultFailed:
            raise AnalyzeFailed

        except Exception as er:
            # generate a error log
            self._log.error("Analyze process - {} - {}".format(self.__class__.__name__, er))
            raise AnalyzeFailed

    def check_results(self):
        try:
            # execute and check sets dicts
            self.set_domain_user_data()
            self.set_account_summary()
            self.set_email_account_disk()
            self.set_last_login()
            self.set_pops_disk()
            self.set_mysql_databases()
            self.set_ftp_disk()
            self.set_email_mxs()
            self.set_domains_data()
            self.set_list_domains()
            self.set_report()
            self.set_hostname()
            if self.result_dict['user'] is not None and self.result_dict['user'] is not False and \
                    self.result_dict['server_type'] is not None and self.result_dict['server_type'] is not False and \
                    self.result_dict['main_server'] is not None and self.result_dict['main_server'] is not False:
                # update main_user in database
                self.module_database.update_analyzing("main_user", self.result_dict['user'], self.thread_id)
                self.module_database.update_analyzing("server_type", self.result_dict['server_type'], self.thread_id)
                self.module_database.update_analyzing("main_server", self.result_dict['main_server'], self.thread_id)
                if self.result_dict['owner'] != "root" and os.path.exists(self.file_account_summary_owner):
                    self.set_account_summary_owner()
                    self.module_database.update_analyzing("owner", self.result_dict['owner'], self.thread_id)
                    self.get_user_info_owner()
            else:
                self._log.info("Error in update main_user / server_type / main_server - {}".format(self.values_ticket))
                raise ResultFailed

        except ResultFailed:
            raise GeneralError

        except FileResultFailed:
            raise GeneralError

        except DatabaseUpdateFailed:
            raise GeneralError

        except Exception as er:
            # generate a error log
            self._log.error("check_results {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def scan_ansible(self):
        try:
            # check if ansible_check is true and typeScan is defined and report directory exists
            if self.type_scan is not False and self.type_scan is not None:
                # check if file_url is defined
                if self.file_url is not None and "/" in self.file_url and "../" not in self.file_url:
                    # execute scan in directory where file is
                    self.scan_path_url()
                    # check result of the scan
                    self.check_scan_result()
                    if self.scan == 0 or self.scan is None:
                        # if scan not found any malicious files, execute scan in home directory
                        self.scan_home()
                        self.check_scan_result()
                else:
                    # execute scan in doc root directory of the domain
                    self.scan_doc_root()
                    self.check_scan_result()
                    if self.scan == 0 or self.scan is None:
                        # if scan not found any malicious files, execute scan in home directory
                        self.scan_home()
                        self.check_scan_result()
                if self.scan is not None:
                    # update resultScan in database
                    self.module_database.update_analyzing("result_scan", self.scan, self.thread_id)
            else:
                # debug log
                self._log.info("Type scan failed - {}".format(self.values_ticket))
                raise GeneralError

        except AnsibleScanFailed:
            try:
                self.module_database.update_analyzing("ansible_scan", 2, self.thread_id)

            except DatabaseUpdateFailed:
                pass
            raise GeneralError

        except DatabaseUpdateFailed:
            raise GeneralError

        except Exception as er:
            # generate a error log
            self._log.error("scan_ansible {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def get_user_info(self):
        try:
            if self.module_configuration.application == "development" or \
                    self.module_configuration.application == "production":
                if self.result_dict['server_type'] == "vps" or self.result_dict['server_type'] == "dedi":
                    identify = self.result_dict['ip']
                else:
                    identify = self.result_dict['user']
                variables_graphql = {
                    'identify': identify,
                    'serverType': self.result_dict['server_type'],
                    'domain': self.result_dict['domain'],
                    'brand': self.brand,
                    'token': self.module_configuration.whmcs_user_info
                }
                endpoint_graphql = HTTPEndpoint(self.url_graphql)
                data_graphql = endpoint_graphql(self.query_graphql, variables_graphql)
                data_user_info = data_graphql['data']
                user_info = data_user_info['userInfo']
                result_user_info = user_info['result']
                code_user_info = user_info['httpStatusCode']
                message_user_info = user_info['message']
                if result_user_info and code_user_info == 200:
                    dict_user_info = ast.literal_eval(message_user_info)
                    client_email = dict_user_info['client']['email']
                    whmcs_last_login = dict_user_info['lastLogin']['ip']
                    self.result_dict.update({"whmcs_last_login": whmcs_last_login})
                    with open(self.report_user_info, "w") as open_report_user_info:
                        json.dump(dict_user_info, open_report_user_info)
                else:
                    self._log.info("GraphQL return failed - {}".format(self.values_ticket))
                    raise GeneralError
            elif self.module_configuration.application == "model":
                if os.path.exists(self.report_user_info):
                    with open(self.report_user_info, "r") as open_report_user_info:
                        dict_user_info = json.load(open_report_user_info)
                        whmcs_last_login = dict_user_info['lastLogin']['ip']
                        client_email = dict_user_info['client']['email']
                        self.result_dict.update({"whmcs_last_login": whmcs_last_login})
                else:
                    self._log.info("GraphQL return failed - {}".format(self.values_ticket))
                    raise GeneralError

        except GeneralError:
            if "data_graphql" in locals():
                self._log.info("GraphQL User Info Result - {}".format(data_graphql.get("errors")))
            raise GraphQLFailed

        except KeyError as er:
            # log info
            self._log.info("Get User Info KeyError - {}".format(er))
            if "data_graphql" in locals():
                self._log.info("GraphQL User Info Result - {}".format(data_graphql.get("errors")))
            raise GraphQLFailed

        except Exception as er:
            if "data_graphql" in locals():
                self._log.info("GraphQL User Info Result - {}".format(data_graphql.get("errors")))
            # generate a error log
            self._log.error("get_user_info - {} - {}".format(self.__class__.__name__, er))
            raise GraphQLFailed

    def get_user_info_owner(self):
        try:
            if self.module_configuration.application == "development" or \
                    self.module_configuration.application == "production":
                variables_graphql = {
                    'identify': self.result_dict['owner'],
                    'serverType': self.result_dict['server_type'],
                    'domain': self.result_dict['domain_owner'],
                    'brand': self.brand,
                    'token': self.module_configuration.whmcs_user_info
                }
                endpoint_graphql = HTTPEndpoint(self.url_graphql)
                data_graphql = endpoint_graphql(self.query_graphql, variables_graphql)
                data_user_info = data_graphql['data']
                user_info = data_user_info['userInfo']
                result_user_info = user_info['result']
                code_user_info = user_info['httpStatusCode']
                message_user_info = user_info['message']
                if result_user_info and code_user_info == 200:
                    dict_user_info_owner = ast.literal_eval(message_user_info)
                    client_email_owner = dict_user_info_owner['client']['email']
                    whmcs_last_login_owner = dict_user_info_owner['lastLogin']['ip']
                    self.result_dict.update({"whmcs_last_login_owner": whmcs_last_login_owner})
                    with open(self.report_user_info_owner, "w") as open_report_user_info_owner:
                        json.dump(dict_user_info_owner, open_report_user_info_owner)
                else:
                    self._log.info("GraphQL owner return failed - {}".format(self.values_ticket))
                    raise GeneralError
            elif self.module_configuration.application == "model":
                if os.path.exists(self.report_user_info_owner):
                    with open(self.report_user_info_owner, "r") as open_report_user_info_owner:
                        dict_user_info_owner = json.load(open_report_user_info_owner)
                        whmcs_last_login_owner = dict_user_info_owner['lastLogin']['ip']
                        client_email_owner = dict_user_info_owner['client']['email']
                        self.result_dict.update({"whmcs_last_login_owner": whmcs_last_login_owner})
                else:
                    self._log.info("GraphQL owner return failed - {}".format(self.values_ticket))
                    raise GeneralError

        except GeneralError:
            if "data_graphql" in locals():
                self._log.info("GraphQL User Info Result - {}".format(data_graphql.get("errors")))
            raise GraphQLFailed

        except KeyError as er:
            if "data_graphql" in locals():
                self._log.info("GraphQL User Info Result - {}".format(data_graphql.get("errors")))
            # log info
            self._log.info("Get User Info Owner KeyError - {}".format(er))
            raise GraphQLFailed

        except Exception as er:
            if "data_graphql" in locals():
                self._log.info("GraphQL User Info Result - {}".format(data_graphql.get("errors")))
            # generate a error log
            self._log.error("get_user_info_owner - {} - {}".format(self.__class__.__name__, er))
            raise GraphQLFailed

    def abuse_upload(self):
        try:
            self.module_database.update_analyzing("upload_report", 1, self.thread_id)
            vars_ansible = {
                "report_dir": self.report_case_path,
                "ansible_port": self.module_configuration.abuse_port,
            }
            # instance ansible module to abuse server
            module_ansible = ModuleAnsible(module_log=self._log, module_configuration=self.module_configuration, abuse_server=True)
            # debug log
            self._log.debug(vars_ansible)
            # execute playbook that copy reports to abuse server
            summary_ansible = module_ansible.execute(self.playbook_abuse, vars_ansible, self.module_configuration.abuse_server)
            if summary_ansible is False:
                # error log
                self._log.error("Abuse upload error")
                self.module_database.update_analyzing("upload_report", 2, self.thread_id)
                return True
            else:
                # debug log
                self._log.debug("Abuse upload completed")
                self.module_database.update_analyzing("upload_report", 3, self.thread_id)
                return True

        except Exception as er:
            # generate a error log
            self._log.error("abuse_upload {} - {}".format(self.__class__.__name__, er))
            return False

    def count_malwares(self, file_malwares):
        """
        Responsible for count scan result
        """
        try:
            with closing(open(file_malwares)) as open_malwares:
                return len(open_malwares.readlines())

        except Exception as er:
            # generate a error log
            self._log.error("count_malwares {} - {}".format(self.__class__.__name__, er))
            return False

    def check_scan_result(self):
        """
        Responsible for check scan result, check if file report exists and size
        """
        try:
            if self.type_scan == "scan_phishing":
                if os.path.exists(self.report_scan_phishing):
                    self.scan = self.count_malwares(self.report_scan_phishing)
            elif self.type_scan == "scan_malware":
                if os.path.exists(self.report_scan_malware):
                    self.scan = self.count_malwares(self.report_scan_malware)
            elif self.type_scan == "scan_all":
                if os.path.exists(self.report_scan_malware) and os.path.exists(self.report_scan_phishing):
                    self.scan = self.count_malwares(self.report_scan_phishing) + self.count_malwares(self.report_scan_malware)
            else:
                return False

        except Exception as er:
            # generate a error log
            self._log.error("check_scan_result {} - {}".format(self.__class__.__name__, er))
            return False

    def scan_path_url(self):
        """
        Define the variables to execute scan in directory where file of the URL is.
        """
        try:
            if self.module_regex.check_home(self.result_dict['home']) and self.module_regex.check_home(
                    self.result_dict['doc_root']):
                # split path_url and get all less last index, this is filename
                list_file_path_url = self.file_url.split("/")[:-1]
                # check first index is empty and delete index
                if list_file_path_url[0] == "":
                    del list_file_path_url[0]
                # create variable with full path for directory
                file_path_url = os.path.join(self.result_dict['doc_root'], "/".join(list_file_path_url))
                # set ansible vars
                vars_ansible = {
                    "local_report_dir": self.report_case_path,
                    "domain": self.main_domain,
                    "server": self.server,
                    "ticket_id": self.ticket_id,
                    "thread_id": self.thread_id,
                    "path_scan": file_path_url,
                    "home": self.result_dict['home'],
                    self.type_scan: True,
                }
                # debug log
                self._log.debug(vars_ansible)
                # set start ansible_scan in database
                self.module_database.update_analyzing("ansible_scan", 1, self.thread_id)
                # execute playbook of scan and check result
                summary_ansible = self.module_ansible.execute(self.playbook_scan, vars_ansible, self.server)
                if summary_ansible is False or summary_ansible is None or \
                        summary_ansible['rescued'] > 0 or os.path.exists(os.path.join(self.report_case_path, "scan_error.flag")):
                    # set failed ansible_scan in database
                    self.module_database.update_analyzing("ansible_scan", 2, self.thread_id)
                else:
                    # set completed ansible_scan in database
                    self.module_database.update_analyzing("ansible_scan", 3, self.thread_id)
            else:
                self._log.info("Path home or doc_root not compatible - {} - {}".format(self.result_dict['home'], self.result_dict['doc_root']))
                raise ResultFailed

        except ResultFailed:
            raise AnsibleScanFailed

        except DatabaseUpdateFailed:
            raise AnsibleScanFailed

        except Exception as er:
            # generate a error log
            self._log.error("scan_path_url {} - {}".format(self.__class__.__name__, er))
            raise AnsibleScanFailed

    def scan_doc_root(self):
        """
        Define the variables to execute scan in docroot directory of the domain.
        """
        try:
            if self.module_regex.check_home(self.result_dict['home']) and self.module_regex.check_home(self.result_dict['doc_root']):
                # set ansible variables to scan in docroot directory
                vars_ansible = {
                    "local_report_dir": self.report_case_path,
                    "domain": self.main_domain,
                    "server": self.server,
                    "ticket_id": self.ticket_id,
                    "thread_id": self.thread_id,
                    "path_scan": self.result_dict['doc_root'],
                    "home": self.result_dict['home'],
                    self.type_scan: True,
                }
                # debug log
                self._log.debug(vars_ansible)
                # set start ansible_scan in database
                self.module_database.update_analyzing("ansible_scan", 1, self.thread_id)
                # execute playbook of scan and check result
                summary_ansible = self.module_ansible.execute(self.playbook_scan, vars_ansible, self.server)
                if summary_ansible is False or summary_ansible is None or \
                        summary_ansible['rescued'] > 0 or os.path.exists(os.path.join(self.report_case_path, "scan_error.flag")):
                    # set failed ansible_scan in database
                    self.module_database.update_analyzing("ansible_scan", 2, self.thread_id)
                else:
                    # set completed ansible_scan in database
                    self.module_database.update_analyzing("ansible_scan", 3, self.thread_id)
            else:
                self._log.info("Path home or doc_root not compatible - {} - {}".format(self.result_dict['home'], self.result_dict['doc_root']))
                raise ResultFailed

        except ResultFailed:
            raise AnsibleScanFailed

        except DatabaseUpdateFailed:
            raise AnsibleScanFailed

        except Exception as er:
            # generate a error log
            self._log.error("scan_doc_root {} - {}".format(self.__class__.__name__, er))
            raise AnsibleScanFailed

    def scan_home(self):
        """
        Define the variables to execute scan in home directory.
        """
        try:
            if self.module_regex.check_home(self.result_dict['home']):
                # set ansible variables
                vars_ansible = {
                    "local_report_dir": self.report_case_path,
                    "domain": self.main_domain,
                    "server": self.server,
                    "ticket_id": self.ticket_id,
                    "thread_id": self.thread_id,
                    "path_scan": self.result_dict['home'],
                    "home": self.result_dict['home'],
                    self.type_scan: True,
                }
                # debug log
                self._log.debug(vars_ansible)
                # set start ansible_scan in database
                self.module_database.update_analyzing("ansible_scan", 1, self.thread_id)
                # execute playbook of scan and check result
                summary_ansible = self.module_ansible.execute(self.playbook_scan, vars_ansible, self.server)
                if summary_ansible is False or summary_ansible is None or \
                        summary_ansible['rescued'] > 0 or os.path.exists(os.path.join(self.report_case_path, "scan_error.flag")):
                    # set failed ansible_scan in database
                    self.module_database.update_analyzing("ansible_scan", 2, self.thread_id)
                else:
                    # set completed ansible_scan in database
                    self.module_database.update_analyzing("ansible_scan", 3, self.thread_id)
            else:
                self._log.info("Path home or doc_root not compatible - {} - {}".format(self.result_dict['home'], self.result_dict['doc_root']))
                raise ResultFailed

        except ResultFailed:
            raise AnsibleScanFailed

        except DatabaseUpdateFailed:
            raise AnsibleScanFailed

        except Exception as er:
            # generate a error log
            self._log.error("scan_home {} - {}".format(self.__class__.__name__, er))
            raise AnsibleScanFailed

    def set_report(self):
        """
        Responsible for check result vdetect and hf commands
        """
        try:
            if os.path.exists(self.file_report):
                with closing(open(self.file_report)) as open_report:
                    report_content = open_report.read().splitlines()
                # create empty list
                report_cms = list()
                report_hf = False
                # walking reportContent
                for temp_report in report_content:
                    # check if the line contains cmsFalse
                    if "cmsFalse" in temp_report:
                        # set not found CMS
                        report_cms = False
                    # check if the line contains cmsTrue and report is not false
                    elif "cmsTrue" in temp_report and report_cms is not False:
                        # append result line of the CMS in list
                        report_cms.append(temp_report)
                    # check if the line contains hf=
                    elif "hf=" in temp_report:
                        # split hf result and convert to dict
                        report_hf = ast.literal_eval(temp_report.split("hf=")[1])
                # add in dict
                self.result_dict.update({"cms": report_cms})
                self.result_dict.update({"hf": report_hf})
            else:
                self._log.info("Report file not found - {} - {}".format(self.ticket_id, self.main_domain))
                raise FileResultFailed

        except Exception as er:
            # generate a error log
            self._log.error("set_report - {} - {}".format(self.__class__.__name__, er))
            raise ResultFailed

    def set_hostname(self):
        """
        Responsible for check result hostname command
        """
        try:
            if os.path.exists(self.file_hostname):
                # open file and store in variable
                with closing(open(self.file_hostname)) as open_hostname:
                    report_hostname = open_hostname.read()
                # create key in dict with hostname of the server
                self.result_dict.update({"main_server": report_hostname})
                self.result_dict.update({"server_type": self.module_regex.check_server(report_hostname)})
            else:
                self._log.info("Hostname file not found - {} - {} - {}".format(self.ticket_id, self.main_domain, self.file_hostname))
                raise FileResultFailed

        except Exception as er:
            # generate a error log
            self._log.error("set_hostname - {} - {}".format(self.__class__.__name__, er))
            raise ResultFailed

    def set_domain_user_data(self):
        """
        Responsible for check result whmapi1 domainuserdata command
        """
        try:
            if os.path.exists(self.file_domain_user_data):
                # load json file
                with closing(open(self.file_domain_user_data)) as open_domain_user_data:
                    domain_user_data = json.load(open_domain_user_data)
                # store values in separate variables and add in dict
                if int(domain_user_data['metadata']['result']) == 1:
                    user = domain_user_data['data']['userdata']['user']
                    doc_root = domain_user_data['data']['userdata']['documentroot']
                    ip = domain_user_data['data']['userdata']['ip']
                    home = domain_user_data['data']['userdata']['homedir']
                    server_name = domain_user_data['data']['userdata']['servername']
                    server_alias = domain_user_data['data']['userdata']['serveralias']
                    self.result_dict.update({"user": user})
                    self.result_dict.update({"doc_root": doc_root})
                    self.result_dict.update({"ip": ip})
                    self.result_dict.update({"home": home})
                    self.result_dict.update({"servername": server_name})
                    self.result_dict.update({"serveralias": server_alias})
                else:
                    # info log
                    self._log.info("Domain User Data fail - {} - {}".format(self.ticket_id, self.main_domain))
                    raise ResultFailed
            else:
                self._log.info("Domain User Data file not found - {} - {} - {}".format(self.ticket_id, self.main_domain, self.file_domain_user_data))
                raise FileResultFailed

        except KeyError as er:
            # info log
            self._log.info("Domain User Data KeyError - {} - {} - {}".format(self.ticket_id, self.main_domain, er))
            raise ResultFailed

        except Exception as er:
            # generate a error log
            self._log.error("Domain User Data {} - {}".format(self.__class__.__name__, er))
            raise ResultFailed

    def set_account_summary(self):
        """
        Responsible for check result whmapi1 accountsummary command
        """
        try:
            if os.path.exists(self.file_account_summary):
                # open file and load json in variable
                with closing(open(self.file_account_summary)) as open_account_summary:
                    account_summary = json.load(open_account_summary)
                # check if result of the command is success and store in separate variables
                if int(account_summary['metadata']['result']) == 1 and account_summary['metadata']['reason'] == "OK":
                    # example 38M - diskused
                    disk_used = account_summary['data']['acct'][0]['diskused']
                    jail_shell = account_summary['data']['acct'][0]['shell']
                    is_locked = account_summary['data']['acct'][0]['is_locked']
                    start_account = account_summary['data']['acct'][0]['unix_startdate']
                    suspended = account_summary['data']['acct'][0]['suspended']
                    uid = account_summary['data']['acct'][0]['uid']
                    inodes_used = account_summary['data']['acct'][0]['inodesused']
                    plan = account_summary['data']['acct'][0]['plan']
                    email = account_summary['data']['acct'][0]['email']
                    domain = account_summary['data']['acct'][0]['domain']
                    owner = account_summary['data']['acct'][0]['owner']
                    self.result_dict.update({"disk_used": disk_used})
                    self.result_dict.update({"jail_shell": jail_shell})
                    self.result_dict.update({"is_locked": is_locked})
                    self.result_dict.update({"start_account": start_account})
                    self.result_dict.update({"suspended": suspended})
                    self.result_dict.update({"plan": plan})
                    self.result_dict.update({"uid": uid})
                    self.result_dict.update({"inodes_used": inodes_used})
                    self.result_dict.update({"domain": domain})
                    self.result_dict.update({"owner": owner})
                else:
                    # info log
                    self._log.info("Account Summary fail - {} - {}".format(self.ticket_id, self.main_domain))
                    raise ResultFailed
            else:
                self._log.info("Account Summary file not found - {} - {} - {}".format(self.ticket_id, self.main_domain, self.file_account_summary))
                raise FileResultFailed

        except KeyError as er:
            # info log
            self._log.info("Account Summary KeyError - {} - {} - {}".format(self.ticket_id, self.main_domain, er))
            raise ResultFailed

        except Exception as er:
            # generate a error log
            self._log.error("set_account_summary -  {} - {}".format(self.__class__.__name__, er))
            raise ResultFailed

    def set_account_summary_owner(self):
        """
        Responsible for check result whmapi1 accountsummary command
        """
        try:
            # check if file exists
            if os.path.exists(self.file_account_summary_owner):
                # open file and load json in variable
                with closing(open(self.file_account_summary_owner)) as open_account_summary_owner:
                    account_summary_owner = json.load(open_account_summary_owner)
                # check if result of the command is success and store in separate variables
                if int(account_summary_owner['metadata']['result']) == 1 and account_summary_owner['metadata']['reason'] == "OK":
                    disk_used_owner = account_summary_owner['data']['acct'][0]['diskused']
                    jail_shell_owner = account_summary_owner['data']['acct'][0]['shell']
                    is_locked_owner = account_summary_owner['data']['acct'][0]['is_locked']
                    start_account_owner = account_summary_owner['data']['acct'][0]['unix_startdate']
                    suspended_owner = account_summary_owner['data']['acct'][0]['suspended']
                    uid_owner = account_summary_owner['data']['acct'][0]['uid']
                    inodes_used_owner = account_summary_owner['data']['acct'][0]['inodesused']
                    plan_owner = account_summary_owner['data']['acct'][0]['plan']
                    email_owner = account_summary_owner['data']['acct'][0]['email']
                    domain_owner = account_summary_owner['data']['acct'][0]['domain']
                    self.result_dict.update({"disk_used_owner": disk_used_owner})
                    self.result_dict.update({"jail_shell_owner": jail_shell_owner})
                    self.result_dict.update({"is_locked_owner": is_locked_owner})
                    self.result_dict.update({"start_account_owner": start_account_owner})
                    self.result_dict.update({"suspended_owner": suspended_owner})
                    self.result_dict.update({"uid_owner": uid_owner})
                    self.result_dict.update({"inodes_used_owner": inodes_used_owner})
                    self.result_dict.update({"plan_owner": plan_owner})
                    self.result_dict.update({"domain_owner": domain_owner})
                else:
                    # info log
                    self._log.info("Account Summary Owner fail - {} - {}".format(self.ticket_id, self.main_domain))
                    raise ResultFailed
            else:
                self._log.info("Account Summary Owner file not found - {} - {} - {}".format(self.ticket_id, self.main_domain, self.file_account_summary_owner))
                raise FileResultFailed

        except KeyError as er:
            # info log
            self._log.info("Account Summary Owner KeyError - {} - {} - {}".format(self.ticket_id, self.main_domain, er))
            raise ResultFailed

        except Exception as er:
            # generate a error log
            self._log.error("set_account_summary_owner - {} - {}".format(self.__class__.__name__, er))
            raise ResultFailed

    def set_email_account_disk(self):
        """
        Responsible for check result uapi --user=USER Email get_main_account_disk_usage command
        """
        try:
            # check if file exists
            if os.path.exists(self.file_email_account_disk):
                # open file and load json in variable
                with closing(open(self.file_email_account_disk)) as open_email_account_disk:
                    email_account_disk = json.load(open_email_account_disk)
                # check if result of the command is success
                if int(email_account_disk['result']['status']) == 1 and email_account_disk['result']['errors'] is None:
                    # example 38 de bytes
                    email_account_disk_used = email_account_disk['result']['data']
                    self.result_dict.update({"email_account_disk_used": email_account_disk_used})
                else:
                    # info log
                    self._log.info("Email Account Disk fail - {} - {}".format(self.ticket_id, self.main_domain))
                    raise ResultFailed
            else:
                self._log.info("Email Account file not found - {} - {} - {}".format(self.ticket_id, self.main_domain, self.file_email_account_disk))
                raise FileResultFailed

        except KeyError as er:
            # info log
            self._log.info("Email Account Disk KeyError - {} - {} - {}".format(self.ticket_id, self.main_domain, er))
            raise ResultFailed

        except Exception as er:
            # generate a error log
            self._log.error("set_email_account_disk - {} - {}".format(self.__class__.__name__, er))
            raise ResultFailed

    def set_last_login(self):
        """
        Responsible for check result uapi --user=USER last_login get_last_or_current_logged_in_ip command
        """
        try:
            # check if file exists
            if os.path.exists(self.file_last_login):
                # open file and load json in variable
                with closing(open(self.file_last_login)) as open_last_login:
                    last_login = json.load(open_last_login)
                # check if result of the command is success
                if int(last_login['result']['status']) == 1 and last_login['result']['errors'] is None:
                    ip_last_login = last_login['result']['data']
                    self.result_dict.update({"ip_last_login": ip_last_login})
                else:
                    # info log
                    self._log.info("Last Login fail - {} - {}".format(self.ticket_id, self.main_domain))
                    raise ResultFailed
            else:
                self._log.info("Last Login file not found - {} - {} - {}".format(self.ticket_id, self.main_domain, self.file_last_login))
                raise FileResultFailed

        except KeyError as er:
            # info log
            self._log.info("Last Login KeyError - {} - {} - {}".format(self.ticket_id, self.main_domain, er))
            raise ResultFailed

        except Exception as er:
            # generate a error log
            self._log.error("set_last_login - {} - {}".format(self.__class__.__name__, er))
            raise ResultFailed

    def set_pops_disk(self):
        """
        Responsible for check result uapi --user=USER Email list_pops_with_disk command
        """
        try:
            # check if file exists
            if os.path.exists(self.file_pops_disk):
                # open file and load json in variable
                with closing(open(self.file_pops_disk)) as open_pops_disk:
                    pops_disk = json.load(open_pops_disk)
                # check if result of the command is success
                if int(pops_disk['result']['status']) == 1 and pops_disk['result']['errors'] is None:
                    # check if data is than 0
                    if len(pops_disk['result']['data']) > 0:
                        list_pops_disk = list()
                        # walking list, add values in dict and add dict in list
                        for temp_pops_disk in pops_disk['result']['data']:
                            # not insert e-mail in result_dict, message traffic in plain text
                            # email=temp_pops_disk['email']
                            dict_pops_disk = dict(mtime=temp_pops_disk['mtime'],
                                           suspended_login=temp_pops_disk['suspended_login'],
                                           domain=temp_pops_disk['domain'],
                                           user=temp_pops_disk['user'],
                                           humandiskused=temp_pops_disk['humandiskused'])
                            list_pops_disk.append(dict_pops_disk)
                        self.result_dict.update({"list_pops_disk": list_pops_disk})
                    else:
                        # if data is empty, set none in list
                        list_pops_disk = None
                        self.result_dict.update({"list_pops_disk": list_pops_disk})
                else:
                    # info log
                    self._log.info("Pops Disk fail - {} - {}".format(self.ticket_id, self.main_domain))
                    raise ResultFailed
            else:
                self._log.info("Pops disk file not found - {} - {} - {}".format(self.ticket_id, self.main_domain, self.file_pops_disk))
                raise FileResultFailed

        except KeyError as er:
            self._log.info("Pops Disk KeyError - {} - {} - {}".format(self.ticket_id, self.main_domain, er))
            raise ResultFailed

        except Exception as er:
            # generate a error log
            self._log.error("set_pops_disk - {} - {}".format(self.__class__.__name__, er))
            raise ResultFailed

    def set_mysql_databases(self):
        """
        Responsible for check result whmapi1 list_mysql_databases_and_users command
        """
        try:
            # check if file exists
            if os.path.exists(self.file_mysql_databases):
                # open file and load json in variable
                with closing(open(self.file_mysql_databases)) as open_mysql_databases:
                    mysql_databases = json.load(open_mysql_databases)
                # check if result of the command is success
                if int(mysql_databases['metadata']['result']) == 1 and mysql_databases['metadata']['reason'] == "OK":
                    # check if data is than 0
                    if len(mysql_databases['data']['mysql_databases']) > 0:
                        list_mysql_databases = list()
                        # walking list, add values in list and add list in dict
                        for temp_mysql_databases in mysql_databases['data']['mysql_databases']:
                            list_mysql_databases.append(temp_mysql_databases)
                        self.result_dict.update({"list_mysql_databases": list_mysql_databases})
                    else:
                        # if data is empty, set none in list
                        list_mysql_databases = None
                        self.result_dict.update({"list_mysql_databases": list_mysql_databases})
                else:
                    # info log
                    self._log.info("MySQL Databases fail - {} - {}".format(self.ticket_id, self.main_domain))
                    raise ResultFailed
            else:
                self._log.info("MySQL Databases file not found - {} - {} - {}".format(self.ticket_id, self.main_domain, self.file_mysql_databases))
                raise FileResultFailed

        except KeyError as er:
            # info log
            self._log.info("MySQL Databases KeyError - {} - {} - {}".format(self.ticket_id, self.main_domain, er))
            raise ResultFailed

        except Exception as er:
            # generate a error log
            self._log.error("set_mysql_databases - {} - {}".format(self.__class__.__name__, er))
            raise ResultFailed

    def set_ftp_disk(self):
        """
        Responsible for check result uapi --user=USER Email list_pops_with_disk command
        """
        try:
            # check if file exists
            if os.path.exists(self.file_ftp_disk):
                # open file and load json in variable
                with closing(open(self.file_ftp_disk)) as open_ftp_disk:
                    ftp_disk = json.load(open_ftp_disk)
                # check if result of the command is success
                if int(ftp_disk['result']['status']) == 1 and ftp_disk['result']['errors'] is None:
                    # check if data is than 0
                    if len(ftp_disk['result']['data']) > 0:
                        list_ftp_disk = list()
                        # walking list, add values in dict and add dict in list
                        for temp_ftp_disk in ftp_disk['result']['data']:
                            # example 38,11 MB
                            dict_ftp_disk = dict(humandiskused=temp_ftp_disk['humandiskused'],
                                                      user=temp_ftp_disk['user'],
                                                      dir=temp_ftp_disk['dir'])
                            list_ftp_disk.append(dict_ftp_disk)
                        self.result_dict.update({"list_ftp_disk": list_ftp_disk})
                    else:
                        # if data is empty, set none in list
                        list_ftp_disk = None
                        self.result_dict.update({"list_ftp_disk": list_ftp_disk})
                else:
                    # log info
                    self._log.info("Ftp Disk fail - {} - {}".format(self.ticket_id, self.main_domain))
                    raise ResultFailed
            else:
                self._log.info("Ftp Disk file not found - {} - {} - {}".format(self.ticket_id, self.main_domain, self.file_ftp_disk))
                raise FileResultFailed

        except KeyError as er:
            # log info
            self._log.info("FTP Disk KeyError - {} - {} - {}".format(self.ticket_id, self.main_domain, er))
            raise ResultFailed

        except Exception as er:
            # generate a error log
            self._log.error("set_ftp_disk - {} - {}".format(self.__class__.__name__, er))
            raise ResultFailed

    def set_email_mxs(self):
        """
        Responsible for check result uapi --user=USER Email list_mxs command
        """
        try:
            # check if file exists
            if os.path.exists(self.file_email_mxs):
                # open file and load json in variable
                with closing(open(self.file_email_mxs)) as open_email_mxs:
                    email_mxs = json.load(open_email_mxs)
                # check if result of the command is success
                if int(email_mxs['result']['status']) == 1 and email_mxs['result']['errors'] is None:
                    # check if data is than 0
                    if len(email_mxs['result']['data']) > 0:
                        list_email_mxs = list()
                        # walking list, add values in dict and add dict in list
                        for temp_email_mxs in email_mxs['result']['data']:
                            dict_email_mxs = dict(mx=temp_email_mxs['mx'],
                                                  domain=temp_email_mxs['domain'])
                            list_email_mxs.append(dict_email_mxs)
                        self.result_dict.update({"list_email_mxs": list_email_mxs})
                    else:
                        # if data is empty, set none in list
                        list_email_mxs = None
                        self.result_dict.update({"list_email_mxs": list_email_mxs})
                else:
                    # log info
                    self._log.info("Email MXs fail - {} - {}".format(self.ticket_id, self.main_domain))
                    raise ResultFailed
            else:
                self._log.info("Email MXs file not found - {} - {} - {}".format(self.ticket_id, self.main_domain, self.file_email_mxs))
                raise FileResultFailed

        except KeyError as er:
            # log info
            self._log.info("Email MXs KeyError - {} - {} - {}".format(self.ticket_id, self.main_domain, er))
            raise ResultFailed

        except Exception as er:
            # generate a error log
            self._log.error("set_email_mxs - {} - {}".format(self.__class__.__name__, er))
            raise ResultFailed

    def set_domains_data(self):
        """
        Responsible for check result uapi --user=USER Email list_pops_with_disk command
        """
        try:
            # check if file exists
            if os.path.exists(self.file_domains_data):
                # open file and load json in variable
                with closing(open(self.file_domains_data)) as open_domains_data:
                    domains_data = json.load(open_domains_data)
                # check if result of the command is success
                if int(domains_data['result']['status']) == 1 and domains_data['result']['errors'] is None:
                    # check if addon domains than 0
                    if len(domains_data['result']['data']['addon_domains']) > 0:
                        list_addon_domains_data = list()
                        # walking list, add values in dict and add dict in list
                        for temp_addon_domains_data in domains_data['result']['data']['addon_domains']:
                            dict_addon_domains_data = dict(domain=temp_addon_domains_data['domain'],
                                                           serveralias=temp_addon_domains_data['serveralias'],
                                                           ip=temp_addon_domains_data['ip'],
                                                           type=temp_addon_domains_data['type'],
                                                           homedir=temp_addon_domains_data['homedir'],
                                                           documentroot=temp_addon_domains_data['documentroot'])
                            list_addon_domains_data.append(dict_addon_domains_data)
                        self.result_dict.update({"list_addon_domains_data": list_addon_domains_data})
                    else:
                        list_addon_domains_data = None
                        self.result_dict.update({"list_addon_domains_data": list_addon_domains_data})
                    # check if parked domains than 0
                    if len(domains_data['result']['data']['parked_domains']) > 0:
                        list_parked_domains_data = list()
                        # walking list, add values in dict and add dict in list
                        for temp_parked_domains_data in domains_data['result']['data']['parked_domains']:
                            dict_parked_domains_data = dict(domain=temp_parked_domains_data['domain'],
                                                            serveralias=temp_parked_domains_data['serveralias'],
                                                            ip=temp_parked_domains_data['ip'],
                                                            type=temp_parked_domains_data['type'],
                                                            homedir=temp_parked_domains_data['homedir'],
                                                            documentroot=temp_parked_domains_data['documentroot'])
                            list_parked_domains_data.append(dict_parked_domains_data)
                        self.result_dict.update({"list_parked_domains_data": list_parked_domains_data})
                    else:
                        list_parked_domains_data = None
                        self.result_dict.update({"list_parked_domains_data": list_parked_domains_data})
                    # check if sub domains than 0
                    if len(domains_data['result']['data']['sub_domains']) > 0:
                        list_sub_domains_data = list()
                        # walking list, add values in dict and add dict in list
                        for temp_sub_domains_data in domains_data['result']['data']['sub_domains']:
                            dict_sub_domains_data = dict(domain=temp_sub_domains_data['domain'],
                                                         serveralias=temp_sub_domains_data['serveralias'],
                                                         ip=temp_sub_domains_data['ip'],
                                                         type=temp_sub_domains_data['type'],
                                                         homedir=temp_sub_domains_data['homedir'],
                                                         documentroot=temp_sub_domains_data['documentroot'])
                            list_sub_domains_data.append(dict_sub_domains_data)
                        self.result_dict.update({"list_sub_domains_data": list_sub_domains_data})
                    else:
                        list_sub_domains_data = None
                        self.result_dict.update({"list_sub_domains_data": list_sub_domains_data})
                else:
                    # log info
                    self._log.info("Domains Data fail - {} - {}".format(self.ticket_id, self.main_domain))
                    raise ResultFailed
            else:
                self._log.info("Domains Data file not found - {} - {} - {}".format(self.ticket_id, self.main_domain, self.file_domains_data))
                raise FileResultFailed

        except KeyError as er:
            # log info
            self._log.info("Domains Data KeyError - {} - {} - {}".format(self.ticket_id, self.main_domain, er))
            raise ResultFailed

        except Exception as er:
            # generate a error log
            self._log.error("set_domains_data - {} - {}".format(self.__class__.__name__, er))
            raise ResultFailed

    def set_list_domains(self):
        """
        Responsible for check result uapi --user=USER Email list_pops_with_disk command
        """
        try:
            # check if file exists
            if os.path.exists(self.file_list_domains):
                # open file and load json in variable
                with closing(open(self.file_list_domains)) as open_list_domains:
                    list_domains = json.load(open_list_domains)
                # check if result of the command is success
                if int(list_domains['result']['status']) == 1 and list_domains['result']['errors'] is None:
                    # check if sub domains than 0
                    if len(list_domains['result']['data']['sub_domains']) > 0:
                        list_sub_domains = list_domains['result']['data']['sub_domains']
                        self.result_dict.update({"list_sub_domains": list_sub_domains})
                    else:
                        list_sub_domains = None
                        self.result_dict.update({"list_sub_domains": list_sub_domains})
                    # check if parked domains than 0
                    if len(list_domains['result']['data']['parked_domains']) > 0:
                        list_parked_domains = list_domains['result']['data']['parked_domains']
                        self.result_dict.update({"list_parked_domains": list_parked_domains})
                    else:
                        list_parked_domains = None
                        self.result_dict.update({"list_parked_domains": list_parked_domains})
                    # check if addon domains than 0
                    if len(list_domains['result']['data']['addon_domains']) > 0:
                        list_addon_domains = list_domains['result']['data']['addon_domains']
                        self.result_dict.update({"list_addon_domains": list_addon_domains})
                    else:
                        list_addon_domains = None
                        self.result_dict.update({"list_addon_domains": list_addon_domains})
                else:
                    self._log.info("List Domains fail - {} - {}".format(self.ticket_id, self.main_domain))
                    raise ResultFailed
            else:
                self._log.info("List Domains file not found - {} - {} - {}".format(self.ticket_id, self.main_domain, self.file_list_domains))
                raise FileResultFailed

        except KeyError as er:
            self._log.info("List Domains KeyError - {} - {} - {}".format(self.ticket_id, self.main_domain, er))
            raise ResultFailed

        except Exception as er:
            # generate a error log
            self._log.error("set_list_domains - {} - {}".format(self.__class__.__name__, er))
            raise ResultFailed

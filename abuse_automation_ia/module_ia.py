# -*- coding: utf-8 -*-
"""


- Contributors
Elliann Marks <elian.markes@gmail.com>

**- Version 02 - 07/08/2019**

**- Version 03 - 18/12/2019**

- IA
'ip_last_login'           => int # -1 - not found, 1 - Brazil, 2 - Others countries
'disk_used'              => int # Megabytes
'start_account'          => int # Account days
'suspended'             => int # 0 - False, 1 - True
'inodes_used'            => int # number of inodes
'email_account_disk_used'  => int # Megabytes
'list_pops_disk'          => len(list_pops_disk) # number of e-mail accounts
'list_mysql_databases'    => len(list_mysql_databases)  # number of databases
'list_ftp_disk'           => len(list_ftp_disk) # number of ftp accounts
'list_addon_domains'      => len(list_addon_domains) # number of addons domains
'list_parked_domains'     => len(list_parked_domains) # number of parked domains
'list_subdomains'        => len(list_subdomains) # number of subdomains
'cms'                   => int # number of CMS found
'scan'                  => int # number of malicious files found
'virus_total'           => int # number of positives found
'wordlist'              => int # 0 - not found, 1 - found
'cpanel_fml_command'      => int # -1 - not found, 1 - found
'cpanel_fml_date'         => int # -1 - not found, number of days between start_account and hf log
'cpanel_country_ip'       => int # -1 - not found, 1 - Brazil, 2 - Others countries
'cpanel_compare_ips'      => int # -1 - not found, 1 - IP last login and hf log is equal, 2 - IP last login and hf log not equal
'cpanel_date'            => int # -1 - not found, number of days between start_account and hf log
'apache_country_ip'       => int # -1 - not found, 1 - Brazil, 2 - Others countries
'apache_compare_ips'      => int # -1 - not found, 1 - IP last login and hf log is equal, 2 - IP last login and hf log not equal
'apache_wp'              => int # -1 - not found, 0 - nothing WP, 1 - found WP
'apache_date'            => int # -1 - not found, number of days between start_account and hf log
'ftp_country_ip'          => int # -1 - not found, 1 - Brazil, 2 - Others countries
'ftp_compare_IPs'         => int # -1 - not found, 1 - IP last login and hf log is equal, 2 - IP last login and hf log not equal
'ftp_date'               => int # -1 - not found, number of days between start_account and hf log

- New values IA
'server_type'           => int # -1 - not found, 2 - shared, 3 - reseller, 4 - wp, 5 - dedi, 6 - vps
'score_domain'          => int # -1 - not found, score value in get phishing API
'whmcs_last_login'      => int # -1 - not found, 1 - Brazil, 2 - Others countries
'whmcs_compare_ips'     => int # -1 - not found, 1 - IP last login and WHMCS last login is equal, 2 - IP last login and WHMCS last login not equal

"""

# libraries
import os
import ast
import re
import time
import ipinfo
import requests
import pandas
import numpy
from bitmath import kB, MB, GB
from contextlib import closing
from datetime import datetime
from abuse_automation.module_ansible import ModuleAnsible
from abuse_automation.module_database import ModuleDatabase
from abuse_automation.module_regex import ModuleRegex
from abuse_automation.module_exceptions import NormalizeFailed, IAFailed, GeneralError, \
    DatabaseSelectFailed


class ModuleIA:

    def __init__(self, module_log, module_configuration, values_ticket):
        try:
            self.module_configuration = module_configuration
            self._log = module_log
            self.values_ticket = values_ticket
            # instance modules
            self.module_database = ModuleDatabase(self._log, self.module_configuration)
            self.module_ansible = ModuleAnsible(self._log, self.module_configuration)
            self.module_regex = ModuleRegex(self._log, self.module_configuration)
            self.report_action_dir = self.module_configuration.report_action_dir
            self.report_backups = self.module_configuration.report_backups
            self.token_ip_info = "8dcb21e3602689"
            self.playbook_block = self.module_configuration.playbook_block
            self.playbook_backup = self.module_configuration.playbook_backup
            # regex for normalize data
            self.regex_mb = "m|mb|mib"
            self.regex_kb = "k|kb|kib"
            self.regex_gb = "g|gb|gib"
            self.regex_bytes = "b"
            self.regex_number = "[0-9]+"
            # set none value in variables IA
            self.ip_last_login_ia = None
            self.disk_used_ia = None
            self.start_account_ia = None
            self.suspended_ia = None
            self.inodes_used_ia = None
            self.email_account_disk_used_ia = None
            self.len_pops_disk_ia = None
            self.len_mysql_databases_ia = None
            self.len_ftp_disk_ia = None
            self.len_addon_domains_ia = None
            self.len_parked_domains_ia = None
            self.len_subdomains_ia = None
            self.len_cms_ia = None
            self.scan_ia = None
            self.virustotal_ia = None
            self.intentional_words_ia = None
            self.cpanel_fml_command_ia = None
            self.cpanel_fml_date_ia = None
            self.cpanel_country_ip_ia = None
            self.cpanel_compare_ips_ia = None
            self.cpanel_date_ia = None
            self.apache_country_ip_ia = None
            self.apache_compare_ips_ia = None
            self.apache_wp_ia = None
            self.apache_date_ia = None
            self.ftp_country_ip_ia = None
            self.ftp_compare_ips_ia = None
            self.ftp_date_ia = None
            self.score_domain_ia = None
            self.server_type_ia = None
            self.whmcs_compare_ips_ia = None
            self.whmcs_last_login_ia = None
            self.value_disk = None
            self.temp_apache_country_ip_ia = None
            self.temp_apache_compare_ips_ia = None
            self.temp_apache_date_ia = None
            self.temp_apache_wp_ia = None
            self.temp_ftp_country_ip_ia = None
            self.temp_ftp_compare_ips_ia = None
            self.temp_ftp_date_ia = None
            self.temp_cpanel_country_ip_ia = None
            self.temp_cpanel_compare_ips_ia = None
            self.temp_cpanel_date_ia = None
            self.result_type = None
            # get variables message
            self.general_error = self.values_ticket['general_error']
            if self.general_error is False:
                self.ansible_check = self.values_ticket['ansible_check']
                self.brand = self.values_ticket['brand']
                self.user = self.values_ticket['user']
                self.doc_root = self.values_ticket['doc_root']
                self.server = self.values_ticket['server']
                self.thread_id = self.values_ticket['thread_id']
                self.home = self.values_ticket['home']
                self.scan = self.values_ticket['scan']
                self.path_url = self.values_ticket['path_url']
                self.domain = self.values_ticket['domain']
                self.main_domain = self.values_ticket['main_domain']
                self.main_check = self.values_ticket['main_check']
                self.main_server = self.values_ticket['main_server']
                self.ticket_id = self.values_ticket['ticket_id']
                self.owner = self.values_ticket['owner']
                self.intentional_words = self.values_ticket['intentional_words']
                self.whmcs_last_login = self.values_ticket['whmcs_last_login']
                self.whmcs_last_login_owner = self.values_ticket.get('whmcs_last_login_owner')
                self.server_type = self.values_ticket['server_type']
                self.disk_used = self.values_ticket['disk_used']
                self.ip_last_login = self.values_ticket['ip_last_login']
                self.start_account = self.values_ticket['start_account']
                self.suspended = self.values_ticket['suspended']
                self.inodes_used = self.values_ticket['inodes_used']
                self.email_account_disk_used = self.values_ticket['email_account_disk_used']
                self.list_pops_disk = self.values_ticket['list_pops_disk']
                self.list_mysql_databases = self.values_ticket['list_mysql_databases']
                self.list_ftp_disk = self.values_ticket['list_ftp_disk']
                self.list_addon_domains = self.values_ticket['list_addon_domains']
                self.list_parked_domains = self.values_ticket['list_parked_domains']
                self.list_subdomains = self.values_ticket['list_sub_domains']
                self.cms = self.values_ticket['cms']
                self.hf = self.values_ticket['hf']
            else:
                self._log.info("General error is true - {}".format(self.values_ticket))
                raise GeneralError
            # initialize dict
            self.result_dict = dict(result_action=False,
                                    general_error=self.general_error,
                                    ticket_id=self.ticket_id,
                                    thread_id=self.thread_id,
                                    doc_root=self.doc_root,
                                    server=self.server,
                                    domain=self.domain,
                                    path_url=self.path_url,
                                    main_domain=self.main_domain,
                                    main_check=self.main_check,
                                    main_server=self.main_server,
                                    brand=self.brand,
                                    owner=self.owner,
                                    result_type=0,
                                    ansible_action=0,
                                    generate_backup=False,
                                    suspend_account=False,
                                    )
            # directory of report
            self.check_backup = os.path.join(self.report_backups, self.thread_id + "_backup.flag")
            self.check_suspend = os.path.join(self.report_backups, self.thread_id + "_suspend.flag")
            self.report_action = os.path.join(self.report_action_dir, self.thread_id)
            # initialize handler ipinfo
            self.handler_ip_info = ipinfo.getHandler(self.token_ip_info)
            # variables for hf
            self.hf_mtime = None
            self.hf_cpanel_fml_mtime = None
            self.hf_cpanel_mtime = None
            self.hf_ftpxfer_mtime = None
            self.hf_apache_access_mtime = None
            self.hf_ftp_messages_mtime = None
            self.hf_apache_dom_mtime = None
            self.hf_bash_history_mtime = None
            self.hf_ctime = None
            self.hf_cpanel_fml_ctime = None
            self.hf_ftpxfer_ctime = None
            self.hf_apache_access_ctime = None
            self.hf_ftp_messages_ctime = None
            self.hf_apache_dom_ctime = None
            self.hf_bash_history_ctime = None
            self.hf_cpanel_ctime = None
            # handle values hf
            self.handle_hf()
            # check last login ips
            if self.module_regex.check_excludes_ip(self.ip_last_login):
                self.ip_last_login_ia = -1
            else:
                self.ip_last_login_ia = self.get_country(self.ip_last_login)
            # check whmcs last login
            if self.module_regex.check_excludes_ip(self.whmcs_last_login):
                self.whmcs_last_login_ia = -1
            else:
                self.whmcs_last_login_ia = self.get_country(self.whmcs_last_login)
            # check ip last login cpanel and whmcs
            if self.module_regex.check_excludes_ip(self.whmcs_last_login) or \
                    self.module_regex.check_excludes_ip(self.ip_last_login):
                self.whmcs_compare_ips_ia = -1
            elif self.whmcs_last_login == self.ip_last_login:
                self.whmcs_compare_ips_ia = 1
            else:
                self.whmcs_compare_ips_ia = 2
            # check disk used
            if self.disk_used is not None and self.disk_used is not False:
                self.disk_used_ia = self.handle_disk(self.disk_used)
            else:
                self.disk_used_ia = -1
            # check server type and set value
            if self.server_type == "shared":
                self.server_type_ia = 2
            elif self.server_type == "reseller":
                self.server_type_ia = 3
            elif self.server_type == "wp":
                self.server_type_ia = 4
            elif self.server_type == "dedi":
                self.server_type_ia = 5
            elif self.server_type == "vps":
                self.server_type_ia = 6
            else:
                self.server_type_ia = -1
            # get value with time of the account
            if self.module_configuration.application == "model":
                try:
                    self.get_start_handle = self.module_database.get_start_handle(self.thread_id)
                    if self.get_start_handle is not False and self.get_start_handle is not None:
                        self.start_account_ia = self.get_days_account(value_start=self.start_account, value_end=datetime.timestamp(self.get_start_handle))
                    else:
                        self._log.error("Failed in get_start_handle - {}".format(self.thread_id))
                        exit(1)

                except DatabaseSelectFailed:
                    exit(1)
            else:
                self.start_account_ia = self.get_days_account(value_end=self.start_account)
            # set suspended value
            self.suspended_ia = self.suspended
            # set inodes used value
            self.inodes_used_ia = self.inodes_used
            # check and handles values
            if self.email_account_disk_used is not None and self.email_account_disk_used is not False:
                self.email_account_disk_used_ia = self.handle_disk(self.email_account_disk_used)
            else:
                self.email_account_disk_used_ia = -1
            # check len pops disk
            if self.list_pops_disk is not None and self.list_pops_disk is not False:
                self.len_pops_disk_ia = len(self.list_pops_disk)
            else:
                self.len_pops_disk_ia = -1
            # check len databases
            if self.list_mysql_databases is not None and self.list_mysql_databases is not False:
                self.len_mysql_databases_ia = len(self.list_mysql_databases)
            else:
                self.len_mysql_databases_ia = -1
            # check len ftp disk
            if self.list_ftp_disk is not None and self.list_ftp_disk is not False:
                self.len_ftp_disk_ia = len(self.list_ftp_disk)
            else:
                self.len_ftp_disk_ia = -1
            # check len addon domains
            if self.list_addon_domains is not None and self.list_addon_domains is not False:
                self.len_addon_domains_ia = len(self.list_addon_domains)
            else:
                self.len_addon_domains_ia = -1
            # check len parked domains
            if self.list_parked_domains is not None and self.list_parked_domains is not False:
                self.len_parked_domains_ia = len(self.list_parked_domains)
            else:
                self.len_parked_domains_ia = -1
            # check len subdomains
            if self.list_subdomains is not None and self.list_subdomains is not False:
                self.len_subdomains_ia = len(self.list_subdomains)
            else:
                self.len_subdomains_ia = -1
            # check len cms
            if self.cms is not None and self.cms is not False:
                self.len_cms_ia = len(self.cms)
            else:
                self.len_cms_ia = -1
            # set
            if self.scan is not None and self.scan is not False:
                self.scan_ia = self.scan
            else:
                self.scan_ia = -1
            # get virustotal result in database
            self.virustotal_ia = self.module_database.result_vt(self.thread_id)
            self.intentional_words_ia = self.intentional_words
            # execute handles cpanel cml
            self.handle_cpanel_fml()
            # execute handle cpanel
            self.handle_cpanel()
            # execute handle apache
            self.handle_apache()
            # execute handle ftp
            self.handle_ftp()
            # set score domain
            self.score_domain_ia = -1 # self.get_score_domain(self.domain)
            # create list
            self.list_ia = list()
            # create dict
            self.dict_ia = dict()
            # check results
            if self.ip_last_login_ia is not None and self.disk_used_ia is not None and self.start_account_ia is not None and \
                    self.suspended_ia is not None and self.inodes_used_ia is not None and self.email_account_disk_used_ia is not None and \
                    self.len_pops_disk_ia is not None and self.len_mysql_databases_ia is not None and self.len_ftp_disk_ia is not None and \
                    self.len_addon_domains_ia is not None and self.len_parked_domains_ia is not None and self.len_subdomains_ia is not None and \
                    self.len_cms_ia is not None and self.scan_ia is not None and self.virustotal_ia is not None and self.intentional_words_ia is not None and \
                    self.cpanel_fml_command_ia is not None and self.cpanel_fml_date_ia is not None and self.cpanel_country_ip_ia is not None and \
                    self.cpanel_compare_ips_ia is not None and self.cpanel_date_ia is not None and self.apache_country_ip_ia is not None and \
                    self.apache_compare_ips_ia is not None and self.apache_wp_ia is not None and self.apache_date_ia is not None and \
                    self.ftp_country_ip_ia is not None and self.ftp_compare_ips_ia is not None and self.ftp_date_ia is not None and \
                    self.whmcs_last_login_ia is not None and self.whmcs_compare_ips_ia is not None and self.server_type_ia is not None and \
                    self.score_domain_ia is not None:
                self.set_list_ia()
                self.set_dict_ia()
                time.sleep(1)
                # check result_type if environment is model
                if self.module_configuration.application == "model":
                    try:
                        self.get_result_type = self.module_database.get_result_type(self.thread_id)
                        if self.get_result_type is not False and self.get_result_type is not None:
                            self.list_ia.append(self.get_result_type)
                            self.dict_ia.update({"result_type": self.get_result_type})
                        else:
                            self._log.error("Failed in get_result_type - {}".format(self.thread_id))
                            exit(1)

                    except DatabaseSelectFailed:
                        exit(1)
                self._log.info(self.dict_ia)
            else:
                self._log.info("Normalize failed - {} - {}".format(self.thread_id, self.ticket_id))
                raise NormalizeFailed

        except DatabaseSelectFailed:
            raise IAFailed

        except GeneralError:
            raise IAFailed

        except NormalizeFailed:
            raise IAFailed

        except KeyError as er:
            # generate a error log
            self._log.error("IA key error - {} - {}".format(self.__class__.__name__, er))
            raise IAFailed

        except Exception as er:
            # generate a error log
            self._log.error("IA init - {} - {}".format(self.__class__.__name__, er))
            raise IAFailed

    def set_list_ia(self):
        try:
            self.list_ia.append(self.ip_last_login_ia)
            self.list_ia.append(self.disk_used_ia)
            self.list_ia.append(self.start_account_ia)
            self.list_ia.append(self.suspended_ia)
            self.list_ia.append(self.inodes_used_ia)
            self.list_ia.append(self.email_account_disk_used_ia)
            self.list_ia.append(self.len_pops_disk_ia)
            self.list_ia.append(self.len_mysql_databases_ia)
            self.list_ia.append(self.len_ftp_disk_ia)
            self.list_ia.append(self.len_addon_domains_ia)
            self.list_ia.append(self.len_parked_domains_ia)
            self.list_ia.append(self.len_subdomains_ia)
            self.list_ia.append(self.len_cms_ia)
            self.list_ia.append(self.scan_ia)
            self.list_ia.append(self.virustotal_ia)
            self.list_ia.append(self.intentional_words_ia)
            self.list_ia.append(self.cpanel_fml_command_ia)
            self.list_ia.append(self.cpanel_fml_date_ia)
            self.list_ia.append(self.cpanel_country_ip_ia)
            self.list_ia.append(self.cpanel_compare_ips_ia)
            self.list_ia.append(self.cpanel_date_ia)
            self.list_ia.append(self.apache_country_ip_ia)
            self.list_ia.append(self.apache_compare_ips_ia)
            self.list_ia.append(self.apache_wp_ia)
            self.list_ia.append(self.apache_date_ia)
            self.list_ia.append(self.ftp_country_ip_ia)
            self.list_ia.append(self.ftp_compare_ips_ia)
            self.list_ia.append(self.ftp_date_ia)
            self.list_ia.append(self.server_type_ia)
            self.list_ia.append(self.score_domain_ia)
            self.list_ia.append(self.whmcs_last_login_ia)
            self.list_ia.append(self.whmcs_compare_ips_ia)

        except Exception as er:
            # generate a error log
            self._log.error("set_list_ia - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def set_dict_ia(self):
        try:
            self.dict_ia.update({"ip_last_login_ia": self.ip_last_login_ia})
            self.dict_ia.update({"disk_used_ia": self.disk_used_ia})
            self.dict_ia.update({"start_account_ia": self.start_account_ia})
            self.dict_ia.update({"suspended_ia": self.suspended_ia})
            self.dict_ia.update({"inodes_used_ia": self.inodes_used_ia})
            self.dict_ia.update({"email_account_disk_used_ia": self.email_account_disk_used_ia})
            self.dict_ia.update({"len_pops_disk_ia": self.len_pops_disk_ia})
            self.dict_ia.update({"len_mysql_databases_ia": self.len_mysql_databases_ia})
            self.dict_ia.update({"len_ftp_disk_ia": self.len_ftp_disk_ia})
            self.dict_ia.update({"len_addon_domains_ia": self.len_addon_domains_ia})
            self.dict_ia.update({"len_parked_domains_ia": self.len_parked_domains_ia})
            self.dict_ia.update({"len_subdomains_ia": self.len_subdomains_ia})
            self.dict_ia.update({"len_cms_ia": self.len_cms_ia})
            self.dict_ia.update({"scan_ia": self.scan_ia})
            self.dict_ia.update({"virustotal_ia": self.virustotal_ia})
            self.dict_ia.update({"wordlist_ia": self.intentional_words_ia})
            self.dict_ia.update({"cpanel_fml_command_ia": self.cpanel_fml_command_ia})
            self.dict_ia.update({"cpanel_fml_date_ia": self.cpanel_fml_date_ia})
            self.dict_ia.update({"cpanel_country_ip_ia": self.cpanel_country_ip_ia})
            self.dict_ia.update({"cpanel_compare_ips_ia": self.cpanel_compare_ips_ia})
            self.dict_ia.update({"cpanel_date_ia": self.cpanel_date_ia})
            self.dict_ia.update({"apache_country_ip_ia": self.apache_country_ip_ia})
            self.dict_ia.update({"apache_compare_ips_ia": self.apache_compare_ips_ia})
            self.dict_ia.update({"apache_wp_ia": self.apache_wp_ia})
            self.dict_ia.update({"apache_date_ia": self.apache_date_ia})
            self.dict_ia.update({"ftp_country_ip_ia": self.ftp_country_ip_ia})
            self.dict_ia.update({"ftp_compare_ips_ia": self.ftp_compare_ips_ia})
            self.dict_ia.update({"ftp_date_ia": self.ftp_date_ia})
            self.dict_ia.update({"server_type_ia": self.server_type_ia})
            self.dict_ia.update({"score_domain_ia": self.score_domain_ia})
            self.dict_ia.update({"whmcs_last_login_ia": self.whmcs_last_login_ia})
            self.dict_ia.update({"whmcs_compare_ips_ia": self.whmcs_compare_ips_ia})

        except Exception as er:
            # generate a error log
            self._log.error("set_dict_ia - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def get_days_account(self, value_end, value_start=None):
        try:
            if value_start is None:
                days_account = datetime.now()-datetime.fromtimestamp(int(value_end))
            else:
                days_account = datetime.fromtimestamp(int(value_end))-datetime.fromtimestamp(int(value_start))
            return int(days_account.days)

        except Exception as er:
            # generate a error log
            self._log.error("get_days_account - {} - {}".format(self.__class__.__name__, er))
            raise NormalizeFailed

    def get_country(self, value_ip):
        try:
            time.sleep(0.5)
            if value_ip is not None and value_ip is not False and value_ip != "" and self.handler_ip_info is not None:
                details_ip_info = self.handler_ip_info.getDetails(value_ip)
                check_country = details_ip_info.country
                if check_country == "BR":
                    return 1
                else:
                    return 2
            return -1

        except requests.exceptions.HTTPError as er:
            # generate a error log
            self._log.error("get_country HTTPError - {} - {} - {}".format(self.__class__.__name__, er, value_ip))
            return -1

        except Exception as er:
            # generate a error log
            self._log.error("get_country - {} - {} - {}".format(self.__class__.__name__, er, value_ip))
            raise NormalizeFailed

    def handle_disk(self, value_disk):
        try:
            self.value_disk = str(value_disk)
            if self.value_disk is not None and self.value_disk is not False and self.value_disk != "0":
                if re.search(self.regex_mb, self.value_disk, flags=re.IGNORECASE):
                    if re.search(self.regex_number, self.value_disk):
                        return int(int(re.search(self.regex_number, self.value_disk).group()))
                elif re.search(self.regex_kb, self.value_disk, flags=re.IGNORECASE):
                    if re.search(self.regex_number, self.value_disk):
                        return int(kB(int(re.search(self.regex_number, self.value_disk).group())).to_MB())
                elif re.search(self.regex_gb, self.value_disk, flags=re.IGNORECASE):
                    if re.search(self.regex_number, self.value_disk):
                        return int(GB(int(re.search(self.regex_number, self.value_disk).group())).to_MB())
                else:
                    if re.search(self.regex_number, self.value_disk):
                        return int(MB(bytes=int(re.search(self.regex_number, self.value_disk).group())))
            else:
                return -1

        except Exception as er:
            # generate a error log
            self._log.error("handle_disk - {} - {} - {}".format(self.__class__.__name__, er, self.value_disk))
            raise NormalizeFailed

    def handle_apache(self):
        try:
            self.temp_apache_country_ip_ia = None
            self.temp_apache_compare_ips_ia = None
            self.temp_apache_date_ia = None
            self.temp_apache_wp_ia = None
            if self.apache_compare_ips_ia is None and self.apache_country_ip_ia is None and self.apache_date_ia is None and \
                    self.apache_wp_ia is None:
                if self.hf_apache_dom_ctime is not None:
                    self.check_match_apache(self.hf_apache_dom_ctime.get('matches'))
            if self.apache_compare_ips_ia is None and self.apache_country_ip_ia is None and self.apache_date_ia is None and \
                    self.apache_wp_ia is None:
                if self.hf_apache_dom_mtime is not None:
                    self.check_match_apache(self.hf_apache_dom_mtime.get('matches'))
            if self.apache_compare_ips_ia is None and self.apache_country_ip_ia is None and self.apache_date_ia is None and \
                    self.apache_wp_ia is None:
                if self.hf_apache_access_mtime is not None:
                    self.check_match_apache(self.hf_apache_access_mtime.get('matches'))
            if self.apache_compare_ips_ia is None and self.apache_country_ip_ia is None and self.apache_date_ia is None and \
                    self.apache_wp_ia is None:
                if self.hf_apache_access_ctime is not None:
                    self.check_match_apache(self.hf_apache_access_ctime.get('matches'))
            if self.apache_compare_ips_ia is None and self.apache_country_ip_ia is None and self.apache_date_ia is None and \
                    self.apache_wp_ia is None:
                if self.hf_apache_dom_mtime is not None:
                    self.check_match_apache(self.hf_apache_dom_mtime.get('matches'))
            # check temp values when result have a brazil IP
            if (self.temp_apache_compare_ips_ia is not None and self.temp_apache_date_ia is not None and
                    self.temp_apache_wp_ia is not None) and (self.apache_country_ip_ia is None and self.apache_compare_ips_ia is None
                    and self.apache_date_ia is None and self.apache_wp_ia is None):
                self.apache_country_ip_ia = self.temp_apache_country_ip_ia
                self.apache_compare_ips_ia = self.temp_apache_compare_ips_ia
                self.apache_date_ia = self.temp_apache_date_ia
                self.apache_wp_ia = self.temp_apache_wp_ia
            # set not found value in compare ips
            if self.apache_compare_ips_ia is None:
                self.apache_compare_ips_ia = -1
            # set not found value in country
            if self.apache_country_ip_ia is None:
                self.apache_country_ip_ia = -1
            # set not found value in date
            if self.apache_date_ia is None:
                self.apache_date_ia = -1
            # set not found value in wp
            if self.apache_wp_ia is None:
                self.apache_wp_ia = -1

        except Exception as er:
            # generate a error log
            self._log.error("handle_apache - {} - {}".format(self.__class__.__name__, er))
            raise NormalizeFailed

    def check_match_apache(self, matches_apache):
        try:
            # check if match exists and then zero
            if matches_apache is not None and matches_apache is not False and len(matches_apache) > 0:
                # walk matches
                for match in matches_apache:
                    result_match = match.get("match")
                    if result_match is not None:
                        # check regex in entry key
                        result_apache = self.module_regex.check_apache(result_match.get("entry"))
                        # check result regex
                        if result_apache is not None and result_apache is not False and len(result_apache) == 2:
                            temp_country_ip = self.get_country(value_ip=result_apache[0])
                            if temp_country_ip == 1:
                                self.temp_apache_country_ip_ia = temp_country_ip
                                self.temp_apache_date_ia = self.get_days_account(value_end=result_match.get("time"), value_start=self.start_account)
                                if result_apache[0] == self.ip_last_login:
                                    self.temp_apache_compare_ips_ia = 1
                                else:
                                    self.temp_apache_compare_ips_ia = 2
                                self.temp_apache_wp_ia = result_apache[1]
                            elif temp_country_ip == 2:
                                self.apache_country_ip_ia = temp_country_ip
                                self.apache_date_ia = self.get_days_account(value_end=result_match.get("time"), value_start=self.start_account)
                                if result_apache[0] == self.ip_last_login:
                                    self.apache_compare_ips_ia = 1
                                else:
                                    self.apache_compare_ips_ia = 2
                                self.apache_wp_ia = result_apache[1]
                                break
                            else:
                                self.temp_apache_date_ia = self.get_days_account(value_end=result_match.get("time"), value_start=self.start_account)
                                if result_apache[0] == self.ip_last_login:
                                    self.temp_apache_compare_ips_ia = 1
                                else:
                                    self.temp_apache_compare_ips_ia = 2
                                self.temp_apache_wp_ia = result_apache[1]

        except Exception as er:
            # generate a error log
            self._log.error("check_match_apache - {} - {}".format(self.__class__.__name__, er))
            raise NormalizeFailed

    def check_match_cpanel_fml(self, matches_cpanel_fml):
        try:
            # check if match exists and then zero
            if matches_cpanel_fml is not None and matches_cpanel_fml is not False and len(matches_cpanel_fml) > 0:
                # walk matches
                for match in matches_cpanel_fml:
                    result_match = match.get("match")
                    if result_match is not None:
                        # check regex in entry key
                        result_cpanel_fml = self.module_regex.check_cpanel_fml(result_match.get("entry"))
                        # check result regex
                        if result_cpanel_fml is not None and result_cpanel_fml is not False:
                            # set found in command
                            self.cpanel_fml_command_ia = 1
                            # get difference days between start_account and time log hf
                            self.cpanel_fml_date_ia = self.get_days_account(value_start=self.start_account, value_end=result_match.get("time"))
                            break

        except Exception as er:
            # generate a error log
            self._log.error("check_match_cpanel_fml - {} - {}".format(self.__class__.__name__, er))
            raise NormalizeFailed

    def handle_cpanel_fml(self):
        try:
            # check mtime result in hf
            if self.cpanel_fml_command_ia is None and self.cpanel_fml_date_ia is None:
                if self.hf_cpanel_fml_mtime is not None:
                    self.check_match_cpanel_fml(self.hf_cpanel_fml_mtime.get('matches'))
            # check ctime result in hf
            if self.cpanel_fml_command_ia is None and self.cpanel_fml_date_ia is None:
                if self.hf_cpanel_fml_ctime is not None:
                    self.check_match_cpanel_fml(self.hf_cpanel_fml_ctime.get('matches'))
            # set not found value in command
            if self.cpanel_fml_command_ia is None:
                self.cpanel_fml_command_ia = -1
            # set not found value in date
            if self.cpanel_fml_date_ia is None:
                self.cpanel_fml_date_ia = -1

        except Exception as er:
            # generate a error log
            self._log.error("handle_cpanel_fml - {} - {}".format(self.__class__.__name__, er))
            raise NormalizeFailed

    def check_match_ftp(self, matches_ftp):
        try:
            if matches_ftp is not None and matches_ftp is not False and len(matches_ftp) > 0:
                for match in matches_ftp:
                    result_match = match.get("match")
                    if result_match is not None:
                        result_ftp = self.module_regex.check_ftp_upload(result_match.get("entry"))
                        if result_ftp is not None and result_ftp is not False and len(result_ftp) == 2:
                            temp_country_ip = self.get_country(value_ip=result_ftp[0])
                            if temp_country_ip == 1:
                                self.temp_ftp_country_ip_ia = temp_country_ip
                                self.temp_ftp_date_ia = self.get_days_account(value_end=result_match.get("time"), value_start=self.start_account)
                                if result_ftp[0] == self.ip_last_login:
                                    self.temp_ftp_compare_ips_ia = 1
                                else:
                                    self.temp_ftp_compare_ips_ia = 2
                            elif temp_country_ip == 2:
                                self.ftp_country_ip_ia = temp_country_ip
                                self.ftp_date_ia = self.get_days_account(value_end=result_match.get("time"), value_start=self.start_account)
                                if result_ftp[0] == self.ip_last_login:
                                    self.ftp_compare_ips_ia = 1
                                else:
                                    self.ftp_compare_ips_ia = 2
                                break
                            else:
                                self.temp_ftp_date_ia = self.get_days_account(value_end=result_match.get("time"), value_start=self.start_account)
                                if result_ftp[0] == self.ip_last_login:
                                    self.temp_ftp_compare_ips_ia = 1
                                else:
                                    self.temp_ftp_compare_ips_ia = 2

        except Exception as er:
            # generate a error log
            self._log.error("check_match_ftp - {} - {}".format(self.__class__.__name__, er))
            raise NormalizeFailed

    def handle_ftp(self):
        try:
            self.temp_ftp_country_ip_ia = None
            self.temp_ftp_compare_ips_ia = None
            self.temp_ftp_date_ia = None
            # check mtime result in hf
            if self.ftp_compare_ips_ia is None and self.ftp_country_ip_ia is None and self.ftp_date_ia is None:
                if self.hf_ftp_messages_ctime is not None:
                    self.check_match_ftp(self.hf_ftp_messages_ctime.get('matches'))
            # check ctime result in hf
            if self.ftp_compare_ips_ia is None and self.ftp_country_ip_ia is None and self.ftp_date_ia is None:
                if self.hf_ftp_messages_mtime is not None:
                    self.check_match_ftp(self.hf_ftp_messages_mtime.get('matches'))
            # check temp values when result have a brazil IP
            if (self.temp_ftp_compare_ips_ia is not None and self.temp_ftp_date_ia is not None) and (self.ftp_compare_ips_ia is None and
                    self.ftp_country_ip_ia is None and self.ftp_date_ia is None):
                self.ftp_compare_ips_ia = self.temp_ftp_compare_ips_ia
                self.ftp_country_ip_ia = self.temp_ftp_country_ip_ia
                self.ftp_date_ia = self.temp_ftp_date_ia
            # set not found value in compare IPs
            if self.ftp_compare_ips_ia is None:
                self.ftp_compare_ips_ia = -1
            # set not found value in date
            if self.ftp_date_ia is None:
                self.ftp_date_ia = -1
            # set not found value in country IP
            if self.ftp_country_ip_ia is None:
                self.ftp_country_ip_ia = -1

        except Exception as er:
            # generate a error log
            self._log.error("handle_ftp - {} - {}".format(self.__class__.__name__, er))
            raise 

    def check_match_cpanel(self, matches_cpanel):
        try:
            if matches_cpanel is not None and matches_cpanel is not False and len(matches_cpanel) > 0:
                for match in matches_cpanel:
                    result_match = match.get("match")
                    if result_match is not None:
                        result_cpanel = self.module_regex.check_cpanel(result_match.get("entry"))
                        if result_cpanel is not None and result_cpanel is not False:
                            temp_country_ip = self.get_country(value_ip=result_cpanel)
                            if temp_country_ip == 1:
                                self.temp_cpanel_country_ip_ia = temp_country_ip
                                self.temp_cpanel_date_ia = self.get_days_account(value_end=result_match.get("time"), value_start=self.start_account)
                                if result_cpanel == self.ip_last_login:
                                    self.temp_cpanel_compare_ips_ia = 1
                                else:
                                    self.temp_cpanel_compare_ips_ia = 2
                            elif temp_country_ip == 2:
                                self.cpanel_country_ip_ia = temp_country_ip
                                self.cpanel_date_ia = self.get_days_account(value_end=result_match.get("time"), value_start=self.start_account)
                                if result_cpanel == self.ip_last_login:
                                    self.cpanel_compare_ips_ia = 1
                                else:
                                    self.cpanel_compare_ips_ia = 2
                                break
                            else:
                                self.temp_cpanel_date_ia = self.get_days_account(value_end=result_match.get("time"), value_start=self.start_account)
                                if result_cpanel == self.ip_last_login:
                                    self.temp_cpanel_compare_ips_ia = 1
                                else:
                                    self.temp_cpanel_compare_ips_ia = 2

        except Exception as er:
            # generate a error log
            self._log.error("check_match_cpanel - {} - {}".format(self.__class__.__name__, er))
            raise NormalizeFailed

    def handle_cpanel(self):
        try:
            self.temp_cpanel_country_ip_ia = None
            self.temp_cpanel_compare_ips_ia = None
            self.temp_cpanel_date_ia = None
            # check mtime result in hf
            if self.cpanel_compare_ips_ia is None and self.cpanel_country_ip_ia is None and self.cpanel_date_ia is None:
                if self.hf_cpanel_mtime is not None:
                    self.check_match_cpanel(self.hf_cpanel_mtime.get('matches'))
            # check ctime result in hf
            if self.cpanel_compare_ips_ia is None and self.cpanel_country_ip_ia is None and self.cpanel_date_ia is None:
                if self.hf_cpanel_ctime is not None:
                    self.check_match_cpanel(self.hf_cpanel_ctime.get('matches'))
            # check temp values when result have a brazil IP
            if (self.temp_cpanel_compare_ips_ia is not None and self.temp_cpanel_date_ia is not None) and (self.cpanel_compare_ips_ia is None and
                    self.cpanel_country_ip_ia is None and self.cpanel_date_ia is None):
                self.cpanel_compare_ips_ia = self.temp_cpanel_compare_ips_ia
                self.cpanel_country_ip_ia = self.temp_cpanel_country_ip_ia
                self.cpanel_date_ia = self.temp_cpanel_date_ia
            # set not found value in compare ips
            if self.cpanel_compare_ips_ia is None:
                self.cpanel_compare_ips_ia = -1
            # set not found value in country
            if self.cpanel_country_ip_ia is None:
                self.cpanel_country_ip_ia = -1
            # set not found value in date
            if self.cpanel_date_ia is None:
                self.cpanel_date_ia = -1

        except Exception as er:
            # generate a error log
            self._log.error("handle_cpanel - {} - {}".format(self.__class__.__name__, er))
            raise NormalizeFailed

    def handle_hf(self):
        try:
            if self.hf is not None and self.hf is not False:
                self.hf_mtime = self.hf.get('mtime')
                if self.hf_mtime is not None and self.hf_mtime is not False:
                    self.hf_cpanel_fml_mtime = self.hf_mtime.get('cpanel_fml')
                    self.hf_cpanel_mtime = self.hf_mtime.get('cpanel')
                    self.hf_ftpxfer_mtime = self.hf_mtime.get('ftp_xfer')
                    self.hf_apache_access_mtime = self.hf_mtime.get('apache_access')
                    self.hf_ftp_messages_mtime = self.hf_mtime.get('ftp_messages')
                    self.hf_apache_dom_mtime = self.hf_mtime.get('apache_dom')
                    self.hf_bash_history_mtime = self.hf_mtime.get('bash_history')
                self.hf_ctime = self.hf.get('ctime')
                if self.hf_ctime is not None and self.hf_ctime is not False:
                    self.hf_cpanel_fml_ctime = self.hf_ctime.get('cpanel_fml')
                    self.hf_ftpxfer_ctime = self.hf_ctime.get('ftp_xfer')
                    self.hf_apache_access_ctime = self.hf_ctime.get('apache_access')
                    self.hf_ftp_messages_ctime = self.hf_ctime.get('ftp_messages')
                    self.hf_apache_dom_ctime = self.hf_ctime.get('apache_dom')
                    self.hf_bash_history_ctime = self.hf_ctime.get('bash_history')
                    self.hf_cpanel_ctime = self.hf_ctime.get('cpanel')
            else:
                self.hf_mtime = None
                self.hf_ctime = None

        except Exception as er:
            # generate a error log
            self._log.error("handle_hf - {} - {}".format(self.__class__.__name__, er))
            raise NormalizeFailed

    def process(self, mIA=None, mIA_scaler=None):
        # mark start ansible action, 1 - pwrestrict, 2 - suspension, 3 - nothing action
        try:
            if self.module_configuration.application == "production" or \
                    self.module_configuration.application == "development":
                if self.ansible_check is True:
                    if len(self.list_ia) == 32:
                        del self.list_ia[-1]
                        del self.list_ia[-1]
                        del self.list_ia[-1]
                        del self.list_ia[-1]
                        try:
                            mIA_dataframe = pandas.DataFrame(numpy.array(self.list_ia).reshape(1,28))
                            mIA_transform = mIA_scaler.transform(mIA_dataframe)
                            mIA_result = int(mIA.predict(mIA_transform)[0])

                        except Exception as er:
                            self._log.error("mIA - {} - {}".format(self.__class__.__name__, er))
                            mIA_result = 0

                        self.result_type = mIA_result
                        result_action = False
                        general_error = False
                        if self.result_type == 2 and self.disk_used_ia != -1 and self.disk_used_ia <= 500:
                            if self.execute_backup():
                                result_action = True
                            else:
                                result_action = False
                                general_error = True
                        else:
                            if self.result_type == 2:
                                self.result_dict.update({"generate_backup": False})
                            if self.execute_block():
                                if self.result_dict.get("pw_already_enabled") is not None and \
                                        self.result_dict.get("pw_already_enabled"):
                                    if self.execute_unblock():
                                        if self.execute_block() is True and self.result_dict.get("pw_already_enabled") is False:
                                            result_action = True
                                        else:
                                            result_action = False
                                            general_error = True
                                    else:
                                        result_action = False
                                        general_error = True
                                else:
                                    result_action = True
                            else:
                                result_action = False
                                general_error = True
                        self.result_dict.update({"result_action": result_action})
                        self.result_dict.update({"result_type": self.result_type})
                        self.result_dict.update({"general_error": general_error})
                    else:
                        self._log.error("Len list IA not compatible - {} - {}".format(self.values_ticket, self.list_ia))
                        raise IAFailed
                else:
                    self._log.error("Ansible check is not true - {}".format(self.values_ticket))
                    raise IAFailed
            elif self.module_configuration.application == "model":
                if len(self.list_ia) == 32:
                    self.result_dict.update({"result_action": True})
                    csv_output = open("/opt/abuse/list_ia.csv", "a")
                    csv_output.write(",".join(map(str, self.list_ia)))
                    csv_output.write("\n")
                    csv_output.close()
                else:
                    self._log.error("Len list IA not compatible - {} - {}".format(self.values_ticket, self.list_ia))
                    exit(1)

        except GeneralError:
            raise IAFailed

        except Exception as er:
            # generate a error log
            self._log.error("process - {} - {}".format(self.__class__.__name__, er))
            raise IAFailed

    def execute_unblock(self):
        try:
            vars_ansible_unblock = {
                "thread_id": self.thread_id,
                "directory": self.home,
                "type_block": "pwrestrict",
                "pw_unblock": True,
            }
            summary_ansible = self.module_ansible.execute(self.playbook_block, vars_ansible_unblock, self.server)
            if summary_ansible is False or summary_ansible is None or summary_ansible['rescued'] > 0:
                self._log.info("Failed execute playbook unblock - {}".format(vars_ansible_unblock))
                return False
            else:
                return True

        except Exception as er:
            # generate a error log
            self._log.error("execute_unblock - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def execute_block(self):
        try:
            vars_ansible_block = {
                "thread_id": self.thread_id,
                "directory": self.home,
                "type_block": "pwrestrict",
                "pw_block": True,
            }
            summary_ansible = self.module_ansible.execute(self.playbook_block, vars_ansible_block, self.server)
            if summary_ansible is False or summary_ansible is None or summary_ansible['rescued'] > 0:
                self._log.info("Failed execute playbook block - {}".format(vars_ansible_block))
                return False
            else:
                if os.path.exists(self.report_action) and os.path.getsize(self.report_action) > 0:
                    with closing(open(self.report_action)) as open_report:
                        report_content = open_report.read().split(",")
                    if report_content is not None and report_content is not False and len(report_content) == 4:
                        ansible_action = 4
                        self.result_dict.update({"pw_user": report_content[0]})
                        self.result_dict.update({"pw_password": report_content[1]})
                        self.result_dict.update({"check_unblock": ast.literal_eval(report_content[2])})
                        self.result_dict.update({"pw_already_enabled": ast.literal_eval(report_content[3])})
                        self.result_dict.update({"ansible_action": ansible_action})
                        if self.result_dict.get("pw_already_enabled") is False:
                            self.module_database.update_analyzing("ansible_action", ansible_action, self.thread_id)
                            self.module_database.update_analyzing("result_type", self.result_type, self.thread_id)
                        return True
                    else:
                        self._log.info("Failed get report content - {}".format(vars_ansible_block))
                        return False
                else:
                    self._log.info("Failed check report action - {}".format(vars_ansible_block))
                    return False

        except Exception as er:
            # generate a error log
            self._log.error("execute_block - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def execute_backup(self):
        try:
            vars_ansible_intentional = {
                "thread_id": self.thread_id,
                "user": self.user,
                "domain": self.domain,
                "ticket_id": self.ticket_id,
                "phishing_intentional": True,
            }
            summary_ansible = self.module_ansible.execute(self.playbook_backup, vars_ansible_intentional, self.server)
            if summary_ansible is False or summary_ansible is None or summary_ansible['rescued'] > 0:
                self._log.info("Failed execute playbook backup - {}".format(vars_ansible_intentional))
                return False
            else:
                if not os.path.exists(self.check_backup) and not os.path.exists(self.check_suspend):
                    ansible_action = 3
                    self.result_dict.update({"generate_backup": True})
                    self.result_dict.update({"suspend_account": True})
                    self.result_dict.update({"ansible_action": ansible_action})
                    self.module_database.update_analyzing("generate_backup", 3, self.thread_id)
                    self.module_database.update_analyzing("suspend_account", 3, self.thread_id)
                    self.module_database.update_analyzing("ansible_action", ansible_action, self.thread_id)
                    self.module_database.update_analyzing("result_type", self.result_type, self.thread_id)
                    return True
                elif not os.path.exists(self.check_backup):
                    ansible_action = 2
                    self.result_dict.update({"generate_backup": True})
                    self.result_dict.update({"suspend_account": False})
                    self.result_dict.update({"ansible_action": ansible_action})
                    self.module_database.update_analyzing("generate_backup", 3, self.thread_id)
                    self.module_database.update_analyzing("suspend_account", 2, self.thread_id)
                    self.module_database.update_analyzing("ansible_action", ansible_action, self.thread_id)
                    self.module_database.update_analyzing("result_type", self.result_type, self.thread_id)
                    return True
                elif not os.path.exists(self.check_suspend):
                    ansible_action = 1
                    self.result_dict.update({"generate_backup": False})
                    self.result_dict.update({"suspend_account": True})
                    self.result_dict.update({"ansible_action": ansible_action})
                    self.module_database.update_analyzing("generate_backup", 2, self.thread_id)
                    self.module_database.update_analyzing("suspend_account", 3, self.thread_id)
                    self.module_database.update_analyzing("ansible_action", ansible_action, self.thread_id)
                    self.module_database.update_analyzing("result_type", self.result_type, self.thread_id)
                    return True
                else:
                    ansible_action = 9
                    self.result_dict.update({"generate_backup": False})
                    self.result_dict.update({"suspend_account": False})
                    self.result_dict.update({"ansible_action": ansible_action})
                    self.module_database.update_analyzing("generate_backup", 2, self.thread_id)
                    self.module_database.update_analyzing("suspend_account", 2, self.thread_id)
                    self.module_database.update_analyzing("ansible_action", ansible_action, self.thread_id)
                    self.module_database.update_analyzing("result_type", self.result_type, self.thread_id)
                    return True

        except Exception as er:
            # generate a error log
            self._log.error("execute_backup - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

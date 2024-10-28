# -*- coding: utf-8 -*-
"""

- Contributors
Elliann Marks <elian.markes@gmail.com>

"""

# libraries
import os
import time
import json
from contextlib import closing
from abuse_automation.module_zen import ModuleZen
from abuse_automation.module_database import ModuleDatabase
from abuse_automation_zenapply.module_templates import ModuleTemplates
from abuse_automation.module_exceptions import GeneralError, ZenapplyFailed, ZenFailed, \
    TemplatesFailed, DatabaseUpdateFailed, ContinueError


class ModuleZenapply:

    def __init__(self, module_log, module_configuration, values_ticket):
        """
        """
        try:
            self._log = module_log
            self.module_configuration = module_configuration
            self.values_ticket = values_ticket
            # instance of the ModuleDatabase
            self.module_database = ModuleDatabase(self._log, self.module_configuration)
            self.module_zen = ModuleZen(self._log, self.module_configuration)
            self._zen_task = "zendesk_task"
            self.report_dir = self.module_configuration.report_dir
            self.report_prints = self.module_configuration.report_prints
            # set variables
            self.module_templates = None
            self.user_info = None
            self.open_ticket = False
            # set values
            self.values_ticket = values_ticket
            self.general_error = self.values_ticket['general_error']
            self.thread_id = self.values_ticket['thread_id']
            self.ticket_id = self.values_ticket['ticket_id']
            self.brand = self.values_ticket['brand']
            if self.general_error:
                self._log.error("General error is true - {}".format(self.values_ticket))
                self.set_true_error()
                raise GeneralError
            else:
                self.pw_user = self.values_ticket.get('pw_user')
                self.pw_password = self.values_ticket.get('pw_password')
                self.check_unblock = self.values_ticket.get('check_unblock')
                self.pw_already_enabled = self.values_ticket.get('pw_already_enabled')
                self.result_action = self.values_ticket['result_action']
                self.ansible_action = self.values_ticket['ansible_action']
                self.generate_backup = self.values_ticket['generate_backup']
                self.suspend_account = self.values_ticket['suspend_account']
                self.doc_root = self.values_ticket['doc_root']
                self.server = self.values_ticket['server']
                self.domain = self.values_ticket['domain']
                self.path_url = self.values_ticket['path_url']
                self.main_check = self.values_ticket['main_check']
                self.main_domain = self.values_ticket['main_domain']
                self.main_server = self.values_ticket['main_server']
                self.result_type = self.values_ticket['result_type']
                self.owner = self.values_ticket['owner']
                # directory report
                self.report_case = str(self.main_domain) + "_" + str(self.ticket_id) + "_" + str(self.thread_id)
                self.report_case_path = os.path.join(self.report_dir, self.report_case)
                # paths scan
                self.report_scan_phishing = os.path.join(self.report_case_path, "scan_phishing")
                self.report_scan_malware = os.path.join(self.report_case_path, "scan_malware")
                self.report_user_info = os.path.join(self.report_case_path, "user_info.json")
                self.report_user_info_owner = os.path.join(self.report_case_path, "user_info_owner.json")
                # path print
                self.print_path = os.path.join(self.report_prints, self.thread_id + ".jpg")

        except GeneralError:
            raise ZenapplyFailed

        except Exception as er:
            # generate a error log
            self._log.error("{} - {}".format(self.__class__.__name__, er))
            raise ZenapplyFailed

    def process(self):
        try:
            # ansible action -> 1 - suspended, 2 - backup generate, 3 - suspended and backup generate, 4 - pwrestrict, 9 - nothing action
            if self.result_action:
                # get user info
                if self.get_user_info() and self.user_info is not None and self.user_info.get('client') is not None:
                    client_email = self.user_info['client']['email']
                    # instance templates
                    self.module_templates = ModuleTemplates(self._log, self.module_configuration, self.values_ticket)
                    # check result type
                    if self.result_type == 1:
                        if self.ansible_action == 4:
                            upload_file = self.upload_files()
                            # check if print exists
                            if os.path.exists(self.print_path) and os.path.getsize(self.print_path) > 0:
                                upload_file.append(self.module_zen.upload_file(self.print_path, self.main_domain + ".jpg", brand=self.brand))
                                description = self.module_templates.description(print_url=True)
                            else:
                                description = self.module_templates.description()
                            # create ticket client
                            if len(upload_file) > 0:
                                create_ticket = self.module_zen.create_ticket(
                                    submitter_id=self.module_zen.submitter_support, email=client_email,
                                    tags=[self.module_zen.new_ticket, self.module_zen.tag_phishing],
                                    subject=self.module_templates.subject_client, comment=description,
                                    upload=upload_file, priority="normal", status="pending",
                                    group_id=self.module_zen.group_abuse, brand=self.brand)
                            else:
                                create_ticket = self.module_zen.create_ticket(
                                    submitter_id=self.module_zen.submitter_support, email=client_email,
                                    tags=[self.module_zen.new_ticket, self.module_zen.tag_phishing],
                                    subject=self.module_templates.subject_client, description=description,
                                    priority="normal", status="pending", group_id=self.module_zen.group_abuse,  brand=self.brand)
                            self.module_database.update_analyzing(self._zen_task, 2, self.thread_id)
                            self.module_database.update_analyzing("status", 3, self.thread_id)
                            self.open_ticket = self.module_zen.job_status(create_ticket.id, brand=self.brand)
                            if self.open_ticket is not False:
                                self.module_database.update_analyzing("new_ticket", self.open_ticket, self.thread_id)
                                self.comment_result()
                            else:
                                self.module_database.update_analyzing("job_id_ticket", create_ticket.id, self.thread_id)
                                self.comment_result(job_id=create_ticket.id)
                            time.sleep(1)
                            zen_return = self.module_zen.search_id(self.ticket_id, brand=self.brand)
                            zen_return.tags = self.module_zen.handle_tag(zen_return.tags, self.module_zen.tag_handled)
                            zen_return.tags = self.module_zen.handle_tag(zen_return.tags, self.module_zen.tag_phishing)
                            zen_return.tags = self.module_zen.handle_tag(zen_return.tags, self.module_zen.tag_closed)
                            self.module_zen.update_ticket(zen_return, brand=self.brand)
                            self._log.debug("Zenapply finish phishing- {} - {} - {}".format(self.ticket_id, self.result_type, self.ansible_action))
                        else:
                            self._log.debug("Zenapply invalid ansible action - {} - {}".format(self.ticket_id, self.thread_id))
                            self.comment_result()
                            time.sleep(1)
                            self.set_true()
                    elif self.result_type == 2:
                        if (self.ansible_action == 3 or self.ansible_action == 2) and self.generate_backup:
                            create_ticket = self.module_zen.create_ticket(submitter_id=self.module_zen.submitter_support,
                                                                          email=client_email, tags=[self.module_zen.new_ticket,self.module_zen.tag_phishing_intentional],
                                                                          subject=self.module_templates.subject_client, description=self.module_templates.description_intentional(),
                                                                          assignee_id=None, priority="normal", status="open", group_id=self.module_zen.group_financial_3, brand=self.brand)
                            self.module_database.update_analyzing(self._zen_task, 2, self.thread_id)
                            self.module_database.update_analyzing("status", 3, self.thread_id)
                            self.module_zen.comment_ticket(self.ticket_id, self.module_templates.comment_intentional, public=False, brand=self.brand)
                            self.open_ticket = self.module_zen.job_status(create_ticket.id, brand=self.brand)
                            if self.open_ticket is not False:
                                self.module_database.update_analyzing("new_ticket", self.open_ticket, self.thread_id)
                                self.comment_result()
                                time.sleep(1)
                                self.module_zen.comment_ticket(self.open_ticket, self.module_templates.comment_intentional, public=False, brand=self.brand)
                            else:
                                self.module_database.update_analyzing("job_id_ticket", create_ticket.id, self.thread_id)
                                self.comment_result(job_id=create_ticket.id)
                            time.sleep(1)
                            zen_return = self.module_zen.search_id(self.ticket_id, brand=self.brand)
                            zen_return.tags = self.module_zen.handle_tag(zen_return.tags, self.module_zen.tag_handled)
                            zen_return.tags = self.module_zen.handle_tag(zen_return.tags, self.module_zen.tag_phishing_intentional)
                            zen_return.tags = self.module_zen.handle_tag(zen_return.tags, self.module_zen.tag_closed)
                            self.module_zen.update_ticket(zen_return, brand=self.brand)
                            self._log.debug("Zenapply finish phishing intentional - {} - {} - {}".format(self.ticket_id, self.result_type, self.ansible_action))
                        else:
                            create_ticket = self.module_zen.create_ticket(submitter_id=self.module_zen.submitter_support, email=client_email,
                                                                          tags=[self.module_zen.new_ticket,self.module_zen.tag_phishing_intentional],
                                                                          subject=self.module_templates.subject_client, description=self.module_templates.description_intentional(),
                                                                          assignee_id=None, priority="high", status="open", group_id=self.module_zen.group_abuse, brand=self.brand)
                            self.module_database.update_analyzing(self._zen_task, 2, self.thread_id)
                            self.module_database.update_analyzing("status", 3, self.thread_id)
                            self.module_zen.comment_ticket(self.ticket_id, self.module_templates.comment_intentional, public=False, brand=self.brand)
                            self.open_ticket = self.module_zen.job_status(create_ticket.id, brand=self.brand)
                            if self.open_ticket is not False:
                                self.module_database.update_analyzing("new_ticket", self.open_ticket, self.thread_id)
                                self.comment_result()
                                time.sleep(1)
                                self.module_zen.comment_ticket(self.open_ticket, self.module_templates.comment_intentional, public=False, brand=self.brand)
                                time.sleep(1)
                                if self.ansible_action == 1:
                                    self.module_zen.comment_ticket(self.open_ticket, "INFO: Backup not create, but account has been suspended. Require checking and notification to the financial.", public=False, brand=self.brand)
                                elif self.ansible_action == 9:
                                    self.module_zen.comment_ticket(self.open_ticket, "INFO: Ansible failed, nothing action executed. Require checking and notification to the financial.", public=False, brand=self.brand)
                                else:
                                    self.module_zen.comment_ticket(self.open_ticket, "ERROR: Invalid value in ansible action, undefined status of the account. Require checking and that continue the handle.", public=False, brand=self.brand)
                            else:
                                self.module_database.update_analyzing("job_id_ticket", create_ticket.id, self.thread_id)
                                self.comment_result(job_id=create_ticket.id)
                                time.sleep(1)
                                if self.ansible_action == 1:
                                    self.module_zen.comment_ticket(self.ticket_id, "INFO: Backup not create, but account has been suspended. Require checking and notification to the financial.", public=False, brand=self.brand)
                                elif self.ansible_action == 9:
                                    self.module_zen.comment_ticket(self.ticket_id, "INFO: Ansible failed, nothing action executed. Require checking and notification to the financial.", public=False, brand=self.brand)
                                else:
                                    self.module_zen.comment_ticket(self.ticket_id, "ERROR: Invalid value in ansible action, undefined status of the account. Require checking and that continue the handle.", public=False, brand=self.brand)
                            time.sleep(1)
                            zen_return = self.module_zen.search_id(self.ticket_id, brand=self.brand)
                            zen_return.tags = self.module_zen.handle_tag(zen_return.tags, self.module_zen.tag_handled)
                            zen_return.tags = self.module_zen.handle_tag(zen_return.tags, self.module_zen.tag_phishing_intentional)
                            zen_return.tags = self.module_zen.handle_tag(zen_return.tags, self.module_zen.tag_closed)
                            self.module_zen.update_ticket(zen_return, brand=self.brand)
                            self._log.debug("Zenapply finish phishing intentional - {} - {} - {}".format(self.ticket_id, self.result_type, self.ansible_action))
                    else:
                        self._log.debug("Zenapply invalid result type")
                        self.open_ticket = "Not created"
                        self.module_zen.comment_ticket(self.ticket_id, "ERROR: Invalid result, undefined type for IA. Require checking and that continue the handle.", public=False, brand=self.brand)
                        time.sleep(1)
                        self.comment_result()
                        time.sleep(1)
                        self.set_true_error()
                else:
                    self._log.error("Zenapply failed in get_user_info - {} - {}".format(self.ticket_id, self.thread_id))
                    self.comment_result()
                    time.sleep(1)
                    self.set_true_error()
            else:
                self._log.debug("Zenapply result action not true - {} - {}".format(self.ticket_id, self.thread_id))
                self.comment_result()
                time.sleep(1)
                self.set_true_error()

        except DatabaseUpdateFailed:
            raise GeneralError

        except TemplatesFailed:
            raise GeneralError

        except ZenFailed:
            raise GeneralError

        except KeyError as er:
            raise GeneralError

        except Exception as er:
            # generate a error log
            self._log.error("process - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def set_true(self):
        try:
            zen_return = self.module_zen.search_id(self.ticket_id, brand=self.brand)
            # update ticket
            zen_return.tags = self.module_zen.tag_true
            zen_return.assignee = None
            zen_return.status = "open"
            zen_return.priority = "normal"
            # apply the change in ticket
            self.module_zen.update_ticket(zen_return, brand=self.brand)
            self.module_database.update_analyzing(self._zen_task, 1, self.thread_id)
            self.module_database.update_analyzing("status", 3, self.thread_id)

        except ZenFailed:
            try:
                self.module_database.update_analyzing(self._zen_task, 1, self.thread_id)
                self.module_database.update_analyzing("status", 2, self.thread_id)

            except Exception as er:
                self._log.error("set_true - {} - {}".format(self.__class__.__name__, er))
                pass

            raise GeneralError

        except Exception as er:
            # generate a error log
            self._log.error("set_true - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def set_true_error(self):
        try:
            zen_return = self.module_zen.search_id(self.ticket_id, brand=self.brand)
            # update ticket
            zen_return.tags = self.module_zen.tag_true_error
            zen_return.assignee = None
            zen_return.status = "open"
            zen_return.priority = "normal"
            # apply the change in ticket
            self.module_zen.update_ticket(zen_return, brand=self.brand)
            self.module_database.update_analyzing(self._zen_task, 1, self.thread_id)
            self.module_database.update_analyzing("status", 2, self.thread_id)

        except ZenFailed:
            try:
                self.module_database.update_analyzing(self._zen_task, 1, self.thread_id)
                self.module_database.update_analyzing("status", 2, self.thread_id)

            except Exception as er:
                self._log.error("set_true_error - {} - {}".format(self.__class__.__name__, er))
                pass
            
            raise GeneralError

        except Exception as er:
            # generate a error log
            self._log.error("set_true_error - {} - {}".format(self.__class__.__name__, er))
            raise GeneralError

    def comment_result(self, job_id=None):
        try:
            if job_id is None:
                self.module_zen.comment_ticket(self.ticket_id,
                                               self.module_templates.result_analyzing(open_ticket=self.open_ticket),
                                               public=False, upload=self.upload_files(), brand=self.brand)
            else:
                self.module_zen.comment_ticket(self.ticket_id,
                                               self.module_templates.result_analyzing(job_id=job_id),
                                               public=False, upload=self.upload_files(), brand=self.brand)

        except ZenFailed:
            return False

        except Exception as er:
            # generate a error log
            self._log.error("comment_result - {} - {}".format(self.__class__.__name__, er))
            return False

    def upload_files(self):
        try:
            upload_list_files = list()
            if os.path.exists(self.report_scan_phishing) and os.path.getsize(self.report_scan_phishing) > 0 and \
                    os.path.exists(self.report_scan_malware) and os.path.getsize(self.report_scan_malware) > 0:
                upload_list_files.append(self.module_zen.upload_file(self.report_scan_phishing, self.main_domain + ".txt", brand=self.brand))
                upload_list_files.append(self.module_zen.upload_file(self.report_scan_malware, self.main_domain + ".txt", brand=self.brand))
            elif os.path.exists(self.report_scan_phishing) and os.path.getsize(self.report_scan_phishing) > 0:
                upload_list_files.append(self.module_zen.upload_file(self.report_scan_phishing, self.main_domain + ".txt", brand=self.brand))
            elif os.path.exists(self.report_scan_malware) and os.path.getsize(self.report_scan_malware) > 0:
                upload_list_files.append(self.module_zen.upload_file(self.report_scan_malware, self.main_domain + ".txt", brand=self.brand))
            return upload_list_files

        except ZenFailed:
            upload_list_files = list()
            return upload_list_files

        except Exception as er:
            upload_list_files = list()
            # generate a error log
            self._log.error("upload_files - {} - {}".format(self.__class__.__name__, er))
            return upload_list_files

    def get_user_info(self):
        try:
            # check if file exists
            if os.path.exists(self.report_user_info_owner) and self.owner != "root":
                # open file and load json in variable
                with closing(open(self.report_user_info_owner)) as open_user_info:
                    self.user_info = json.load(open_user_info)
                return True
            elif os.path.exists(self.report_user_info):
                # open file and load json in variable
                with closing(open(self.report_user_info)) as open_user_info:
                    self.user_info = json.load(open_user_info)
                return True
            else:
                return False

        except Exception as er:
            # generate a error log
            self._log.error("get_user_info {} - {}".format(self.__class__.__name__, er))
            return False

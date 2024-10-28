# -*- coding: utf-8 -*-
"""
- Contributors
Elliann Marks <elian.markes@gmail.com>

"""

# libraries
from abuse_automation.module_database import ModuleDatabase
from abuse_automation.module_exceptions import TemplatesFailed


class ModuleTemplates:

    def __init__(self, module_log, module_configuration, values_ticket):
        try:
            self._log = module_log
            self.module_configuration = module_configuration
            # instance of the module_database
            self.module_database = ModuleDatabase(self._log, self.module_configuration)
            # set values
            self.pw_user = values_ticket.get('pw_user')
            self.pw_password = values_ticket.get('pw_password')
            self.check_unblock = values_ticket.get('check_unblock')
            self.pw_already_enabled = values_ticket.get('pw_already_enabled')
            self.ansible_action = values_ticket['ansible_action']
            self.result_action = values_ticket['result_action']
            self.thread_id = values_ticket['thread_id']
            self.ticket_id = values_ticket['ticket_id']
            self.doc_root = values_ticket['doc_root']
            self.server = values_ticket['server']
            self.domain = values_ticket['domain']
            self.path_url = values_ticket['path_url']
            self.main_check = values_ticket['main_check']
            self.main_domain = values_ticket['main_domain']
            self.main_server = values_ticket['main_server']
            self.result_type = values_ticket['result_type']
            self.brand = values_ticket['brand']
            # set string result type
            if self.result_type is not None and self.result_type == 1:
                self.string_result_type = "Phishing"
            elif self.result_type is not None and self.result_type == 2:
                self.string_result_type = "Phishing Intentional"
            else:
                self.string_result_type = "Undefined"
            # set string ansible action
            if self.ansible_action is not None and self.ansible_action is not False and self.ansible_action == 3:
                self.string_ansible_action = "Backup generate and account suspended"
            elif self.ansible_action is not None and self.ansible_action is not False and self.ansible_action == 2:
                self.string_ansible_action = "Backup generate and failed in suspend account"
            elif self.ansible_action is not None and self.ansible_action is not False and self.ansible_action == 1:
                self.string_ansible_action = "Suspended account and failed in generate backup of the account"
            elif self.ansible_action is not None and self.ansible_action is not False and self.ansible_action == 9:
                self.string_ansible_action = "Nothing action executed"
            elif self.ansible_action is not None and self.ansible_action is not False and self.ansible_action == 4:
                self.string_ansible_action = "Executed pwrestrict"
            else:
                self.string_ansible_action = "Action undefined, require checking"

        except Exception as er:
            self._log.error("Templates init - {} - {}".format(self.__class__.__name__, er))
            raise TemplatesFailed

    def get_link_vt(self, scan_vt):
        try:
            return "https://www.virustotal.com/en/url/" + str(scan_vt.split("-")[0]) + "/analysis/" + str(scan_vt.split("-")[1])

        except Exception as er:
            # generate a error log
            self._log.error("get_link_vt - {} - {}".format(self.__class__.__name__, er))
            return False

    def result_analyzing(self, open_ticket=None, job_id=None):
        if job_id is None:
            if "." in self.main_domain:
                return "Domain: {}\n\nPath_url: {}\n\n" \
                   "Process ID: {}\n\nDoc Root: {}\n\nAnsible Action: {}\n\nNew Ticket: {}\n\n" \
                   "User: {}\n\nPassword: {}\n\nServer: {}\n\nResult Type: {}\n\n".format(self.main_domain, self.main_domain + self.path_url, self.thread_id,
                                                                                          self.doc_root, self.string_ansible_action, open_ticket, self.pw_user, self.pw_password, self.main_server, self.string_result_type)
            else:
                return "User: {}\n\nPath: {}\n\n" \
                   "Process ID: {}\n\nDoc Root: {}\n\nAnsible Action: {}\n\nNew Ticket: {}\n\n" \
                   "User: {}\n\nPassword: {}\n\nServer: {}\n\nResult Type: {}\n\n".format(self.main_domain, self.path_url, self.thread_id,
                                                                                          self.doc_root, self.string_ansible_action, open_ticket, self.pw_user, self.pw_password, self.main_server, self.string_result_type)
        else:
            if "." in self.main_domain:
                return "Domain: {}\n\nPath_url: {}\n\n" \
                   "Process ID: {}\n\nDoc Root: {}\n\nAnsible Action: {}\n\nJob ID Zendesk: {}\n\n" \
                   "User: {}\n\nPassword: {}\n\nServer: {}\n\nResult Type: {}\n\n".format(self.main_domain, self.main_domain + self.path_url, self.thread_id,
                                                                                          self.doc_root, self.string_ansible_action, job_id, self.pw_user, self.pw_password, self.main_server, self.string_result_type)
            else:
                return "User: {}\n\nPath: {}\n\n" \
                   "Process ID: {}\n\nDoc Root: {}\n\nAnsible Action: {}\n\nJob ID Zendesk: {}\n\n" \
                   "User: {}\n\nPassword: {}\n\nServer: {}\n\nResult Type: {}\n\n".format(self.main_domain, self.path_url, self.thread_id,
                                                                                          self.doc_root, self.string_ansible_action, job_id, self.pw_user, self.pw_password, self.main_server, self.string_result_type)

    @property
    def comment_intentional(self):
        if "." in self.main_domain:
            return "Domain: {}\n\nPath_url: {}\n\n" \
               "Process ID: {}\n\nDoc Root: {}\n\nAnsible Action: {}\n\nReport Ticket: {}\n\n" \
               "Server: {}\n\nResult Type: {}\n\n".format(self.main_domain, self.main_domain + self.path_url, self.thread_id,
                                                     self.doc_root, self.string_ansible_action, self.ticket_id, self.main_server, self.string_result_type)
        else:
            return "User: {}\n\nPath: {}\n\n" \
               "Process ID: {}\n\nDoc Root: {}\n\nAnsible Action: {}\n\nReport Ticket: {}\n\n" \
               "Server: {}\n\nResult Type: {}\n\n".format(self.main_domain, self.path_url, self.thread_id,
                                                     self.doc_root, self.string_ansible_action, self.ticket_id, self.main_server, self.string_result_type)

    @property
    def subject_client(self):
        if self.brand == "es":
            return "Informaciones sobre la seguridad de su cuenta: {} :: {}".format(self.pw_user, self.main_server)
        else:
            return "Informações Sobre a Segurança de Sua Conta: {} :: {}".format(self.pw_user, self.main_server)

    def description_intentional(self):
        evidence = self.main_domain + self.path_url
        if self.brand == "es":
            return  "Hola," \
                    "\n\nEvidencia: {}".format(evidence)
        else:
            return "Olá," \
                   "\n\nEvidência: {}".format(evidence)

    def description(self, print_url=False):
        try:
            if self.brand == "es":
                if print_url:
                    return "Hola," \
                           "\n\nUsuario: {}" \
                           "\n\nContraseña: {}".format(self.pw_user, self.pw_password)
                else:
                    return "Hola," \
                           "\n\nUsuario: {}" \
                           "\n\nContraseña: {}".format(self.pw_user, self.pw_password)

        except Exception as er:
            # generate a error log
            self._log.error("description - {} - {}".format(self.__class__.__name__, er))
            raise TemplatesFailed
